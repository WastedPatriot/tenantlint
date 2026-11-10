"""The security checks.

Every check is a plain function that takes a snapshot (a dict of the JSON files
that `collect` saved) and returns one Finding. Checks never call the network,
which is why they can be unit-tested against small hand-written snapshots.
"""
from datetime import datetime, timedelta, timezone

from .models import Finding

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
LEGACY_CLIENTS = {"exchangeActiveSync", "other"}
STALE_DAYS = 90
MAX_GLOBAL_ADMINS = 4
SECRET_WARN_DAYS = 30
SECRET_MAX_LIFETIME_DAYS = 730


def _parse(ts):
    """Graph timestamps look like 2026-01-31T09:00:00Z."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def _now(snap):
    """Measure 'stale' from when the data was collected, so re-checking an old
    snapshot gives the same answer every time."""
    return _parse(snap.get("meta", {}).get("collectedAt")) or datetime.now(timezone.utc)


def _enabled_policies(snap):
    return [p for p in snap.get("conditional_access", []) if p.get("state") == "enabled"]


def _security_defaults_on(snap):
    return bool(snap.get("security_defaults", {}).get("isEnabled"))


def _requires_mfa(policy):
    grant = policy.get("grantControls") or {}
    return "mfa" in (grant.get("builtInControls") or []) or bool(grant.get("authenticationStrength"))


def _targets_everyone(policy):
    cond = policy.get("conditions", {})
    return ("All" in cond.get("users", {}).get("includeUsers", [])
            and "All" in cond.get("applications", {}).get("includeApplications", []))


def _global_admins(snap):
    for role in snap.get("directory_roles", []):
        if role.get("roleTemplateId") == GLOBAL_ADMIN_TEMPLATE:
            return role.get("members", [])
    return []


# ---- Conditional Access ---------------------------------------------------

def ca01_legacy_auth_blocked(snap):
    """Legacy protocols (IMAP, POP, SMTP AUTH, old Office) cannot do MFA, so
    attackers use them for password spraying. They should be blocked outright."""
    blocking = [
        p["displayName"] for p in _enabled_policies(snap)
        if LEGACY_CLIENTS <= set(p.get("conditions", {}).get("clientAppTypes", []))
        and "block" in ((p.get("grantControls") or {}).get("builtInControls") or [])
        and "All" in p.get("conditions", {}).get("users", {}).get("includeUsers", [])
    ]
    ok = bool(blocking) or _security_defaults_on(snap)
    return Finding(
        "CA-01", "Legacy authentication is blocked", "high", "pass" if ok else "fail",
        f"Blocked by: {', '.join(blocking) or 'security defaults'}." if ok
        else "No enabled policy blocks legacy authentication for all users.",
        "Create a Conditional Access policy for all users that blocks the "
        "'Exchange ActiveSync clients' and 'Other clients' client app types.")


def ca02_mfa_all_users(snap):
    """One stolen password should never be enough to sign in."""
    policies = [p["displayName"] for p in _enabled_policies(snap)
                if _targets_everyone(p) and _requires_mfa(p)]
    ok = bool(policies) or _security_defaults_on(snap)
    return Finding(
        "CA-02", "MFA is required for all users", "critical", "pass" if ok else "fail",
        f"Required by: {', '.join(policies) or 'security defaults'}." if ok
        else "No enabled policy requires MFA for all users on all apps, and security defaults are off.",
        "Enable a Conditional Access policy requiring MFA for all users and all "
        "cloud apps, with only break-glass accounts excluded.")


def ca03_mfa_admins(snap):
    """Admin accounts are the highest-value target, so they get their own check."""
    covered = [
        p["displayName"] for p in _enabled_policies(snap) if _requires_mfa(p) and (
            _targets_everyone(p)
            or GLOBAL_ADMIN_TEMPLATE in p.get("conditions", {}).get("users", {}).get("includeRoles", []))
    ]
    ok = bool(covered) or _security_defaults_on(snap)
    return Finding(
        "CA-03", "MFA is required for administrators", "critical", "pass" if ok else "fail",
        f"Required by: {', '.join(covered) or 'security defaults'}." if ok
        else "No enabled policy requires MFA for the Global Administrator role.",
        "Enable a Conditional Access policy requiring MFA (ideally phishing-resistant) for all admin roles.")


def ca04_report_only(snap):
    """Report-only policies log what they would do but enforce nothing."""
    names = [p["displayName"] for p in snap.get("conditional_access", [])
             if p.get("state") == "enabledForReportingButNotEnforced"]
    return Finding(
        "CA-04", "No policies left in report-only mode", "low", "fail" if names else "pass",
        f"{len(names)} policies are in report-only mode and are not enforced." if names
        else "No report-only policies.",
        "Review the sign-in impact of each report-only policy, then switch it on or delete it.", names)


def ca05_broad_exclusions(snap, limit=5):
    """Every exclusion is a hole in the policy; a long list usually means forgotten exceptions."""
    names = []
    for p in _enabled_policies(snap):
        users = p.get("conditions", {}).get("users", {})
        count = len(users.get("excludeUsers", [])) + len(users.get("excludeGroups", []))
        if count > limit:
            names.append(f"{p['displayName']} ({count} exclusions)")
    return Finding(
        "CA-05", "Policies have few exclusions", "medium", "fail" if names else "pass",
        f"{len(names)} enabled policies exclude more than {limit} users or groups." if names
        else f"No enabled policy excludes more than {limit} users or groups.",
        "Replace individual exclusions with one reviewed exclusion group, and remove stale entries.", names)


# ---- MFA registration -------------------------------------------------------

def mfa01_users_registered(snap):
    """A policy that requires MFA does little for users who never set a method up."""
    reg = snap.get("mfa_registration")
    if reg is None:
        return Finding("MFA-01", "All users have registered an MFA method", "high", "skipped",
                       "MFA registration data was not available (needs Entra ID P1 and AuditLog.Read.All).")
    enabled = {u["id"] for u in snap.get("users", [])
               if u.get("accountEnabled") and u.get("userType") == "Member"}
    missing = [r["userPrincipalName"] for r in reg
               if r["id"] in enabled and not r.get("isMfaRegistered")]
    return Finding(
        "MFA-01", "All users have registered an MFA method", "high", "fail" if missing else "pass",
        f"{len(missing)} of {len(enabled)} enabled member accounts have no MFA method registered." if missing
        else "Every enabled member account has an MFA method registered.",
        "Run a registration campaign, and block sign-in for accounts that stay unregistered.", missing)


def mfa02_admins_registered(snap):
    reg = snap.get("mfa_registration")
    if reg is None:
        return Finding("MFA-02", "All administrators have registered an MFA method", "critical", "skipped",
                       "MFA registration data was not available.")
    missing = [r["userPrincipalName"] for r in reg if r.get("isAdmin") and not r.get("isMfaRegistered")]
    return Finding(
        "MFA-02", "All administrators have registered an MFA method", "critical",
        "fail" if missing else "pass",
        f"{len(missing)} administrator accounts have no MFA method registered." if missing
        else "Every administrator has an MFA method registered.",
        "Register a phishing-resistant method (FIDO2 key or passkey) for each admin today.", missing)


# ---- Privileged roles ---------------------------------------------------------

def adm01_global_admin_count(snap):
    """Microsoft's guidance is fewer than five Global Administrators; at least
    two are needed so that one lost account cannot lock the tenant."""
    admins = [m.get("userPrincipalName") or m.get("displayName", "?") for m in _global_admins(snap)]
    n = len(admins)
    ok = 2 <= n <= MAX_GLOBAL_ADMINS
    return Finding(
        "ADM-01", "Between 2 and 4 Global Administrators", "high", "pass" if ok else "fail",
        f"The tenant has {n} Global Administrators.",
        "Move day-to-day admins to narrower roles (User, Exchange, Intune Administrator) "
        "and keep two to four Global Administrators.", [] if ok else admins)


def adm02_guest_admins(snap):
    """A guest is managed by another organisation, so it should not hold the keys to yours."""
    guests = {u["id"] for u in snap.get("users", []) if u.get("userType") == "Guest"}
    names = [m.get("userPrincipalName", "?") for m in _global_admins(snap) if m.get("id") in guests]
    return Finding(
        "ADM-02", "No guest accounts hold Global Administrator", "critical", "fail" if names else "pass",
        f"{len(names)} guest accounts are Global Administrators." if names
        else "No guest account is a Global Administrator.",
        "Remove the role from guest accounts and give the person a member account if they need admin access.",
        names)


# ---- Stale accounts -----------------------------------------------------------

def _stale(snap, user_type):
    """Enabled accounts of one type with no sign-in for STALE_DAYS.
    Returns None when the tenant did not provide sign-in activity at all."""
    users = [u for u in snap.get("users", [])
             if u.get("userType") == user_type and u.get("accountEnabled")]
    if users and not any("signInActivity" in u for u in users):
        return None
    cutoff = _now(snap) - timedelta(days=STALE_DAYS)
    out = []
    for u in users:
        last = _parse((u.get("signInActivity") or {}).get("lastSignInDateTime"))
        created = _parse(u.get("createdDateTime"))
        never_used_and_old = last is None and created is not None and created < cutoff
        if (last is not None and last < cutoff) or never_used_and_old:
            out.append(u["userPrincipalName"])
    return out


def usr01_stale_members(snap):
    names = _stale(snap, "Member")
    if names is None:
        return Finding("USR-01", "No stale member accounts", "medium", "skipped",
                       "Sign-in activity was not available (needs Entra ID P1 and AuditLog.Read.All).")
    return Finding(
        "USR-01", "No stale member accounts", "medium", "fail" if names else "pass",
        f"{len(names)} enabled member accounts have not signed in for {STALE_DAYS} days." if names
        else f"Every enabled member account has signed in within {STALE_DAYS} days.",
        "Disable these accounts, confirm with the manager, then delete after 30 days.", names)


def gst01_stale_guests(snap):
    names = _stale(snap, "Guest")
    if names is None:
        return Finding("GST-01", "No stale guest accounts", "medium", "skipped",
                       "Sign-in activity was not available.")
    return Finding(
        "GST-01", "No stale guest accounts", "medium", "fail" if names else "pass",
        f"{len(names)} guest accounts have not signed in for {STALE_DAYS} days." if names
        else f"Every guest account has signed in within {STALE_DAYS} days.",
        "Remove stale guests, and set up access reviews so guests expire automatically.", names)


# ---- Tenant-wide settings -------------------------------------------------------

def gst02_guest_invites(snap):
    who = snap.get("authorization_policy", {}).get("allowInvitesFrom", "unknown")
    bad = who == "everyone"
    return Finding(
        "GST-02", "Guests cannot invite other guests", "medium", "fail" if bad else "pass",
        f"Guest invitations are allowed from: {who}.",
        "Set 'Guest invite settings' so that only admins or users in the Guest Inviter role can invite.")


def app01_user_consent(snap):
    """Consent phishing: a user is tricked into granting a malicious app access to their mailbox."""
    perms = snap.get("authorization_policy", {}).get("defaultUserRolePermissions", {})
    assigned = perms.get("permissionGrantPoliciesAssigned", [])
    bad = any("microsoft-user-default-legacy" in p for p in assigned)
    return Finding(
        "APP-01", "Users cannot consent to any application", "high", "fail" if bad else "pass",
        "Users can grant any application access to their data without admin approval." if bad
        else "User consent is restricted or disabled.",
        "Allow user consent only for verified publishers and low-impact permissions, "
        "and turn on the admin consent workflow.")


def app02_app_registration(snap):
    perms = snap.get("authorization_policy", {}).get("defaultUserRolePermissions", {})
    bad = bool(perms.get("allowedToCreateApps"))
    return Finding(
        "APP-02", "Users cannot register applications", "low", "fail" if bad else "pass",
        "Any user can register an application in the tenant." if bad
        else "Only administrators can register applications.",
        "Set 'Users can register applications' to No and grant the Application Developer role where needed.")


def app03_secrets(snap):
    """Client secrets are passwords for apps. Expired ones break things; long-lived ones are a standing risk."""
    now, names = _now(snap), []
    for app in snap.get("applications", []):
        for cred in app.get("passwordCredentials", []):
            start, end = _parse(cred.get("startDateTime")), _parse(cred.get("endDateTime"))
            if end is None:
                continue
            if end < now:
                names.append(f"{app['displayName']}: secret expired {end.date()}")
            elif end < now + timedelta(days=SECRET_WARN_DAYS):
                names.append(f"{app['displayName']}: secret expires {end.date()}")
            elif start and (end - start).days > SECRET_MAX_LIFETIME_DAYS:
                names.append(f"{app['displayName']}: secret valid for {(end - start).days} days")
    return Finding(
        "APP-03", "Application secrets are current and short-lived", "medium",
        "fail" if names else "pass",
        f"{len(names)} application secrets are expired, expiring within {SECRET_WARN_DAYS} days, "
        f"or valid for more than {SECRET_MAX_LIFETIME_DAYS} days." if names
        else "All application secrets are current and short-lived.",
        "Rotate these secrets, prefer certificates or managed identities, and cap secret lifetime.", names)


ALL_CHECKS = [
    ca01_legacy_auth_blocked, ca02_mfa_all_users, ca03_mfa_admins, ca04_report_only,
    ca05_broad_exclusions, mfa01_users_registered, mfa02_admins_registered,
    adm01_global_admin_count, adm02_guest_admins, usr01_stale_members, gst01_stale_guests,
    gst02_guest_invites, app01_user_consent, app02_app_registration, app03_secrets,
]


def run_all(snapshot):
    """Run every check and return the findings in a stable order."""
    return [check(snapshot) for check in ALL_CHECKS]
