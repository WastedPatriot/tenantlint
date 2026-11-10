"""Generate the fictional tenant used by `tenantlint demo` and the tests.

Every name, domain and ID here is invented. Run: python tools/make_sample_data.py
"""
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent.parent / "tenantlint" / "sample_data"
NOW = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
DOMAIN = "larkfield.example"
GA = "62e90394-69f5-4237-9190-012177145e10"
rng = random.Random(7)  # fixed seed so the files never change between runs


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def uid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))


FIRST = ["Amara", "Ben", "Chloe", "Dev", "Elin", "Farid", "Grace", "Hugo", "Imani", "Jonas", "Kira",
         "Leo", "Mina", "Noor", "Owen", "Priya", "Quinn", "Rosa", "Sami", "Tess", "Uma", "Viktor",
         "Wren", "Xavi", "Yara", "Zane", "Ada", "Bram"]
LAST = ["Okafor", "Hale", "Marsh", "Patel", "Berg", "Nazari", "Lindqvist", "Reyes", "Mwangi", "Falk"]

users, reg = [], []
for i, first in enumerate(FIRST):
    upn = f"{first.lower()}.{LAST[i % len(LAST)].lower()}@{DOMAIN}"
    stale = i in (3, 11, 19, 24)
    last = NOW - timedelta(days=rng.randint(120, 400) if stale else rng.randint(0, 20))
    users.append({"id": uid(upn), "displayName": f"{first} {LAST[i % len(LAST)]}",
                  "userPrincipalName": upn, "userType": "Member", "accountEnabled": i != 27,
                  "createdDateTime": ts(NOW - timedelta(days=rng.randint(200, 1500))),
                  "signInActivity": {"lastSignInDateTime": ts(last)}})
    reg.append({"id": uid(upn), "userPrincipalName": upn, "isAdmin": i < 5,
                "isMfaRegistered": i not in (2, 8, 13, 17, 22),
                "methodsRegistered": [] if i in (2, 8, 13, 17, 22) else ["microsoftAuthenticatorPush"]})

for i, org in enumerate(["structa", "greenline", "atelier-nord", "pivot-qs", "mapworks", "lumen-me"]):
    upn = f"contact_{org}.example#EXT#@{DOMAIN}"
    last = NOW - timedelta(days=rng.randint(150, 500) if i in (1, 3, 4) else rng.randint(1, 30))
    users.append({"id": uid(upn), "displayName": f"Contact ({org})", "userPrincipalName": upn,
                  "userType": "Guest", "accountEnabled": True,
                  "createdDateTime": ts(NOW - timedelta(days=600)),
                  "signInActivity": {"lastSignInDateTime": ts(last)}})


def member(u):
    return {"id": u["id"], "displayName": u["displayName"], "userPrincipalName": u["userPrincipalName"]}


roles = [
    {"id": uid("role-ga"), "displayName": "Global Administrator", "roleTemplateId": GA,
     "members": [member(u) for u in users[:5]] + [member(users[28])]},
    {"id": uid("role-ua"), "displayName": "User Administrator",
     "roleTemplateId": "fe930be7-5e62-47db-91af-98c3a49a38b1", "members": [member(users[6])]},
]


def policy(name, state, include_users=("All",), roles_=(), clients=("all",), controls=("mfa",),
           exclude=()):
    return {"id": uid(name), "displayName": name, "state": state,
            "conditions": {"users": {"includeUsers": list(include_users), "excludeUsers": list(exclude),
                                     "includeGroups": [], "excludeGroups": [],
                                     "includeRoles": list(roles_), "excludeRoles": []},
                           "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": list(clients)},
            "grantControls": {"operator": "OR", "builtInControls": list(controls),
                              "authenticationStrength": None}}


ca = [
    policy("Require MFA for all users", "enabledForReportingButNotEnforced"),
    policy("Require MFA for admins", "enabled", include_users=(), roles_=(GA,)),
    policy("Require compliant device", "enabled", controls=("compliantDevice",),
           exclude=[u["id"] for u in users[5:13]]),
    policy("Block high-risk countries (old)", "disabled", controls=("block",)),
]

apps = [
    {"displayName": "Scan-to-Email Relay", "appId": uid("app1"), "passwordCredentials": [
        {"displayName": "relay", "startDateTime": ts(NOW - timedelta(days=800)),
         "endDateTime": ts(NOW - timedelta(days=70))}]},
    {"displayName": "Timesheet Sync", "appId": uid("app2"), "passwordCredentials": [
        {"displayName": "sync", "startDateTime": ts(NOW - timedelta(days=350)),
         "endDateTime": ts(NOW + timedelta(days=12))}]},
    {"displayName": "Render Farm Connector", "appId": uid("app3"), "passwordCredentials": [
        {"displayName": "farm", "startDateTime": ts(NOW - timedelta(days=100)),
         "endDateTime": ts(NOW + timedelta(days=1725))}]},
    {"displayName": "Backup Reporter", "appId": uid("app4"), "passwordCredentials": [
        {"displayName": "report", "startDateTime": ts(NOW - timedelta(days=30)),
         "endDateTime": ts(NOW + timedelta(days=150))}]},
]

files = {
    "users": users, "mfa_registration": reg, "directory_roles": roles,
    "conditional_access": ca, "applications": apps,
    "security_defaults": {"isEnabled": False},
    "authorization_policy": {"allowInvitesFrom": "everyone", "defaultUserRolePermissions": {
        "allowedToCreateApps": True,
        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}},
    "meta": {"tenant": "Larkfield Studio (fictional demo tenant)", "collectedAt": ts(NOW), "limitations": []},
}
OUT.mkdir(parents=True, exist_ok=True)
for name, data in files.items():
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")
print(f"wrote {len(files)} files to {OUT}")
