"""Each test builds the smallest snapshot that proves one behaviour."""
from tenantlint import checks, graph, report
from tenantlint.cli import SAMPLE, main

GA = checks.GLOBAL_ADMIN_TEMPLATE
NOW = "2026-11-01T09:00:00Z"


def policy(state="enabled", users=("All",), roles=(), clients=("all",), controls=("mfa",), exclude=()):
    return {"displayName": "p", "state": state,
            "conditions": {"users": {"includeUsers": list(users), "includeRoles": list(roles),
                                     "excludeUsers": list(exclude), "excludeGroups": []},
                           "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": list(clients)},
            "grantControls": {"builtInControls": list(controls)}}


def user(upn, last=None, kind="Member", enabled=True, created="2020-01-01T00:00:00Z"):
    return {"id": upn, "userPrincipalName": upn, "userType": kind, "accountEnabled": enabled,
            "createdDateTime": created, "signInActivity": {"lastSignInDateTime": last}}


def test_mfa_for_all_users_passes_with_enforced_policy():
    assert checks.ca02_mfa_all_users({"conditional_access": [policy()]}).status == "pass"


def test_report_only_mfa_policy_does_not_count():
    snap = {"conditional_access": [policy(state="enabledForReportingButNotEnforced")]}
    assert checks.ca02_mfa_all_users(snap).status == "fail"
    assert checks.ca04_report_only(snap).status == "fail"


def test_security_defaults_satisfy_mfa_and_legacy_checks():
    snap = {"security_defaults": {"isEnabled": True}}
    assert checks.ca01_legacy_auth_blocked(snap).status == "pass"
    assert checks.ca02_mfa_all_users(snap).status == "pass"
    assert checks.ca03_mfa_admins(snap).status == "pass"


def test_legacy_auth_needs_a_block_on_both_legacy_client_types():
    only_one = {"conditional_access": [policy(clients=("other",), controls=("block",))]}
    both = {"conditional_access": [policy(clients=("exchangeActiveSync", "other"), controls=("block",))]}
    assert checks.ca01_legacy_auth_blocked(only_one).status == "fail"
    assert checks.ca01_legacy_auth_blocked(both).status == "pass"


def test_admin_mfa_passes_with_role_targeted_policy():
    snap = {"conditional_access": [policy(users=(), roles=(GA,))]}
    assert checks.ca03_mfa_admins(snap).status == "pass"
    assert checks.ca02_mfa_all_users(snap).status == "fail"


def test_broad_exclusions_flagged_over_limit():
    snap = {"conditional_access": [policy(exclude=[str(i) for i in range(6)])]}
    assert checks.ca05_broad_exclusions(snap).status == "fail"
    assert checks.ca05_broad_exclusions({"conditional_access": [policy(exclude=["a"])]}).status == "pass"


def test_unregistered_users_ignore_disabled_accounts():
    snap = {"users": [user("a@x"), user("b@x", enabled=False)],
            "mfa_registration": [{"id": "a@x", "userPrincipalName": "a@x", "isMfaRegistered": False},
                                 {"id": "b@x", "userPrincipalName": "b@x", "isMfaRegistered": False}]}
    assert checks.mfa01_users_registered(snap).affected == ["a@x"]


def test_mfa_checks_skip_when_report_unavailable():
    assert checks.mfa01_users_registered({"users": []}).status == "skipped"
    assert checks.mfa02_admins_registered({}).status == "skipped"


def test_global_admin_count_bounds():
    def snap(n):
        return {"directory_roles": [{"roleTemplateId": GA,
                                     "members": [{"id": str(i), "userPrincipalName": f"a{i}@x"} for i in range(n)]}]}
    assert [checks.adm01_global_admin_count(snap(n)).status for n in (1, 2, 4, 5)] == \
        ["fail", "pass", "pass", "fail"]


def test_guest_global_admin_is_flagged():
    snap = {"users": [user("g@x", kind="Guest")],
            "directory_roles": [{"roleTemplateId": GA, "members": [{"id": "g@x", "userPrincipalName": "g@x"}]}]}
    assert checks.adm02_guest_admins(snap).affected == ["g@x"]


def test_stale_accounts_use_collection_time_not_today():
    snap = {"meta": {"collectedAt": NOW},
            "users": [user("old@x", last="2026-06-01T00:00:00Z"),
                      user("recent@x", last="2026-10-20T00:00:00Z"),
                      user("never@x", last=None),
                      user("new-never@x", last=None, created="2026-10-25T00:00:00Z")]}
    assert checks.usr01_stale_members(snap).affected == ["old@x", "never@x"]


def test_stale_checks_skip_without_sign_in_activity():
    snap = {"users": [{"id": "a", "userPrincipalName": "a@x", "userType": "Member", "accountEnabled": True}]}
    assert checks.usr01_stale_members(snap).status == "skipped"


def test_secret_states():
    def app(name, start, end):
        return {"displayName": name, "passwordCredentials": [{"startDateTime": start, "endDateTime": end}]}
    snap = {"meta": {"collectedAt": NOW}, "applications": [
        app("expired", "2025-01-01T00:00:00Z", "2026-10-01T00:00:00Z"),
        app("soon", "2026-01-01T00:00:00Z", "2026-11-10T00:00:00Z"),
        app("long", "2026-10-01T00:00:00Z", "2031-10-01T00:00:00Z"),
        app("fine", "2026-10-01T00:00:00Z", "2027-04-01T00:00:00Z")]}
    names = " ".join(checks.app03_secrets(snap).affected)
    assert "expired" in names and "soon" in names and "long" in names and "fine" not in names


def test_tenant_settings():
    risky = {"authorization_policy": {"allowInvitesFrom": "everyone", "defaultUserRolePermissions": {
        "allowedToCreateApps": True,
        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}}
    safe = {"authorization_policy": {"allowInvitesFrom": "adminsAndGuestInviters",
                                     "defaultUserRolePermissions": {"allowedToCreateApps": False,
                                                                    "permissionGrantPoliciesAssigned": []}}}
    for check in (checks.gst02_guest_invites, checks.app01_user_consent, checks.app02_app_registration):
        assert check(risky).status == "fail" and check(safe).status == "pass"


def test_demo_tenant_end_to_end(tmp_path, capsys):
    findings = checks.run_all(graph.load_snapshot(SAMPLE))
    failed = {f.check_id for f in findings if f.status == "fail"}
    assert {"CA-01", "CA-02", "MFA-02", "ADM-01", "ADM-02", "APP-03"} <= failed
    assert "CA-03" not in failed
    out = tmp_path / "r.html"
    assert main(["demo", "--html", str(out), "--fail-on", "high"]) == 1
    assert main(["demo"]) == 0
    assert "<script" not in out.read_text() and "CA-01" in out.read_text()
    assert report.summary(findings)["worst"] == "critical"


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeSession:
    """Stands in for requests.Session so paging and throttling can be tested offline."""

    def __init__(self, responses):
        self.headers, self.responses, self.calls = {}, list(responses), []

    def get(self, url, timeout=None):
        self.calls.append(url)
        return self.responses.pop(0)


def test_graph_client_follows_pages_and_retries_throttling(monkeypatch):
    monkeypatch.setattr(graph.time, "sleep", lambda s: None)
    session = FakeSession([
        FakeResponse(429, headers={"Retry-After": "1"}),
        FakeResponse(200, {"value": [1, 2], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2"}),
        FakeResponse(200, {"value": [3]})])
    client = graph.GraphClient("token", session)
    assert client.get_all("/users") == [1, 2, 3]
    assert session.headers["Authorization"] == "Bearer token"
    assert session.calls[-1].endswith("page=2")
