"""Read-only collection from Microsoft Graph.

Only GET requests are made. Results are saved as JSON files so the checks can
run later, offline, and so a snapshot can be diffed against last month's.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = ["Policy.Read.All", "Directory.Read.All", "AuditLog.Read.All", "Application.Read.All"]

# file name -> Graph path. `optional` ones need a paid licence or extra consent,
# so a 403 there is recorded as a limitation instead of stopping the run.
ENDPOINTS = {
    "conditional_access": ("/identity/conditionalAccess/policies", False),
    "applications": ("/applications?$select=displayName,appId,passwordCredentials", False),
    "mfa_registration": ("/reports/authenticationMethods/userRegistrationDetails", True),
}
USER_FIELDS = "id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime"


class GraphClient:
    def __init__(self, token, session=None):
        if session is None:
            import requests
            session = requests.Session()
        self.session = session
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def get(self, path):
        """GET one URL, waiting and retrying when Graph throttles us (HTTP 429)."""
        url = path if path.startswith("http") else GRAPH + path
        for _ in range(5):
            r = self.session.get(url, timeout=60)
            if r.status_code == 429:
                time.sleep(int(r.headers.get("Retry-After", "5")))
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError(f"Graph kept throttling {url}")

    def get_all(self, path):
        """Follow @odata.nextLink until every page has been read."""
        items, url = [], path
        while url:
            page = self.get(url)
            items.extend(page.get("value", []))
            url = page.get("@odata.nextLink")
        return items


def _is_forbidden(err):
    return getattr(getattr(err, "response", None), "status_code", None) in (400, 403)


def collect(client, out_dir, tenant=""):
    """Pull everything the checks need and write it to `out_dir`."""
    out, limits = Path(out_dir), []
    out.mkdir(parents=True, exist_ok=True)
    snap = {}

    for name, (path, optional) in ENDPOINTS.items():
        try:
            snap[name] = client.get_all(path)
        except Exception as err:
            if not (optional and _is_forbidden(err)):
                raise
            limits.append(f"{name}: not available on this tenant or licence")

    # Sign-in activity needs Entra ID P1. Ask for it, and fall back without it.
    try:
        snap["users"] = client.get_all(f"/users?$select={USER_FIELDS},signInActivity&$top=500")
    except Exception as err:
        if not _is_forbidden(err):
            raise
        snap["users"] = client.get_all(f"/users?$select={USER_FIELDS}&$top=500")
        limits.append("users: sign-in activity not available, stale-account checks skipped")

    roles = client.get_all("/directoryRoles")
    for role in roles:
        role["members"] = client.get_all(
            f"/directoryRoles/{role['id']}/members?$select=id,displayName,userPrincipalName")
    snap["directory_roles"] = roles

    snap["security_defaults"] = client.get("/policies/identitySecurityDefaultsEnforcementPolicy")
    snap["authorization_policy"] = client.get("/policies/authorizationPolicy")
    snap["meta"] = {"tenant": tenant, "limitations": limits,
                    "collectedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

    for name, data in snap.items():
        (out / f"{name}.json").write_text(json.dumps(data, indent=2))
    return snap


def load_snapshot(folder):
    """Read a snapshot folder back into the dict shape the checks expect."""
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"{folder} is not a snapshot folder")
    return {p.stem: json.loads(p.read_text()) for p in sorted(folder.glob("*.json"))}


def device_code_token(tenant, client_id):
    """Sign in interactively: prints a code to enter at microsoft.com/devicelogin.
    No secret is stored, and the token only carries the read-only SCOPES above."""
    import msal
    app = msal.PublicClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant}")
    flow = app.initiate_device_flow(scopes=[f"https://graph.microsoft.com/{s}" for s in SCOPES])
    if "user_code" not in flow:
        raise RuntimeError(f"Could not start sign-in: {flow.get('error_description', flow)}")
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Sign-in failed: {result.get('error_description', result)}")
    return result["access_token"]
