"""Data shapes shared by the checks and the reports."""
from dataclasses import asdict, dataclass, field

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    """The result of one check against one tenant snapshot."""

    check_id: str            # stable ID such as "CA-01", used in docs and CI filters
    title: str
    severity: str            # one of SEVERITIES; how bad it is when the check fails
    status: str              # "fail", "pass" or "skipped"
    detail: str              # one sentence saying what was found
    fix: str = ""            # what an admin should change
    affected: list = field(default_factory=list)  # user names, policy names, app names

    def to_dict(self):
        return asdict(self)


def worst_severity(findings):
    """Most severe level among failed findings, or None when nothing failed."""
    failed = [f.severity for f in findings if f.status == "fail"]
    return min(failed, key=SEVERITIES.index) if failed else None
