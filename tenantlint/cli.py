"""Command line entry point.

  tenantlint demo                          run against the bundled fictional tenant
  tenantlint collect --tenant T --client-id C --out snap/
  tenantlint check snap/ --html report.html --fail-on high
"""
import argparse
import sys
from pathlib import Path

from . import __version__, checks, graph, report
from .models import SEVERITIES, worst_severity

SAMPLE = Path(__file__).parent / "sample_data"


def _check(folder, args):
    snap = graph.load_snapshot(folder)
    meta = snap.get("meta", {})
    findings = checks.run_all(snap)
    print(report.to_text(findings, meta.get("tenant", "")))
    if args.html:
        Path(args.html).write_text(report.to_html(findings, meta), encoding="utf-8")
        print(f"\nHTML report written to {args.html}")
    if args.json:
        Path(args.json).write_text(report.to_json(findings, meta), encoding="utf-8")
    # Exit non-zero when something at or above --fail-on failed, so CI can gate on it.
    worst = worst_severity(findings)
    if worst and args.fail_on != "never" and SEVERITIES.index(worst) <= SEVERITIES.index(args.fail_on):
        return 1
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="tenantlint", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_output(sp):
        sp.add_argument("--html", help="write an HTML report to this file")
        sp.add_argument("--json", help="write findings as JSON to this file")
        sp.add_argument("--fail-on", default="never", choices=SEVERITIES + ["never"],
                        help="exit 1 if any finding at this severity or worse failed")

    add_output(sub.add_parser("demo", help="run against the bundled fictional tenant"))
    c = sub.add_parser("check", help="run the checks on a saved snapshot")
    c.add_argument("snapshot")
    add_output(c)
    g = sub.add_parser("collect", help="save a read-only snapshot of a tenant")
    g.add_argument("--tenant", required=True, help="tenant ID or domain")
    g.add_argument("--client-id", required=True, help="app registration (public client) ID")
    g.add_argument("--out", default="snapshot")

    args = p.parse_args(argv)
    try:
        if args.cmd == "demo":
            return _check(SAMPLE, args)
        if args.cmd == "check":
            return _check(args.snapshot, args)
        token = graph.device_code_token(args.tenant, args.client_id)
        graph.collect(graph.GraphClient(token), args.out, args.tenant)
        print(f"Snapshot saved to {args.out}. Now run: tenantlint check {args.out}")
        return 0
    except (FileNotFoundError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
