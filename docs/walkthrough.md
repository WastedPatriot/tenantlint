# Code walkthrough

Read the files in this order. About 15 minutes.

## 1. `models.py` (30 lines)

One dataclass, `Finding`. Every check returns one. `status` is `pass`, `fail` or
`skipped`; `severity` says how bad a failure is. `worst_severity` is what the exit code
is based on.

## 2. `checks.py`

The core. Things to notice:

- **Every check has the same signature**: snapshot in, one `Finding` out. That makes
  adding a check a ten-line job and makes each one testable alone.
- **Helpers at the top** (`_enabled_policies`, `_requires_mfa`, `_targets_everyone`)
  express Conditional Access concepts once, so each check reads close to plain English.
- **`_now(snap)`** uses the snapshot's collection time, not today's date. Re-checking a
  snapshot from last month gives last month's answer.
- **`skipped` is a real state.** If the tenant has no P1 licence, sign-in data is missing.
  The check says so instead of reporting "no stale accounts", which would be false.
- **`ALL_CHECKS`** is a plain list. `run_all` loops over it.

## 3. `graph.py`

- `GraphClient.get` retries on HTTP 429 using the `Retry-After` header.
- `GraphClient.get_all` follows `@odata.nextLink` to read every page.
- `collect` asks for sign-in activity first and falls back without it on a 403, recording
  the limitation in `meta.json` so the report can show what was not assessed.
- `device_code_token` uses MSAL's device code flow, so no client secret is needed.
- The session is injectable (`session=None`), which is how the tests replace the network
  with `FakeSession`.

## 4. `report.py`

Three renderers over the same findings. The HTML is a single file with inline CSS and no
JavaScript; every value from the tenant goes through `html.escape`, so a display name
containing markup cannot inject anything into the report.

## 5. `cli.py`

`argparse` with three subcommands. The exit-code logic at the bottom of `_check` is what
makes it usable in a scheduled job.

## 6. `tests/test_checks.py`

Each test builds the smallest snapshot that proves one rule. Good ones to read first:
`test_report_only_mfa_policy_does_not_count` and
`test_stale_accounts_use_collection_time_not_today`.

## Questions an interviewer might ask

- Why separate collection from checking? (Testability, offline re-checks, snapshot diffs.)
- Why does a report-only policy fail CA-02? (It logs but does not enforce.)
- What happens on a tenant without P1? (Affected checks are skipped and listed.)
- How would you add a check for risky OAuth grants? (New endpoint in `ENDPOINTS`, one
  function in `checks.py`, add to `ALL_CHECKS`, one test.)
- What are the false-positive risks? (See "Limits" in the README.)
