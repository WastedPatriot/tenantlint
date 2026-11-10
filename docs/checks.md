# Why each check exists

Each entry says what an attacker gains when the check fails.

## Conditional Access

**CA-01 Legacy authentication is blocked.** IMAP, POP, SMTP AUTH and older Office clients
send only a username and password, so MFA cannot apply. Password-spray attacks target
these protocols for exactly that reason. The check passes when an enabled policy blocks
both legacy client types for all users, or security defaults are on.

**CA-02 MFA is required for all users.** Without it, one phished or reused password is a
full sign-in. A policy in report-only mode does not count, because it enforces nothing.

**CA-03 MFA is required for administrators.** Checked separately because some tenants
protect admins first. Passes with a policy targeting the Global Administrator role or
with the all-users policy.

**CA-04 No policies left in report-only mode.** Report-only is for testing. Left in place,
it gives the impression of protection that is not there.

**CA-05 Policies have few exclusions.** Exclusions accumulate ("just until the migration is
done") and each excluded account bypasses the control. More than five on one policy is
flagged for review.

## MFA registration

**MFA-01 / MFA-02.** A policy can require MFA, but an account that has never registered a
method is either blocked or, worse, can be registered by whoever signs in first with the
password. Admins are reported separately as critical.

## Privileged roles

**ADM-01 Between 2 and 4 Global Administrators.** Each Global Administrator is an account
whose compromise is a compromise of the whole tenant. Microsoft's guidance is fewer than
five. Fewer than two risks a lock-out.

**ADM-02 No guest accounts hold Global Administrator.** A guest's password, MFA and device
are controlled by another organisation.

## Stale accounts

**USR-01 / GST-01.** Accounts nobody uses are accounts nobody notices being misused. An
account counts as stale when it is enabled and has not signed in for 90 days, or has never
signed in and is more than 90 days old. Age is measured from when the snapshot was taken.

## Tenant-wide settings

**GST-02 Guests cannot invite other guests.** Otherwise external access spreads without
anyone internal approving it.

**APP-01 Users cannot consent to any application.** Consent phishing tricks a user into
granting a malicious app access to mail and files. It needs no password and survives a
password reset.

**APP-02 Users cannot register applications.** Low severity; it limits where persistence
can be hidden.

**APP-03 Application secrets are current and short-lived.** A client secret is a password
for an app. Expired secrets cause outages, and secrets valid for years are rarely rotated
after staff leave.
