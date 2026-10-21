# Security

Do not attach credentials, installed state, conversation logs, `.env` files, usage databases, account exports, diagnostic archives, or private project contents to an issue.

For a suspected vulnerability, use this repository's **Security → Report a vulnerability** private reporting feature if available. Otherwise open a minimal issue asking for a private channel, without exploit payloads or sensitive data. Include the harness/CLI/runtime versions and a reproduction using public canaries or fake keys.

If a real key leaked, revoke it through its provider. Removing it from Git or chat is not revocation. The repository contains no bundled provider credentials or prior user's state. Keys must be created by each owner and stored outside the workspace.

Read [the threat model and limitations](docs/BOUNDARIES.md). In particular, the live project mount, per-process Linux deny-glob snapshot, allowed package hosts, in-VM privileges, and organization-wide quota assumptions are material boundaries. This release does not claim guaranteed zero billing, continuous data-loss prevention, or safety against a compromised host.

Only the current tagged release is maintained. Do not weaken a failing integrity, quota, credential or isolation check to restore service. Report a minimal reproduction instead.
