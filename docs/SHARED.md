# Share an organization safely

Shared mode is optional. Personal mode and existing subscription sessions keep
their own configuration. Shared mode needs one coordinator on the owner's Mac,
which must remain awake and reachable while other members work. No paid server
is required by this implementation; your connectivity provider can have its own
terms or costs.

The coordinator forwards model requests and owns the ledger and project API
keys. Each client still runs the usual isolated Codex environment. Its host relay
holds a member credential; the sandbox receives neither that credential nor an
OpenAI key. The coordinator owner can see prompts and answers while forwarding
them. They are not written to the coordinator log or quota database.

Different projects in the same organization **do not create separate free
pools**. All callers sharing the organization pool must use this one coordinator.
Other keys, Playground, and direct API calls cannot be measured prospectively by
the harness. Organization administrators can bypass the coordinator using other
credentials; this software cannot prevent that.

## Initialize once

Use the account's organization ID and the organization's actual tokens already
consumed today in each approved model group. A zero baseline is appropriate only
when nothing has been used today. Do not silently copy a personal ledger or run
the old independent gateway concurrently against this organization.

```sh
codex-api team init --organization ORG_ID \
  --baseline-a TOKENS_ALREADY_USED --baseline-b TOKENS_ALREADY_USED \
  --all-traffic-coordinated
```

This creates private `team/` state beneath the harness installation. Repeating
initialization cannot reset it. The organization limits retain the reference
5% safety margin: A 237,500 and B 2,375,000 tokens per UTC day. These starter
limits do not prove account-specific complimentary eligibility.

Initialization requires the local API session and its gateway to be stopped.
An installation containing a coordinator cannot continue using an independent
personal model gateway. Prefer a dedicated coordinator installation. The owner
can use a separate client launcher paired with `team join --local`; an existing
configured personal account is preserved rather than silently converted.

For an initial equal split:

```sh
codex-api team member add owner --project OWNER_PROJECT_ID --a 118750 --b 1187500
codex-api team member add friend --project FRIEND_PROJECT_ID --a 118750 --b 1187500
```

The command gives two private file locations. Fill the member's project-specific
restricted OpenAI key into its **key file on the coordinator Mac**. Never put an
OpenAI key into an invite. Send only the invite through an encrypted channel;
it contains a powerful bearer credential and must remain private. Token hashes
are stored in the ledger; invite files and key files use owner-only permissions.

Member requests default to `free_only`. Unconfirmed or expired eligibility
blocks counting and inference. Shared mode does not manufacture free-use
evidence. If an owner explicitly elects ordinary API billing:

```sh
codex-api team member billing friend --allow-api-charges
```

That allows API charges while retaining token limits. It is not a dollar cap or
a promise of free use. `--free-only` restores the conservative billing policy.

## Connect members

Each remote member generates a dedicated tunnel key on their own computer:

```sh
codex-api team keygen
```

Send only its `.pub` public key to the owner. The private key stays on the
member's computer. On the owner Mac, register that public file:

```sh
codex-api team member tunnel-key friend --public-key FRIEND_PUBLIC_KEY_FILE
codex-api team share --listen OWNER_PRIVATE_IP
```

Choose the owner's actual private LAN or private VPN IP. Public addresses and
wildcard listeners are rejected. Members in different locations need a reachable
private network or VPN; the harness does not provision VPN accounts or router
port forwarding. This creates a private OpenSSH host key and validates a
dedicated configuration. It does not start a listener yet.

```sh
codex-api team serve
```

The HTTP listener binds only to `127.0.0.1:49200`. If sharing is configured,
`serve` also starts its own unprivileged SSH listener on port 49202. Its separate
key file permits only registered members and one forwarding destination:
`127.0.0.1:49200`. Shells, login sessions, SFTP, PTYs, SSH agents, UNIX-socket
forwarding, other TCP destinations, and reverse forwarding are disabled. No
new macOS account or system Remote Login setting is needed. System SSH policy,
personal authorized keys, and existing SSH daemons remain unchanged.

Send the refreshed private invite to the member. It includes the dedicated SSH
host public key and both coordinator/member identities. Pairing pins that host
key in its own private known-hosts file, then verifies authenticated `/identity`.
It does not inherit a host SSH agent or accept an unknown host key. Changing
the destination cannot silently join another coordinator. For custom ports,
use matching `--ssh-port`, `--coordinator-port` in `team share`, and `--port` in
`team serve`. Register the member's tunnel public key before pairing.
Each operation uses its own authenticated tunnel and temporary loopback port;
an unrelated listener occupying a saved port is never reused or sent a token.

On the member's prepared client, run `codex-api team join --invite PRIVATE_INVITE_FILE`.
The owner uses a separate client installation with `--local` on the same Mac.
The complete guided pairing flow is in [SETUP.md](../SETUP.md#shared-mode-branch). After pairing,
ordinary `codex-api` usage stays the same. `codex-api usage` shows exactly two
English lines for the current member. The displayed remainder is the smallest
available capacity across the member, project, and organization.

If the coordinator or tunnel is unavailable, requests stop. There is no personal
key fallback, independent local quota, account rotation, or automatic retry.
Stopping the coordinator stops its own SSH child and interrupts active calls; potentially consumed
reservations remain held. Stopping one member's session does not stop the owner
coordinator or another member's session.

## Adjust allocations

```sh
codex-api team allocations
codex-api team transfer --from owner --to friend --a 10000 --b 100000
```

Transfers take effect immediately and expire at the next UTC reset. They can
move only tokens that the donor has neither used nor reserved. Both model
groups change in one transaction or neither changes. Revocation does not refund
usage; the owner can explicitly transfer a revoked member's genuinely unused
capacity. `--revision N` rejects changes based on an outdated administrative
view. Supplying a stable `--operation ID` makes a retried administrative action
idempotent; reuse with different changes is rejected.

To change subsequent daily defaults without rewriting today:

```sh
codex-api team defaults owner --a NEW_A --b NEW_B
codex-api team defaults friend --a NEW_A --b NEW_B
```

When increasing one default and decreasing another, decrease first. Defaults
must always sum to no more than the organization safety limits, including
revoked members until their defaults are explicitly changed. Temporary grants
never create additional capacity.

Optional project limits apply across every member using that project:

```sh
codex-api team project-limit PROJECT_ID --a MAX_A --b MAX_B
```

They persist across UTC days, cannot exceed the organization safety limits,
and cannot be lowered below already used or reserved tokens today. Member
allocations can exceed a tighter project limit; the project limit still wins.

Member quota requests are deduplicated per UTC day and model group. They do
not automatically grant capacity. On the owner Mac:

```sh
codex-api team requests
codex-api team approve REQUEST_ID --from owner
```

Approval and its transfer commit together. Repeating the same approval cannot
grant twice. Old requests expire at the UTC reset. Preapproved automatic tiers
are deliberately absent: this implementation requires the owner's decision.

Administrative commands work while the server runs through an owner-only UNIX
socket inside the private team directory. There are no HTTP administration,
settlement, refund, or arbitrary forwarding endpoints. A very long custom
installation path can exceed the operating system's UNIX-socket limit; use a
shorter private installation directory if the reported path check fails.

## Revoke or rotate

```sh
codex-api team member revoke friend
codex-api team member rotate owner
```

Revocation blocks new authorization and dispatch. A request already sent cannot
be undone. Token rotation invalidates the previous token and writes a new private
invite; that member must pair again. It preserves allocations, history, and
other members' tokens. Revoke an unwanted member before removing old invites.

Revocation also removes that member's registered tunnel keys from the dedicated
listener. An existing SSH connection can outlive public-key revocation, so API
member authentication remains authoritative and is checked again before model
dispatch. Token rotation prevents an old credential's admitted-but-unsent
request from dispatching.

For an uncertain request, inspect `codex-api team reconcile`. Use
`--template REQUEST_ID` to prepare an owner-only review file. Only confirmed
finished usage or specific proof of no consumption can release a hold. Applying
the completed file with `--apply FILE` requires the coordinator to be stopped.
Duplicate receipts do not settle twice; a discrepancy safety stop remains set.

Do not delete, duplicate, or roll back the live ledger to recover capacity.
Its process lease prevents two authoritative processes using the same state;
copying the entire private state to another computer defeats that protection.
Backups are sensitive and cannot be used to create a second active coordinator.

## Accounting boundaries

- One exact-count-and-reserve sequence precedes inference. Organization,
  project, and member admission share one durable transaction. All five models,
  disabled paid hosted tools, supported local tools, and output caps retain the
  normal policy.
- An interrupted, timed-out, rejected, or missing-terminal response is not
  treated as zero use. A known unsent reservation can be voided; uncertain
  dispatched reservations remain conservative across restart and UTC days.
- A UTC change before dispatch prevents that dispatch. A late terminal
  settlement is conservatively counted in the day it becomes known as well.
  Changing the clock or usage exceeding the reservation stops admissions.
- Confirmed usage from requests admitted in the last 615 seconds before
  midnight also constrains the next day, including member and project limits.
  New admissions pause until 00:00:15 UTC. The exact-count response must prove
  a GMT clock reference within six seconds of the coordinator clock before
  inference. Missing or mismatched dates stop inference with a specific error;
  the earlier count may already have occurred. No extra clock API call is made.
- Shared requests require an operation ID. Repeating it cannot create another
  provider attempt; changing its request body conflicts. Responses are not
  cached for replay. An intentional retry uses a new operation after reviewing
  the previous result; it can consume more tokens.
- Warnings are claimed once per member, UTC day, and model group at 90% of
  that member's allocation. A crash immediately after claiming a warning can
  lose its display; quota enforcement does not depend on the warning.
- Provider aggregate Usage/Costs data is useful for reconciliation. It cannot
  prove a future request is affordable or that a missing request consumed zero.
- Free-only qualification remains separate from accounting correctness.

The architecture follows the [OpenAI spending-controller guidance](https://developers.openai.com/cookbook/articles/per_run_spending_controller_responses_api)
on shared atomic reservations and uncertain consumption. The
[Usage API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/completions)
supports project/key/model aggregation. The
[Cycles protocol](https://github.com/runcycles/cycles-protocol/blob/main/cycles-protocol-v0.yaml)
provides a useful reference for atomic scope checks, ownership, server time,
and idempotency; no Cycles server or paid service is a dependency.
OpenSSH documents [MaxSessions, PermitOpen, and PermitListen](https://man.openbsd.org/sshd_config.5)
as the restrictions used by the dedicated forwarding listener. Native acceptance
tests exercise encrypted inference with a fake provider and blocked shell/SFTP,
alternate TCP destinations, reverse TCP forwarding, UNIX-socket forwarding in
both directions, and changed host keys. The UNIX-socket test first proves the
temporary harmless destination is reachable locally, then verifies SSH cannot
reach it or create a reverse UNIX listener. It never probes real Docker or
SSH-agent sockets.
