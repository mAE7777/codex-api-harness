# Share an organization

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

## Choose the policy and allocations

Before initialization, follow [CONFIGURATION.md](CONFIGURATION.md) to select the organization's actual models, daily pools, margins and one service tier. Apply the reviewed private policy on a stopped coordinator installation. Do not ask a joining member to supply an OpenAI key or invent an independent budget. The coordinator policy is pinned after initialization in this release; allocation changes remain supported.

For a single pool named Daily, use:

```sh
codex-api team init --organization ORG_ID --baseline Daily=TOKENS_ALREADY_USED --all-traffic-coordinated
codex-api team member add owner --project OWNER_PROJECT_ID --tokens Daily=OWNER_ALLOCATION
codex-api team member add friend --project FRIEND_PROJECT_ID --tokens Daily=FRIEND_ALLOCATION
```

Repeat `--baseline POOL=N` and `--tokens POOL=N` for every configured pool. The same named-pool arguments apply to `transfer`, `defaults` and `project-limit`. Models, tier, output cap and organization ceiling are authoritative at the coordinator. Invitations include the policy and digest; the client verifies both before forwarding.

A member reviews the invitation before joining. The connection steps below include the required digest. Local owner clients and credential renewal require the same review. The invitation contains a private bearer token. Never print or commit it. Older invitations remain compatible only with the legacy profile.

## Initialize the coordinator once

Use a dedicated coordinator installation. Its local API session and gateway must be stopped. After initialization, it cannot also run an independent personal gateway. The owner uses a separate client installation with its own launcher, private home, and port.

The commands above require the reviewed policy from CONFIGURATION.md. Replace each placeholder with the actual organization, project, prior usage, and allocation. Include all earlier personal usage in the organization baseline. Zero is appropriate only when no tokens were used today.

Initialization creates private `team/` state. Repeating it cannot reset the ledger. Divide each pool's usable capacity between members. The sum of member defaults cannot exceed the organization's ceiling after the safety margin. Prior organization usage still reduces the capacity available today.

For the optional `legacy-five` policy, usable reference ceilings are A 237,500 and B 2,375,000 tokens. An equal split is A 118,750 and B 1,187,500 per member. These numbers are examples, not proof of a free allowance. Legacy `--baseline-a`, `--baseline-b`, `--a`, and `--b` flags remain supported for that policy. Do not mix them with named-pool flags.

Each `member add` command gives two private file locations. Fill the member's project-specific
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

On the member's installed client, review and join:

```sh
codex-api team join --invite PRIVATE_INVITE_FILE --inspect
codex-api team join --invite PRIVATE_INVITE_FILE --reviewed-policy-digest SHA256
```

Use the digest from the inspection. Add `--local` to the owner's separate client command on the same Mac. Then prepare the client sandbox as described in [SETUP.md](../SETUP.md#shared-mode-branch).

Daily startup remains `codex-api`. Usage shows one English line per approved pool, or two lines for the legacy A/B policy. The remaining amount is the smallest available capacity across the member, project, and organization.

If the coordinator or tunnel is unavailable, requests stop. There is no personal
key fallback, independent local quota, account rotation, or automatic retry.
Stopping the coordinator stops its own SSH child and interrupts active calls; potentially consumed
reservations remain held. Stopping one member's session does not stop the owner
coordinator or another member's session.

## Adjust allocations

```sh
codex-api team allocations
codex-api team transfer --from owner --to friend --tokens Daily=TRANSFER_AMOUNT
```

Transfers take effect immediately and expire at the next UTC reset. They can
move only tokens that the donor has neither used nor reserved. All configured pools change in one transaction or none changes. Repeat `--tokens POOL=N` for every pool, including zero transfers. Revocation does not refund
usage; the owner can explicitly transfer a revoked member's genuinely unused
capacity. `--revision N` rejects changes based on an outdated administrative
view. Supplying a stable `--operation ID` makes a retried administrative action
idempotent; reuse with different changes is rejected.

To change subsequent daily defaults without rewriting today:

```sh
codex-api team defaults owner --tokens Daily=NEW_OWNER_ALLOCATION
codex-api team defaults friend --tokens Daily=NEW_FRIEND_ALLOCATION
```

When increasing one default and decreasing another, decrease first. Defaults
must always sum to no more than the organization safety limits, including
revoked members until their defaults are explicitly changed. Temporary grants
never create additional capacity.

Optional project limits apply across every member using that project:

```sh
codex-api team project-limit PROJECT_ID --tokens Daily=PROJECT_CAP
```

They persist across UTC days, cannot exceed the organization safety limits,
and cannot be lowered below already used or reserved tokens today. Member
allocations can exceed a tighter project limit; the project limit still wins.

A member can request more tokens with `codex-api team request --group Daily --tokens AMOUNT`. Use the actual pool identifier. Requests are deduplicated per UTC day and pool. They do not grant capacity automatically. On the owner Mac:

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
  project, and member admission share one durable transaction. All owner-approved models,
  disabled paid hosted tools, supported local tools, and output caps retain the
  normal policy.
- An interrupted, timed-out, rejected, or missing-terminal response is not
  treated as zero use. A known unsent reservation can be voided; uncertain
  dispatched reservations remain conservative across restart and UTC days.
- A UTC change before dispatch prevents that dispatch. A late terminal
  settlement is conservatively counted in the day it becomes known as well.
  Changing the clock or usage exceeding the reservation stops admissions.
- Confirmed usage from requests admitted in the last configured request-deadline-plus-15 seconds before
  midnight also constrains the next day, including member and project limits.
  New admissions pause until 00:00:15 UTC. The exact-count response must prove
  a GMT clock reference within six seconds of the coordinator clock before
  inference. Missing or mismatched dates stop inference with a specific error;
  the earlier count may already have occurred. No extra clock API call is made.
- Shared requests require an operation ID. Repeating it cannot create another
  provider attempt; changing its request body conflicts. Responses are not
  cached for replay. An intentional retry uses a new operation after reviewing
  the previous result; it can consume more tokens.
- Warnings use the policy threshold, recommended at 90% of the member's allocation. Each warning is claimed at most once per member, UTC day, and pool. A crash immediately after claiming a warning can
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
