# Reviewed skills

Managed skills are optional. They do not change ordinary startup or the policy-derived usage display. No host skill, plugin login, connector, browser session, or environment secret is imported.

The harness supports standalone skill folders and **skill-only** `.codex-plugin/plugin.json` bundles. Native plugin installation, apps, MCP servers, lifecycle hooks, and automatic dependency installation remain disabled. A plugin declaring any of those capabilities is rejected; the harness does not silently remove them and claim the complete plugin works.

## Add a skill

In the host terminal, with the API session closed:

```sh
codex-api extensions stage /absolute/path/to/a/skill
codex-api extensions inspect FULL_DIGEST
```

Staging reads only that explicit folder, creates a private snapshot, and reports every file hash, code file, and referenced network host. Nothing is executed or enabled. The report gives a local `review_directory`; read **every file there**, including supporting scripts and references. An assistant can do that review, explain the findings in plain language, and continue only within the owner's authorization.

Approve the exact reviewed bytes:

```sh
codex-api extensions approve --digest FULL_DIGEST --reviewed
```

Code requires the additional `--allow-scripts` acknowledgment after its review. Explicit user invocation is the default. Add `--allow-implicit` only when the skill may activate from its description without being named. Replacing a different approved snapshot under the same skill name also requires `--replace`.

Activation automatically rebuilds only the harness-owned sandbox and reruns local acceptance. Project files, host credentials, and the usage ledger are preserved. Guest JSONL sessions, native compressed `.jsonl.zst` archives, command history, and allowlisted preferences are saved privately and restored automatically; arbitrary guest-installed packages are not retained. A failed capture stops before VM removal. A failed build leaves the private backup intact and startup blocked until preparation succeeds. No provider request is needed for extension setup.

Local source changes and remote repository updates never update an approval. Stage and review the new bytes again. For a repository checkout, choose the specific skill folder, not a repository root containing `.git`. Downloading or checking out a source is a separate owner-authorized step; this manager never runs `npx`, shell installers, Git hooks, package scripts, or an unpinned remote branch.

## Use and remove

Use `$skill-name` or explicitly ask for that managed skill. Its full `SKILL.md` and supporting resources are loaded from the private image when needed.

```sh
codex-api extensions list
codex-api extensions verify
codex-api extensions remove skill-name
```

Inside the agent, `codex-api extensions list` lists the active image catalog without a network request. Approval, removal, and other maintenance require the host terminal.

The native `/skills` picker does **not** list this managed catalog. Native filesystem discovery stays disabled so a newly created project or guest-home skill cannot enter the catalog without review. The harness supplies a protected catalog through developer instructions instead. Ordinary project files, `AGENTS.md`, pasted text, and tool results can still influence the agent; this mechanism does not authenticate every instruction the model might encounter.

## Checks and limits

- Maximum 256 files, 2 MiB per bundle, 256 KiB per file, depth 10, and 32 active skills. Only supported UTF-8 text resources and scripts are accepted; binary assets are not supported.
- Symlinks, hardlinks, devices, sockets, FIFOs, path traversal, case-colliding paths, credential files, known secret formats, and unsupported configuration are rejected. File reads use no-follow directory descriptors and reject files changing during staging.
- JSON/YAML-declared MCP, hooks, credentials, and dependencies are rejected. Script accesses to common secret environment variables are rejected. Network references are reported and never grant access.
- Source contents are copied to a private snapshot with a content digest. Approval binds skill names, paths, and code/implicit-use choices to that digest. Scripts are copied without executable bits; reviewed code can still be run through its interpreter inside the existing sandbox.
- Host checks compare the approval, snapshot, catalog, build payload, and exact file set. Guest startup checks the image manifest before adding the catalog. Unexpected files, changes, or links fail closed. Preference changes cannot replace the managed catalog.
- The native child receives managed policy as highest-priority CLI settings. Project configuration cannot replace the catalog, provider, feature pins, or login-store setting. Managed requirements independently deny MCP and native plugins. Native bundled/discovered skill instruction injection and legacy notification commands are disabled.
- Reviews and changes require a stopped session and exclusive maintenance lease. Approval/removal invalidates image readiness before activation. The next preparation detects changed managed kit bytes and rebuilds only a VM whose recorded identity and project mount still match.

Automatic history preservation is limited to 4,096 files, 64 MiB per file, and 128 MiB total. Unknown or unfinished session formats, unsafe links, invalid checksums, or exceeded limits stop replacement before deleting the old VM. Compressed history stays as opaque, hash-checked bytes; it is never decompressed or executed on the host. Private backups contain conversation history and remain owner-only under the installation's `guest-state/` directory. Login state, native databases, arbitrary config, plugins, and skills are excluded. The most recent verified backup is retained; it is not a general disaster-recovery or secure-deletion service.

These checks reduce accidental installation and modification. They cannot prove that arbitrary prose or code is harmless, detect every possible secret, or resist an owner who rewrites the harness itself. A reviewed skill can still contain prompt injection or harmful project operations. Existing filesystem, outbound network, provider-tool, credential, and quota rules continue to enforce their own boundaries; review grants none of those capabilities. Read [BOUNDARIES.md](BOUNDARIES.md) before relying on the sandbox for sensitive work.

## Sources

The official [skill authoring guide](https://learn.chatgpt.com/docs/build-skills) describes `SKILL.md`, supporting scripts/resources, discovery locations, symlinks, and optional dependencies. Native discovery supports several roots; it is not an allowlist of harness-approved packages. This is why this integration keeps native discovery off and supplies its own verified catalog. The supported package subset is intentionally narrower than the full [plugin format](https://developers.openai.com/plugins/build/plugins).
