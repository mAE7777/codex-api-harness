# Working in this repository

When the user asks to install or configure this harness, read **SETUP.md in full** and follow it. The user wants an automated, understandable setup, not a wall of commands.

- Inspect first. Explain the result briefly in the user's language.
- Ask for missing choices at the point they become necessary. Offer the recommended option first and explain the consequence in one sentence.
- Do not ask for API keys, passwords, tokens, or private configuration contents in chat. Create the supported private file, tell the owner exactly where it is, and let them fill it locally. Never print it or include it in tool output.
- Never inherit an existing API key, subscription login, shell secret, SSH agent, browser session, plugin, or personal skill.
- Do not scan unrelated repositories or home-directory contents. Use the bounded context inventory in SETUP.md.
- Do not allow API charges, assert free eligibility, initialize shared Docker policy, install missing system prerequisites, or mount an existing project without the owner's informed choice. Prior explicit authorization remains valid; do not ask again.
- Use local-only acceptance. Do not send a real prompt merely to prove installation works.
- Stop at failed prerequisites or failed checks. Explain the exact problem and continue independent setup work where useful. Never invent a PASS record.
- Preserve existing launchers, private state, ledgers, unrelated sandboxes, and subscription configuration.

For code changes, run `python3 scripts/check.py`. Before publishing, also run `python3 scripts/check_public.py` against the staged/tracked files and scan Git history with a secret scanner. Never commit an installed environment, runtime log, model/account export, personal acceptance report, key, database, or `.env` file. Source model metadata must not include account-derived `model_messages`.
