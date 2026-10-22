"""Local onboarding commands. No credential values appear in arguments or output."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import sys

from guard import Denied, Ledger, atomic_json
from policy import legacy, limits, digest, PolicyError
from configuration import candidate, baselines, refresh_guest


def configure(root, args):
    parser = argparse.ArgumentParser(prog='codex-api configure')
    parser.add_argument('--organization', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--exclusive-organization', action='store_true')
    parser.add_argument('--baseline-a', type=int)
    parser.add_argument('--baseline-b', type=int)
    parser.add_argument('--policy',type=Path)
    parser.add_argument('--reviewed-policy-digest')
    parser.add_argument('--baseline',action='append',default=[])
    parser.add_argument('--allow-api-charges', action='store_true')
    parsed = parser.parse_args(args)
    if not re.fullmatch(r'org-[A-Za-z0-9_-]{4,100}', parsed.organization) or not re.fullmatch(r'proj_[A-Za-z0-9_-]{4,100}', parsed.project):
        raise Denied('Use the organization and project IDs from your API account settings.')
    if parsed.policy:
        if parsed.baseline_a is not None or parsed.baseline_b is not None:raise Denied('Use named --baseline POOL=TOKENS with a custom policy.')
        p=candidate(parsed.policy,parsed.reviewed_policy_digest)
        prior=baselines(parsed.baseline,p)
    else:
        # Legacy flags explicitly opt in to the previous five-model preset.
        if parsed.baseline_a is None or parsed.baseline_b is None or parsed.baseline:raise Denied('Choose an account-specific --policy and a baseline for each pool. The --baseline-a/--baseline-b pair explicitly selects the legacy-five preset.')
        p=legacy();prior={'A':parsed.baseline_a,'B':parsed.baseline_b}
        if any(type(v) is not int or not 0<=v<=limits(p)[g] for g,v in prior.items()):raise Denied('Prior usage must fit the configured daily limits.')
    ceilings=limits(p)
    from gateway import credentials
    if not credentials(root/'openai-key.env').get('OPENAI_API_KEY'):
        raise Denied('Fill the private OpenAI key file first. Never paste the key into chat.')
    with (root/'session.lock').open('a+b') as lease:
        try: fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise Denied('Exit the API session before configuring billing and account binding.')
        if (root/'gateway-process.json').exists(): raise Denied('Stop the API gateway before configuring the account.')
        verification = json.loads((root/'verification.json').read_text())
        old = verification.get('openai', {})
        ledger = Ledger(root/'state')
        try:
            if ledger.db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]:
                # A new account must never inherit another account's ledger or erase usage.
                raise Denied('This installation already has request history. Account changes require a separate installation; no usage was reset.')
            if old.get('account_configured'):
                raise Denied('Account configuration already exists. No baseline or usage was reset.')
            day = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
            # Resume an interrupted first configuration only when its saved
            # baselines are identical. Existing budgets are never replaced.
            with ledger.transaction():
                for group, baseline in prior.items():
                    row=ledger.db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?',('openai:'+group,day)).fetchone()
                    if row is None:
                        ledger.db.execute('INSERT INTO budgets VALUES (?,?,?,?)',('openai:'+group,day,ceilings[group],baseline))
                    elif row!=(ceilings[group],baseline):
                        raise Denied('An existing initial budget differs. No baseline was overwritten.')
            policy = 'metered' if parsed.allow_api_charges else 'free_only'
            old.update(account_configured=True, enabled=True, verified=False,
                       billing_policy=policy, project_id=parsed.project,
                       organization_id=parsed.organization, quota_guard=True,
                       org_exclusive=parsed.exclusive_organization,
                       policy=p,
                       count_endpoint_free_confirmed=False,
                       local_tool_inference_free_confirmed=False)
            verification['openai'] = old
            atomic_json(root/'verification.json', verification)
        finally: ledger.close()
    refresh_guest(root)
    print('Account configured. Daily reservations and the selected safety margin are enabled.')
    if not parsed.exclusive_organization:
        print('Model requests remain blocked: other organization callers are not accounted for.')
    elif not parsed.allow_api_charges:
        print('Free-only mode: model requests remain blocked because free eligibility is unverified.')
    else:
        print('API charges are allowed. Local token limits are not a dollar cap or a free-eligibility guarantee.')


def credentials_location(root):
    print('OpenAI key file: '+str(root/'openai-key.env'))
    print('Fill OPENAI_API_KEY locally. Do not paste it into chat or put it in the workspace.')
    print('Only OpenAI is needed for the initial setup. Search providers stay disabled.')


def billing(root,args):
    parser=argparse.ArgumentParser(prog='codex-api billing')
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--allow-api-charges',action='store_true')
    mode.add_argument('--free-only',action='store_true')
    parsed=parser.parse_args(args)
    with (root/'session.lock').open('a+b') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('Exit the API session before changing billing policy.')
        if (root/'gateway-process.json').exists():raise Denied('Stop the API gateway before changing billing policy.')
        data=json.loads((root/'verification.json').read_text());entry=data['openai']
        if not entry.get('account_configured'):raise Denied('Configure your own account before changing billing policy.')
        entry.update(billing_policy='metered' if parsed.allow_api_charges else 'free_only',verified=False)
        atomic_json(root/'verification.json',data)
    print('Billing policy updated. Account binding, limits, and the usage ledger were preserved.')
    print('API charges are allowed.' if parsed.allow_api_charges else 'Free-only mode: requests remain blocked until free eligibility is verified.')


def command(root, args):
    if not args or args == ['--help']:
        print('codex-api credentials\ncodex-api policy template; codex-api policy check FILE\ncodex-api configure --organization ORG_ID --project PROJECT_ID --policy FILE --reviewed-policy-digest SHA256 --exclusive-organization --baseline POOL=TOKENS [--allow-api-charges]')
        return
    configure(root, args)
