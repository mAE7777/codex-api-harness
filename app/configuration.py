"""Owner-only policy changes with a durable fence, preserved accounting and replay.

Neither project files nor guest arguments can invoke this host command. A crash
never restores an earlier ledger: repeating the identical reviewed apply finishes.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
import uuid
from guard import Denied, Ledger, atomic_json, canonical, pool_info
from policy import PolicyError, validate, load, limits, digest, read_json, recommended, legacy, render


def baselines(items, policy, *, required=True):
    result={}
    for item in items or []:
        group,sep,value=item.partition('=')
        if not sep or group in result or group not in policy['pools'] or not value.isascii() or not value.isdecimal():raise Denied('Use each --baseline POOL=TOKENS once, for a configured pool.',code='policy_invalid')
        result[group]=int(value)
    if required and set(result)!=set(policy['pools']):raise Denied('Provide today\'s prior input plus output usage for every pool; never assume zero.',code='policy_baseline_required')
    if any(n>limits(policy)[g] for g,n in result.items()):raise Denied('Prior usage already exceeds the safe limit. Wait for the next UTC day or review the real allowance.',code='policy_baseline_required')
    return result


def candidate(path, reviewed_digest):
    try:p=validate(read_json(path,private=True))
    except (PolicyError,OSError) as error:raise Denied('Policy review failed: '+str(error),code='policy_invalid') from None
    if reviewed_digest!=digest(p):raise Denied('Review the exact policy and supply its SHA-256 from policy check. No policy was changed.',code='policy_review_required')
    return p


def refresh_guest(root, *, allow_empty=False, policy=None):
    """Replayable guest rendering. Every changed byte is pinned before writing."""
    import tempfile
    root=Path(root)
    if policy is None and (root/'policy-pending.json').exists():raise Denied('Finish the original reviewed policy apply before preparing the guest.',code='policy_change_pending')
    try:p=validate(policy) if policy is not None else load(root,allow_empty=allow_empty,allow_pending=True)
    except (PolicyError,OSError) as error:raise Denied(str(error),code='policy_invalid') from None
    if not p['models']:return False
    manifest_path=root/'installation.json';manifest=read_json(manifest_path,maximum=4*1024*1024) if manifest_path.exists() else None
    targets=('runtime-policy.json','models.json','config.toml');kit=(root/'kit').resolve(strict=True)
    journal_path=root/'policy-render-pending.json'
    if journal_path.exists() or journal_path.is_symlink():
        journal=read_json(journal_path,private=True,maximum=8*1024*1024)
        if set(journal)!={'version','digest','old','new','files'} or journal['version']!=1 or journal['digest']!=digest(p) or manifest not in (journal['old'],journal['new']):raise Denied('The interrupted guest policy render differs. No stale configuration was restored.',code='policy_change_pending')
        if set(journal['files'])!=set(targets):raise Denied('Invalid pending guest policy files.',code='policy_change_pending')
    else:
        with tempfile.TemporaryDirectory(prefix='.policy-render-',dir=root) as tmp:
            tmp=Path(tmp)
            for name in ('model-template.json','config.toml'):(tmp/name).write_bytes((kit/name).read_bytes())
            render(root,tmp,policy=p)
            files={name:(tmp/name).read_text() for name in targets}
        if all((kit/name).exists() and (kit/name).read_text()==data for name,data in files.items()):return False
        new=json.loads(json.dumps(manifest)) if manifest else None
        if new:
            for name,data in files.items():new['files']['kit/'+name]=hashlib.sha256(data.encode()).hexdigest()
        journal={'version':1,'digest':digest(p),'old':manifest,'new':new,'files':files}
    # Check immutable files and both known states of every generated file.
    if journal['old']:
        for name,expected in journal['old']['files'].items():
            path=root/name
            allowed={expected}
            if name in {'kit/'+n for n in targets}:allowed.add(journal['new']['files'][name])
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() not in allowed:raise Denied('Installed bytes changed outside the reviewed policy render.',code='policy_invalid')
    if not journal_path.exists():atomic_json(journal_path,journal)
    if manifest:
        from extensions import _invalidate
        _invalidate(root)
    for name,data in journal['files'].items():
        path=kit/name
        if path.is_symlink():raise Denied('Generated policy files must not be linked.',code='policy_invalid')
        temporary=root/('.policy-file-'+uuid.uuid4().hex)
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(descriptor,'w') as out:out.write(data);out.flush();os.fsync(out.fileno())
            os.replace(temporary,path)
        finally:temporary.unlink(missing_ok=True)
    descriptor=os.open(kit,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    if manifest:atomic_json(manifest_path,journal['new'])
    journal_path.unlink()
    descriptor=os.open(root,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    return True


def apply(root, policy, *, baseline=None):
    root=Path(root);p=validate(policy);baseline=baseline or {};target_digest=digest(p)
    with (root/'upgrade.lock').open('a+b') as upgrade,(root/'session.lock').open('a+b') as session:
        try:
            fcntl.flock(upgrade,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(session,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('Exit the API session and stop the coordinator before changing policy.',code='policy_stop_required') from None
        if (root/'gateway-process.json').exists() or not (root/'paused').exists():raise Denied('Stop the API environment before changing policy.',code='policy_stop_required')
        if (root/'upgrade-pending.json').exists():raise Denied('Finish the code upgrade before changing policy.',code='upgrade_recovery_required')
        if (root/'team-client.json').exists():raise Denied('Shared clients use the coordinator policy. Review and rejoin its invitation instead of creating an independent limit.',code='policy_shared_authority')
        if (root/'team').exists():raise Denied('Coordinator policy is pinned after initialization. Existing allocations and usage were preserved. This release requires a separately reviewed coordinator policy migration.',code='policy_shared_authority')
        journal_path=root/'policy-pending.json';verification=read_json(root/'verification.json',private=True)
        day=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
        ledger=Ledger(root/'state')
        try:
            if journal_path.exists() or journal_path.is_symlink():
                journal=read_json(journal_path,private=True,maximum=8*1024*1024)
                if set(journal)!={'version','digest','day','old','new','changes'} or journal['version']!=1 or journal['digest']!=target_digest:raise Denied('Another policy change is pending. Finish its original reviewed input first.',code='policy_change_pending')
                expected={g:n for g,old_n,new_n,n in journal['changes'] if old_n is None}
                if any(g not in expected or expected[g]!=n for g,n in baseline.items()):raise Denied('The pending baseline differs. Repeat the original reviewed policy command; no prior usage was changed.',code='policy_change_pending')
                if verification not in (journal['old'],journal['new']):raise Denied('Account configuration changed during policy activation. No stale configuration was restored.',code='policy_change_pending')
            else:
                old=load(root,allow_empty=True);old_limits=limits(old) if old['models'] else {};new_limits=limits(p)
                if ledger.db.execute("SELECT 1 FROM requests WHERE phase IN ('reserved','unknown')").fetchone():raise Denied('Resolve uncertain requests before changing policy. No reservation was refunded.',code='quota_reconciliation_required')
                history=ledger.db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
                if set(old_limits)-set(new_limits):raise Denied('Existing quota pools cannot be removed or renamed. Keep their accounting identity.',code='policy_history_conflict')
                historical=verification['openai'].get('model_pool_history',{})|{name:row['pool'] for name,row in old['models'].items()}
                if history and any(name in p['models'] and group!=p['models'][name]['pool'] for name,group in historical.items()):raise Denied('A model cannot move between pools after usage was recorded. No usage was reassigned.',code='policy_history_conflict')
                changes=[]
                for group,ceiling in new_limits.items():
                    row=ledger.db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?',('openai:'+group,day)).fetchone()
                    if row:
                        if group in baseline:raise Denied('Existing baselines cannot be supplied again or reset.',code='policy_history_conflict')
                        if group not in old_limits or row[0]!=old_limits[group]:raise Denied('Existing quota ceiling differs from the saved policy.',code='quota_settings_changed')
                        info=pool_info(ledger.db,group,row[0],day)
                        if ceiling<info['baseline']+info['used_or_reserved']:raise Denied('The proposed limit is below today\'s usage and reservations. No budget was changed.',code='policy_history_conflict')
                        changes.append([group,row[0],ceiling,row[1]])
                    else:
                        if group not in old_limits and group not in baseline:raise Denied('Every new pool needs an explicit --baseline POOL=TOKENS for today.',code='policy_baseline_required')
                        initial=baseline.get(group,ledger.db.execute("SELECT COALESCE(SUM(actual),0) FROM requests WHERE scope='openai:metered' AND period=?",(day,)).fetchone()[0])
                        if type(initial) is not int or not 0<=initial<=ceiling:raise Denied('Invalid prior usage for new pool.',code='policy_baseline_required')
                        changes.append([group,None,ceiling,initial])
                new=json.loads(json.dumps(verification));new['openai']['policy']=p
                new['openai']['model_pool_history']=historical|{name:row['pool'] for name,row in p['models'].items()}
                # Changing the policy invalidates any previous free-use evidence.
                new['openai']['verified']=False
                journal={'version':1,'digest':target_digest,'day':day,'old':verification,'new':new,'changes':changes}
                atomic_json(journal_path,journal)
            with ledger.transaction():
                for group,old_ceiling,new_ceiling,initial in journal['changes']:
                    row=ledger.db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?',('openai:'+group,journal['day'])).fetchone()
                    if row is None and old_ceiling is None:ledger.db.execute('INSERT INTO budgets VALUES (?,?,?,?)',('openai:'+group,journal['day'],new_ceiling,initial))
                    elif row in ((old_ceiling,initial),(new_ceiling,initial)):
                        ledger.db.execute('UPDATE budgets SET ceiling=? WHERE scope=? AND period=?',(new_ceiling,'openai:'+group,journal['day']))
                    else:raise Denied('The pending policy budget differs. No baseline or usage was reset.',code='policy_change_pending')
            atomic_json(root/'verification.json',journal['new'])
            refresh_guest(root,policy=p)
            journal_path.unlink()
            descriptor=os.open(root,os.O_RDONLY)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
        finally:ledger.close()
    print('Policy updated. Account binding, keys, sessions and all recorded usage were preserved.')
    return True


def command(root,args):
    parser=argparse.ArgumentParser(prog='codex-api policy')
    sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('show')
    draft=sub.add_parser('template');draft.add_argument('--preset',choices=['recommended','legacy-five'],default='recommended')
    check=sub.add_parser('check');check.add_argument('file',type=Path)
    update=sub.add_parser('apply');update.add_argument('file',type=Path);update.add_argument('--reviewed-digest',required=True);update.add_argument('--baseline',action='append',default=[])
    parsed=parser.parse_args(args);root=Path(root)
    try:
        if parsed.action=='template':
            path=root/'policy-draft.json'
            if path.exists() or path.is_symlink():raise Denied('The draft already exists and was preserved. Edit or review that private draft.')
            atomic_json(path,recommended() if parsed.preset=='recommended' else legacy())
            print('Policy draft: '+str(path)+'\nThis is a proposal. Confirm the models, capabilities, account tier permissions and actual daily allowance before applying. No request was made.');return
        if parsed.action=='show':
            p=load(root,allow_empty=True);print(json.dumps({'policy':p,'effective_daily_limits':limits(p) if p['models'] else {},'requests_configured':bool(p['models'])},indent=2));return
        p=validate(read_json(parsed.file,private=True));pin=digest(p)
        if parsed.action=='check':print(json.dumps({'valid':True,'digest':pin,'effective_daily_limits':limits(p),'service_tier':p['defaults']['service_tier'],'account_access_verified':False},indent=2));return
        p=candidate(parsed.file,parsed.reviewed_digest)
        return apply(root,p,baseline=baselines(parsed.baseline,p,required=False))
    except (PolicyError,OSError) as error:raise Denied('Policy configuration failed: '+str(error),code='policy_invalid') from None
