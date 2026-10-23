"""Read-only accounting explanation. Never read prompts or subscription history."""
from __future__ import annotations
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import time

from guard import Denied, Ledger, readonly_database, pool_info
from policy import load as load_policy, limits


def snapshot(root, policy, *, namespace='local', now=None, quota=None):
    root=Path(root);now=time.time() if now is None else now
    instant=dt.datetime.fromtimestamp(now,dt.timezone.utc);day=instant.strftime('%Y-%m-%d')
    for attempt in range(4):
        with readonly_database(root/'state') as db:
            db.execute('BEGIN')
            identity,sequence,paused=db.execute('SELECT * FROM meta').fetchone()
            witness=json.loads((root/'state/ledger-witness.json').read_text())
            if witness!={'identity':identity,'sequence':sequence}:
                if attempt<3:continue
                raise Denied('Usage state changed during inspection. Retry report; nothing was repaired.',code='quota_state_unavailable')
            pools={}
            if quota is None:
                for group,ceiling in limits(policy).items():
                    info=pool_info(db,group,ceiling,day);scope='openai:'+group
                    actual,held=db.execute("SELECT COALESCE(SUM(CASE WHEN phase='settled' THEN actual ELSE 0 END),0),COALESCE(SUM(CASE WHEN phase!='settled' THEN reserved ELSE 0 END),0) FROM requests WHERE scope=? AND period=?",(scope,day)).fetchone()
                    prior=db.execute("SELECT COALESCE(SUM(reserved),0) FROM requests WHERE scope=? AND period!=? AND phase IN ('reserved','unknown')",(scope,day)).fetchone()[0]
                    overlap=db.execute('SELECT COALESCE(SUM(amount),0) FROM carryovers WHERE scope=? AND period=?',(scope,day)).fetchone()[0]
                    pools[group]=dict(info,confirmed_tokens=actual,current_holds=held,prior_unconfirmed_holds=prior,utc_overlap=overlap,
                        safety_margin=policy['pools'][group]['daily_tokens']-ceiling)
            else:
                pools={g:dict(row) for g,row in quota['daily_pools'].items()}
                member=quota['member_id']
                for group,row in pools.items():
                    scope='openai:'+group
                    actual,held=db.execute("SELECT COALESCE(SUM(CASE WHEN r.phase='settled' THEN r.actual ELSE 0 END),0),COALESCE(SUM(CASE WHEN r.phase!='settled' THEN r.reserved ELSE 0 END),0) FROM requests r JOIN team_requests t ON r.id=t.id WHERE t.member=? AND r.scope=? AND r.period=?",(member,scope,day)).fetchone()
                    prior=db.execute("SELECT COALESCE(SUM(r.reserved),0) FROM requests r JOIN team_requests t ON r.id=t.id WHERE t.member=? AND r.scope=? AND r.period!=? AND r.phase IN ('reserved','unknown')",(member,scope,day)).fetchone()[0]
                    overlap=db.execute('SELECT COALESCE(SUM(c.amount),0) FROM carryovers c JOIN team_requests t ON c.request_id=t.id WHERE t.member=? AND c.scope=? AND c.period=?',(member,scope,day)).fetchone()[0]
                    row.update(confirmed_tokens=actual,current_holds=held,prior_unconfirmed_holds=prior,utc_overlap=overlap,safety_margin=0,
                               remaining_rule='minimum of member, project, and organization remaining')
            recent=[];runs=[]
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE name='runtime_requests'").fetchone()
            if exists:
                cursor=db.execute('SELECT id,run_id,created,phase,reserved_tokens,actual_tokens,input_count,input_tokens,cached_tokens,output_tokens,reasoning_tokens,model,tier,reported_model,reported_tier,error_code,provider_request_id,request_id,cost_hold,cost_actual,completed FROM runtime_requests WHERE namespace=? ORDER BY rowid DESC LIMIT 20',(namespace,))
                keys=[d[0] for d in cursor.description]
                for row in cursor:
                    item=dict(zip(keys,row));item['reasoning_is_output_subset']=True
                    item['next_step']=('Inspect reconcile; a retry may spend again.' if item['phase'] in {'unknown','reserved','counting'} else 'No automatic retry was made.' if item['error_code'] else 'Completed usage is recorded.')
                    recent.append(item)
                rows=db.execute('SELECT run_id,COUNT(*),SUM(COALESCE(actual_tokens,reserved_tokens)),MAX(created) FROM runtime_requests WHERE namespace=? GROUP BY run_id ORDER BY MAX(created) DESC LIMIT 20',(namespace,)).fetchall()
                runs=[dict(zip(('run_id','requests','used_or_held_tokens','last_activity'),r)) for r in rows]
            result={'version':1,'observed_at':instant.isoformat(),'period':day,'reset_at':(instant.replace(hour=0,minute=0,second=0,microsecond=0)+dt.timedelta(days=1)).isoformat(),
                    'ledger_sequence':sequence,'paused':bool(paused),'daily_pools':pools,'recent_requests':recent,'runs':runs,
                    'metadata_available':bool(exists),'currency':'USD upper-bound estimates only; not a provider bill',
                    'provider_requests':0,'content_logged':False,'shared':quota is not None}
            if exists:
                from runtime_controls import load,spending_rows
                try:
                    config=load(root.parent if quota is not None else root,policy)
                    result['controls']={k:v for k,v in config.items() if k not in {'spending','policy_digest'}}
                    result['spending_budgets']=spending_rows(db,config,policy,now)
                    result['pricing_valid_until']=config['spending']['valid_until'] if config['spending'] else None
                except (Denied,OSError,ValueError):result['controls_error']='controls_invalid'
            if len(recent)>=3:
                repeats=db.execute('SELECT tool_fingerprint FROM runtime_requests WHERE namespace=? ORDER BY rowid DESC LIMIT 3',(namespace,)).fetchall()
                result['signals']=['Repeated recent tool input; inspect progress before continuing.'] if repeats and repeats[0][0] and all(r==repeats[0] for r in repeats) else []
            else:result['signals']=[]
            return result


def render(value):
    lines=['Request report | '+value['period']+' UTC','Resets: '+value['reset_at']]
    for group,row in value['daily_pools'].items():
        lines.append(group+': '+str(row['remaining'])+' tokens remaining')
        if 'confirmed_tokens' in row:
            lines.append('  Confirmed '+str(row['confirmed_tokens'])+' | current holds '+str(row['current_holds'])+' | prior holds '+str(row['prior_unconfirmed_holds'])+' | UTC overlap '+str(row['utc_overlap'])+' | baseline '+str(row['baseline'])+' | safety margin '+str(row['safety_margin']))
    if not value['recent_requests']:lines.append('No detailed request observations yet; historical missing fields are unavailable.')
    for row in value.get('spending_budgets',[]):lines.append('USD '+row['period']+': '+str(row['remaining_micro_usd'])+' / '+str(row['limit_micro_usd'])+' micro-USD remaining (reviewed upper-bound accounting).')
    for row in value['recent_requests'][:5]:
        def show(k):return 'unavailable' if row[k] is None else str(row[k])
        lines.extend([row['id']+' | '+row['phase']+' | '+row['model']+' / '+row['tier'],
            '  Input '+show('input_tokens')+' (cached '+show('cached_tokens')+') | output '+show('output_tokens')+' (reasoning subset '+show('reasoning_tokens')+')',
            '  Run '+row['run_id']+' | '+row['next_step']])
        if row['error_code']:lines.append('  Error: '+row['error_code'])
    lines.extend(value.get('signals',[]));lines.append('No provider request was made. Currency estimates do not establish free eligibility.')
    return '\n'.join(lines)


def report(root):
    root=Path(root)
    if (root/'team-client.json').exists():
        from team_client import RemoteBroker
        return RemoteBroker(root).report()
    if (root/'team').exists():raise Denied('Use a joined client for a member-scoped report. Coordinator accounting is available with team usage.',code='team_client_required')
    return snapshot(root,load_policy(root))


def command(root,args):
    parser=argparse.ArgumentParser(prog='codex-api report')
    parser.add_argument('--json',action='store_true')
    options=parser.parse_args(args);value=report(root)
    print(json.dumps(value,indent=2) if options.json else render(value))
    return value


def session(root,args):
    parser=argparse.ArgumentParser(prog='codex-api session')
    sub=parser.add_subparsers(dest='action',required=True)
    listing=sub.add_parser('list');listing.add_argument('--json',action='store_true')
    handoff=sub.add_parser('handoff');handoff.add_argument('--json',action='store_true')
    continuing=sub.add_parser('continue');continuing.add_argument('run_id');continuing.add_argument('--reviewed',action='store_true')
    continuing.add_argument('--member')
    resolving=sub.add_parser('resolve');resolving.add_argument('operation_id');resolving.add_argument('--reviewed',action='store_true')
    options=parser.parse_args(args)
    if options.action in {'list','handoff'}:
        value=report(root)
        if options.action=='list':print(json.dumps({'runs':value['runs']},indent=2) if options.json else '\n'.join(r['run_id']+' | '+str(r['used_or_held_tokens'])+' tokens used or held' for r in value['runs']) or 'No recorded API runs.')
        else:print(json.dumps(value,indent=2) if options.json else render(value)+'\nResume the API CLI with codex-api resume --last. No model summary was generated; verify project progress before continuing.')
        return
    if options.action=='resolve':
        if not options.reviewed or not re.fullmatch(r'[a-f0-9]{32}',options.operation_id):raise Denied('Review the operation ID and use --reviewed.',code='controls_invalid')
        if (Path(root)/'team-client.json').exists() or (Path(root)/'team').exists():raise Denied('Use coordinator reconciliation for shared requests.',code='team_request_forbidden')
        from maintenance import stopped
        with stopped(root):
            ledger=Ledger(Path(root)/'state')
            try:
                with ledger.transaction():
                    row=ledger.db.execute('SELECT phase,request_id FROM runtime_requests WHERE id=?',(options.operation_id,)).fetchone()
                    if not row or row[0] not in {'counting','reserved'} or row[1] is not None:raise Denied('Only a stopped, undispatched operation can be resolved here. Use reconcile for dispatched requests.',code='controls_invalid')
                    ledger.db.execute("UPDATE runtime_requests SET phase='unsent',actual_tokens=0,reserved_tokens=0,cost_actual=CASE WHEN counted=1 THEN count_hold ELSE 0 END,completed=? WHERE id=?",(time.time(),options.operation_id))
            finally:ledger.close()
        print('Undispatched operation resolved. No generation usage was refunded; the possible count charge remains.');return
    if not options.reviewed or not re.fullmatch(r'[a-f0-9]{32}|unassigned',options.run_id):raise Denied('Review report, then acknowledge the exact run ID with --reviewed.',code='controls_invalid')
    if (Path(root)/'team-client.json').exists():raise Denied('Shared error acknowledgements require the coordinator owner; member requests cannot clear a pause.',code='team_request_forbidden')
    shared=(Path(root)/'team').exists()
    if shared and (not options.member or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}',options.member)):raise Denied('The coordinator owner must specify the exact --member.',code='team_request_forbidden')
    if not shared and options.member:raise Denied('--member is only for a coordinator owner.',code='team_request_forbidden')
    namespace='member:'+options.member if shared else 'local'
    from maintenance import stopped
    with stopped(root):
        ledger=Ledger(Path(root)/('team/state' if shared else 'state'))
        try:
            from runtime_controls import ensure_schema
            ensure_schema(ledger)
            with ledger.transaction():
                last=ledger.db.execute('SELECT MAX(rowid) FROM runtime_requests WHERE namespace=? AND run_id=?',(namespace,options.run_id)).fetchone()[0]
                if last is None:raise Denied('Run ID was not found.',code='controls_invalid')
                ledger.db.execute('INSERT OR REPLACE INTO runtime_ack VALUES(?,?,?)',(namespace,options.run_id,last))
        finally:ledger.close()
    print('Repeated-error pause acknowledged. Token and spending ceilings, usage, and unknown holds are unchanged.')
