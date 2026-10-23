"""Content-free request observations and optional owner-reviewed run/cost limits.

All mutations use the quota ledger's transaction and witness. Estimates never
replace token accounting or claim to be the provider's final bill.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import time
import uuid

from guard import Denied, Ledger, atomic_json, canonical
from policy import digest as policy_digest, load as load_policy, read_json

DETECTOR_VERSION = 1
ID = re.compile(r'[a-zA-Z0-9_.:-]{1,128}\Z')
NO_ERROR_PAUSE={'daily_token_limit','session_token_limit','session_request_limit','spending_limit','utc_day_transition','quota_day_changed','organization_usage_unknown','controls_changed','storage_low','pricing_expired','client_cancelled'}
SCHEMA = '''
CREATE TABLE runtime_config (id INTEGER PRIMARY KEY, digest TEXT NOT NULL);
CREATE TABLE runtime_requests (
 id TEXT PRIMARY KEY, namespace TEXT NOT NULL, run_id TEXT NOT NULL,
 created REAL NOT NULL, day TEXT NOT NULL, month TEXT NOT NULL, phase TEXT NOT NULL,
 reserved_tokens INTEGER NOT NULL DEFAULT 0, actual_tokens INTEGER,
 cost_hold INTEGER NOT NULL DEFAULT 0, cost_actual INTEGER, count_hold INTEGER NOT NULL DEFAULT 0,
 input_tokens INTEGER, output_tokens INTEGER, cached_tokens INTEGER, reasoning_tokens INTEGER,
 model TEXT NOT NULL, tier TEXT NOT NULL, error_code TEXT, provider_request_id TEXT,
 reported_model TEXT, reported_tier TEXT, counted INTEGER NOT NULL DEFAULT 0,
 input_count INTEGER, request_id TEXT, tool_fingerprint TEXT, completed REAL);
CREATE INDEX runtime_run ON runtime_requests(namespace,run_id);
CREATE INDEX runtime_day ON runtime_requests(day);
CREATE INDEX runtime_month ON runtime_requests(month);
CREATE TABLE runtime_ack (namespace TEXT,run_id TEXT,last_row INTEGER NOT NULL,PRIMARY KEY(namespace,run_id));
CREATE TABLE runtime_baselines (period TEXT PRIMARY KEY,amount INTEGER NOT NULL);
'''


def fail(message, code='controls_invalid'):
    raise Denied(message, code=code)


def defaults(policy):
    return {'version':1, 'policy_digest':policy_digest(policy), 'session_tokens':None,
            'session_requests':None, 'consecutive_errors':0, 'minimum_free_bytes':0, 'spending':None}


def number(value, low, high, name, *, optional=False):
    if optional and value is None:return
    if type(value) is not int or not low<=value<=high:fail('Invalid '+name+'.')


def validate(value, policy):
    if not isinstance(value,dict) or set(value)!=set(defaults(policy)) or value['version']!=1 or type(value['version']) is not int:
        fail('Invalid controls schema; unknown fields are refused.')
    if value['policy_digest']!=policy_digest(policy):fail('Controls must be reviewed against the current model policy.')
    number(value['session_tokens'],1,10**12,'session token ceiling',optional=True)
    number(value['session_requests'],1,10**6,'session request ceiling',optional=True)
    number(value['consecutive_errors'],0,32,'consecutive-error limit')
    number(value['minimum_free_bytes'],0,10**12,'minimum free storage')
    spending=value['spending']
    if spending is not None:
        fields={'daily_micro_usd','monthly_micro_usd','baselines','prices','valid_until','count_request_max_micro_usd'}
        if not isinstance(spending,dict) or set(spending)!=fields:fail('Invalid spending policy.')
        for key in ('daily_micro_usd','monthly_micro_usd'):number(spending[key],1,10**15,key,optional=True)
        if spending['daily_micro_usd'] is None and spending['monthly_micro_usd'] is None:fail('Select a daily or monthly spending ceiling.')
        number(spending['count_request_max_micro_usd'],0,10**12,'reviewed count-request upper price')
        number(spending['valid_until'],1,2**53-1,'pricing expiry')
        if not isinstance(spending['baselines'],dict) or len(spending['baselines'])>2:fail('Provide explicit current daily/monthly prior-use baselines.')
        for period,amount in spending['baselines'].items():
            if not re.fullmatch(r'\d{4}-\d{2}(?:-\d{2})?',period):fail('Invalid baseline period.')
            try:dt.datetime.strptime(period,'%Y-%m-%d' if len(period)==10 else '%Y-%m')
            except ValueError:fail('Invalid baseline date.')
            number(amount,0,10**15,'prior spending baseline')
        if not isinstance(spending['prices'],dict) or set(spending['prices'])!=set(policy['models']):fail('Every selected model requires reviewed upper-bound pricing.')
        for row in spending['prices'].values():
            if not isinstance(row,dict) or set(row)!={'tier','input_micro_usd_per_million','output_micro_usd_per_million','reference'}:fail('Invalid model price record.')
            if row['tier']!=policy['defaults']['service_tier']:fail('Pricing must match the fixed service tier.')
            for k in ('input_micro_usd_per_million','output_micro_usd_per_million'):number(row[k],0,10**15,k)
            if not isinstance(row['reference'],str) or not re.fullmatch(r'https://(?:developers\.openai\.com|platform\.openai\.com)/[A-Za-z0-9_./?#=&%+-]{1,480}',row['reference']):fail('Provide an official pricing reference.')
    return value


def load(root, policy):
    path=Path(root)/'controls.json'
    return validate(read_json(path,private=True),policy) if path.exists() or path.is_symlink() else defaults(policy)


def ensure_schema(ledger):
    with ledger.mutex:
        if ledger.db.execute("SELECT 1 FROM sqlite_master WHERE name='runtime_requests'").fetchone():return
        # executescript commits implicitly; use the witnessed transaction.
        with ledger.transaction():
            for statement in SCHEMA.split(';'):
                if statement.strip():ledger.db.execute(statement)


def run_identity(root):
    path=Path(root)/'active-run.json'
    if not path.exists():return 'unassigned'
    row=read_json(path,private=True)
    if set(row)!={'version','run_id'} or row['version']!=1 or not isinstance(row['run_id'],str) or not re.fullmatch(r'[a-f0-9]{32}',row['run_id']):fail('The host run identity is invalid.')
    return row['run_id']


def upper_cost(price, input_tokens, output_tokens):
    # Cache is deliberately priced at the full input upper bound. Reasoning is
    # already a subset of output. Integer arithmetic always rounds upward.
    return (input_tokens*price['input_micro_usd_per_million']+output_tokens*price['output_micro_usd_per_million']+999999)//1000000


def storage_check(root, floor):
    if floor and shutil.disk_usage(root).free<floor:
        fail('Private storage is below the reviewed free-space floor. No new model request was sent. Free space deliberately; no files were deleted.','storage_low')


def spending_rows(db,config,policy,now,excluding=None):
    spending=config['spending']
    if spending is None:return []
    instant=dt.datetime.fromtimestamp(now,dt.timezone.utc);result=[]
    for key,period,column in [('daily_micro_usd',instant.strftime('%Y-%m-%d'),'day'),('monthly_micro_usd',instant.strftime('%Y-%m'),'month')]:
        if spending[key] is None:continue
        prior=db.execute('SELECT amount FROM runtime_baselines WHERE period=?',(period,)).fetchone()
        baseline=prior[0] if prior else 0
        boundary=dt.datetime.strptime(period,'%Y-%m-%d' if column=='day' else '%Y-%m').replace(tzinfo=dt.timezone.utc).timestamp()
        overlap=policy['defaults']['request_deadline_seconds']+15
        rows=db.execute(f'SELECT id,cost_hold,cost_actual FROM runtime_requests WHERE {column}=? OR phase IN (\'counting\',\'reserved\',\'unknown\') OR completed>=? OR (created>=? AND created<?)',(period,boundary,boundary-overlap,boundary)).fetchall()
        used=baseline+sum(r[2] if r[2] is not None else r[1] for r in rows if r[0]!=excluding)
        result.append({'period':period,'limit_micro_usd':spending[key],'baseline_micro_usd':baseline,'used_or_held_micro_usd':used,'remaining_micro_usd':max(0,spending[key]-used)})
    return result


class Runtime:
    def __init__(self, root, ledger, policy, *, namespace='local', clock=time.time):
        self.root,self.ledger,self.policy,self.namespace,self.clock=Path(root),ledger,policy,namespace,clock
        ensure_schema(ledger)
        self.config=load(root,policy)
        expected=ledger.db.execute('SELECT digest FROM runtime_config WHERE id=1').fetchone()
        if expected and expected[0]!=hashlib.sha256(canonical(self.config)).hexdigest():fail('Reviewed controls changed or disappeared. Restore them or apply an exact reviewed update.','controls_changed')
        if (self.root/'controls.json').exists() and not expected:fail('Controls require explicit digest approval before use.','controls_changed')

    def storage(self):
        if load(self.root,self.policy)!=self.config:fail('Controls changed during this request. No generation was sent.','controls_changed')
        storage_check(self.root,self.config['minimum_free_bytes'])

    def count_started(self, identity):
        with self.ledger.transaction():self.ledger.db.execute('UPDATE runtime_requests SET counted=1 WHERE id=?',(identity,))

    def _cost_capacity(self, added, excluding=None):
        spending=self.config['spending']
        if spending is None:return
        if self.clock()>=spending['valid_until']:fail('Reviewed upper-bound pricing expired. No model request was sent.','pricing_expired')
        for row in spending_rows(self.ledger.db,self.config,self.policy,self.clock(),excluding):
            if row['used_or_held_micro_usd']+added>row['limit_micro_usd']:
                fail('The reviewed '+('daily' if len(row['period'])==10 else 'monthly')+' USD ceiling cannot cover this request. Existing reservations remain held.','spending_limit')

    def start(self, identity, normalized, run_id=None):
        self.storage()
        if (self.ledger.root/'controls-stop.json').exists() or self.ledger.db.execute('SELECT 1 FROM runtime_requests WHERE cost_actual>cost_hold').fetchone():fail('A confirmed cost exceeded its reservation. Review report and the pricing policy before controls resume.','cost_above_reservation')
        run=run_id or run_identity(self.root)
        if not isinstance(run,str) or not re.fullmatch(r'[a-f0-9]{32}|unassigned',run):fail('Invalid run identity.')
        spending=self.config['spending']
        charge=spending['count_request_max_micro_usd'] if spending else 0
        now=self.clock();day=dt.datetime.fromtimestamp(now,dt.timezone.utc).strftime('%Y-%m-%d')
        calls=[x for x in normalized.get('input',[]) if isinstance(x,dict) and x.get('type') in {'function_call','custom_tool_call'}] if isinstance(normalized.get('input'),list) else []
        fingerprint=hashlib.sha256(canonical({k:calls[-1].get(k) for k in ('name','arguments','input')})).hexdigest() if calls else None
        with self.ledger.transaction():
            rows=self.ledger.db.execute('SELECT phase,reserved_tokens,actual_tokens,error_code,rowid FROM runtime_requests WHERE namespace=? AND run_id=? ORDER BY rowid DESC',(self.namespace,run)).fetchall()
            maximum=self.config['session_requests']
            if maximum is not None and len(rows)>=maximum:fail('The run request ceiling was reached. Review the run before intentionally starting new work.','session_request_limit')
            token_limit=self.config['session_tokens']
            used=sum(r[2] if r[2] is not None else r[1] for r in rows)
            if token_limit is not None and used+normalized['max_output_tokens']>token_limit:fail('The run cannot cover another output reservation. Daily usage is preserved.','session_token_limit')
            n=self.config['consecutive_errors']
            ack=self.ledger.db.execute('SELECT last_row FROM runtime_ack WHERE namespace=? AND run_id=?',(self.namespace,run)).fetchone()
            recent=[r for r in rows if not ack or r[4]>ack[0]][:n] if n else []
            if len(recent)==n and n and recent[0][3] and recent[0][3] not in NO_ERROR_PAUSE and all(r[3]==recent[0][3] for r in recent):fail('The same request error repeated. Inspect report, then explicitly acknowledge with codex-api session continue RUN_ID --reviewed.','repeated_request_error')
            self._cost_capacity(charge)
            self.ledger.db.execute('INSERT INTO runtime_requests(id,namespace,run_id,created,day,month,phase,model,tier,cost_hold,count_hold,tool_fingerprint) VALUES(?,?,?,?,?,?,\'counting\',?,?,?,?,?)',
                (identity,self.namespace,run,now,day,day[:7],normalized['model'],normalized['service_tier'],charge,charge,fingerprint))

    def reserve(self, identity, count, maximum):
        self.storage()
        with self.ledger.transaction():
            row=self.ledger.db.execute('SELECT namespace,run_id,model,cost_hold FROM runtime_requests WHERE id=?',(identity,)).fetchone()
            if not row:fail('Request observation is missing.')
            used=self.ledger.db.execute('SELECT COALESCE(SUM(COALESCE(actual_tokens,reserved_tokens)),0) FROM runtime_requests WHERE namespace=? AND run_id=? AND id!=?',(row[0],row[1],identity)).fetchone()[0]
            amount=count+maximum
            if self.config['session_tokens'] is not None and used+amount>self.config['session_tokens']:fail('The complete input and maximum output do not fit this run budget. No generation was sent.','session_token_limit')
            spending=self.config['spending'];cost=row[3]
            if spending:cost+=upper_cost(spending['prices'][row[2]],count,maximum)
            self._cost_capacity(cost,identity)
            self.ledger.db.execute("UPDATE runtime_requests SET reserved_tokens=?,input_count=?,counted=1,cost_hold=?,phase='reserved' WHERE id=?",(amount,count,cost,identity))

    def dispatch(self, identity, request_id):
        self.storage()
        with self.ledger.transaction():
            row=self.ledger.db.execute('SELECT cost_hold FROM runtime_requests WHERE id=?',(identity,)).fetchone()
            self._cost_capacity(row[0],identity)
            self.ledger.db.execute("UPDATE runtime_requests SET phase='unknown',request_id=? WHERE id=?",(request_id,identity))

    def settle(self, identity, usage, reported=None):
        from gateway import terminal_tokens
        total=terminal_tokens(usage)
        def subset(section,key,limit):
            value=usage.get(section,{})
            value=value.get(key) if isinstance(value,dict) else None
            return value if type(value) is int and 0<=value<=limit else None
        reported=reported if isinstance(reported,dict) else {}
        def safe(value):return value if isinstance(value,str) and ID.fullmatch(value) else None
        exceeded=False
        with self.ledger.transaction():
            row=self.ledger.db.execute('SELECT model,cost_hold FROM runtime_requests WHERE id=?',(identity,)).fetchone()
            cost=None
            if self.config['spending']:
                s=self.config['spending'];cost=s['count_request_max_micro_usd']+upper_cost(s['prices'][row[0]],usage['input_tokens'],usage['output_tokens'])
                exceeded=cost>row[1]
            self.ledger.db.execute("UPDATE runtime_requests SET phase='settled',actual_tokens=?,cost_actual=?,input_tokens=?,output_tokens=?,cached_tokens=?,reasoning_tokens=?,reported_model=?,reported_tier=?,completed=? WHERE id=?",
                (total,cost,usage['input_tokens'],usage['output_tokens'],subset('input_tokens_details','cached_tokens',usage['input_tokens']),subset('output_tokens_details','reasoning_tokens',usage['output_tokens']),safe(reported.get('model')),safe(reported.get('service_tier')),self.clock(),identity))
        if exceeded:
            atomic_json(self.ledger.root/'controls-stop.json',{'version':1,'reason':'cost_above_reservation','operation_id':identity})
            fail('Confirmed usage exceeded its cost reservation. Confirmed cost was retained; further requests are stopped.','cost_above_reservation')

    def failed(self, identity, error):
        with self.ledger.transaction():
            row=self.ledger.db.execute('SELECT phase,request_id,counted FROM runtime_requests WHERE id=?',(identity,)).fetchone()
            if not row:return
            code=getattr(error,'code',None) or 'request_failed'
            if not isinstance(code,str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,96}',code):code='request_failed'
            original=self.ledger.db.execute('SELECT phase FROM requests WHERE id=?',(row[1],)).fetchone() if row[1] else None
            unsent=row[0] in {'counting','reserved'} or original and original[0]=='not_sent'
            if unsent:
                s=self.config['spending'];cost=s['count_request_max_micro_usd'] if s and row[2] else 0 if s else None
                self.ledger.db.execute("UPDATE runtime_requests SET phase='unsent',actual_tokens=0,cost_actual=?,reserved_tokens=0,error_code=?,completed=? WHERE id=?",(cost,code,self.clock(),identity))
            else:self.ledger.db.execute('UPDATE runtime_requests SET error_code=? WHERE id=?',(code,identity))


def command(root,args):
    from maintenance import stopped
    parser=argparse.ArgumentParser(prog='codex-api controls')
    sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('show');draft=sub.add_parser('draft');draft.add_argument('file')
    resume=sub.add_parser('resume');resume.add_argument('--reviewed',action='store_true')
    inspect=sub.add_parser('inspect');inspect.add_argument('file')
    apply=sub.add_parser('apply');apply.add_argument('file');apply.add_argument('--digest',required=True);apply.add_argument('--reviewed',action='store_true')
    options=parser.parse_args(args);root=Path(root);policy=load_policy(root)
    if options.action=='show':print(json.dumps(load(root,policy),indent=2));return
    if options.action=='resume':
        if not options.reviewed:fail('Inspect report and current prices, then use --reviewed.')
        with stopped(root):
            if (root/'team-client.json').exists():fail('Only the coordinator owner can resume shared cost controls.')
            ledger=Ledger(root/('team/state' if (root/'team').exists() else 'state'))
            try:
                runtime=Runtime(root,ledger,policy)
                with ledger.transaction():
                    if ledger.db.execute("SELECT 1 FROM runtime_requests WHERE phase IN ('counting','reserved','unknown')").fetchone():fail('Resolve unfinished observations and provider requests before resuming.')
                    runtime._cost_capacity(0)
                    ledger.db.execute('UPDATE runtime_requests SET cost_hold=cost_actual WHERE cost_actual>cost_hold')
                (ledger.root/'controls-stop.json').unlink(missing_ok=True)
            finally:ledger.close()
        print('Cost discrepancy acknowledged. Recorded usage and spending ceilings were preserved.');return
    if options.action=='draft':
        p=Path(options.file)
        if p.exists() or p.is_symlink() or p.parent.resolve()!=root.resolve():fail('Create the controls draft in the private installation, using a new filename.')
        value=defaults(policy);value.update(consecutive_errors=3,minimum_free_bytes=128*1024*1024)
        atomic_json(p,value);print('Private controls draft: '+str(p));return
    value=validate(read_json(options.file,private=True),policy);digest=hashlib.sha256(canonical(value)).hexdigest()
    if options.action=='inspect':print(json.dumps({'digest':digest,'controls':value,'provider_requests':0},indent=2));return
    if options.digest!=digest or not options.reviewed:fail('Approve the exact inspected controls digest with --reviewed.')
    with stopped(root):
        target=root/'team/state' if (root/'team').exists() and not (root/'team-client.json').exists() else root/'state'
        if (root/'team-client.json').exists():fail('Shared request controls are owned by the coordinator. Review them with its owner.')
        ledger=Ledger(target)
        try:
            ensure_schema(ledger)
            with ledger.transaction():
                prior=ledger.db.execute('SELECT digest FROM runtime_config WHERE id=1').fetchone()
                if not prior or prior[0]!=digest:
                    if ledger.db.execute("SELECT 1 FROM requests WHERE phase IN ('reserved','unknown')").fetchone() or ledger.db.execute("SELECT 1 FROM runtime_requests WHERE phase IN ('counting','reserved','unknown')").fetchone():
                        fail('Resolve unfinished requests before changing controls. Existing holds and prices were preserved.')
                s=value['spending']
                if s:
                    now=dt.datetime.now(dt.timezone.utc)
                    for key,period in [('daily_micro_usd',now.strftime('%Y-%m-%d')),('monthly_micro_usd',now.strftime('%Y-%m'))]:
                        if s[key] is None:continue
                        prior=ledger.db.execute('SELECT amount FROM runtime_baselines WHERE period=?',(period,)).fetchone()
                        if prior is None:
                            if period not in s['baselines']:fail('Provide verified prior spending for the current enabled period, including zero when confirmed.')
                            ledger.db.execute('INSERT INTO runtime_baselines VALUES(?,?)',(period,s['baselines'][period]))
                        elif period in s['baselines'] and s['baselines'][period]!=prior[0]:fail('An existing spending baseline cannot be rewritten.')
                # Existing request holds are retained on every controls change.
                ledger.db.execute('INSERT OR REPLACE INTO runtime_config VALUES(1,?)',(digest,))
            atomic_json(root/'controls.json',value)
        finally:ledger.close()
    print('Reviewed controls applied. Existing token usage and reservations were preserved.')
