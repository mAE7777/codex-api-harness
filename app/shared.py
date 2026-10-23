"""Optional organization coordinator. Members can infer, never administer or settle.

The HTTP listener is loopback-only: another computer reaches it through an
owner-established encrypted tunnel. Administrative mutations use a private UNIX
socket, not the member HTTP interface. All authoritative quotas share one Ledger.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import socketserver
import stat
import threading
import time
import uuid

from guard import Denied, Ledger, DAILY_LIMITS, atomic_json, canonical, pool_info
from policy import load as load_policy, validate as validate_policy, limits as policy_limits, legacy, digest as policy_digest, usage_lines, read_json as policy_json
from gateway import Broker, decode_json, public_error, upstream

DEFAULT_PORT = 49200
SERVICE = 'codex-api-team'


def _upgrade_lease(owner_root):
    descriptor=os.open(Path(owner_root)/'upgrade.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    lease=os.fdopen(descriptor,'a+b')
    try:fcntl.flock(lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise Denied('A harness upgrade is in progress. The coordinator was not started.',code='upgrade_in_progress') from None
    return lease


def _private_directory(path, *, create=False):
    path = Path(path)
    if path.is_symlink(): raise Denied('Shared state must not be a symlink.', code='team_state_unsafe')
    if create: path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Denied('Shared state must be an owner-only private directory (0700).', code='team_state_unsafe')
    return path


def _identifier(value, kind='member'):
    pattern = r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}' if kind == 'member' else r'proj_[A-Za-z0-9_-]{4,100}'
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise Denied('Invalid '+kind+' identifier.', code='team_configuration_invalid')
    return value


def _limits(a=None, b=None, *, zero=True, ceilings=None):
    ceilings=ceilings or DAILY_LIMITS
    values=a if isinstance(a,dict) and b is None else {'A':a,'B':b}
    if not isinstance(values,dict) or set(values)!=set(ceilings) or any(type(v) is not int or not (0 if zero else 1)<=v<=ceilings[g] for g,v in values.items()):
        raise Denied('Provide one integer allocation per approved pool, within the organization safety limits.',code='team_allocation_invalid')
    return values


def _read_private(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 65536:
            raise Denied('Shared configuration must be an owner-only regular file.', code='team_state_unsafe')
        return decode_json(source.read(65537))


class Team:
    def __init__(self, root, *, clock=time.time):
        self.root = _private_directory(root)
        self.upgrade_lease=_upgrade_lease(self.root.parent)
        try:self.ledger = Ledger(self.root/'state', clock=clock)
        except Exception:self.upgrade_lease.close();raise
        self.clock = clock
        self.mutex = self.ledger.mutex
        self.stopping = threading.Event()
        self.running = False
        self.request_notice = None
        try:
            row = self.ledger.db.execute('SELECT coordinator,organization,revision FROM team_config').fetchone()
            if not row: raise Denied('The coordinator has not been initialized.', code='team_not_initialized')
            self.coordinator_id, self.organization_id, _ = row
            self.policy=validate_policy(policy_json(self.root/'policy.json',private=True)) if (self.root/'policy.json').exists() else legacy()
            self.limits=policy_limits(self.policy)
            self.ledger.overlap_seconds=self.policy['defaults']['request_deadline_seconds']+15
            self._migrate_pool_tables()
            for name in ('members','projects','invites'): _private_directory(self.root/name)
        except Exception:
            self.ledger.close()
            self.upgrade_lease.close()
            raise

    def _migrate_pool_tables(self):
        if self.ledger.db.execute("SELECT 1 FROM sqlite_master WHERE name='team_pool_defaults'").fetchone():return
        with self.ledger.transaction():
            self.ledger.db.execute('CREATE TABLE team_pool_defaults (member TEXT,group_id TEXT,ceiling INTEGER NOT NULL,PRIMARY KEY(member,group_id))')
            self.ledger.db.execute('CREATE TABLE team_pool_projects (project TEXT,group_id TEXT,ceiling INTEGER NOT NULL,PRIMARY KEY(project,group_id))')
            for m,a,b in self.ledger.db.execute('SELECT id,default_a,default_b FROM team_members'):
                for g,v in (('A',a),('B',b)):self.ledger.db.execute('INSERT INTO team_pool_defaults VALUES (?,?,?)',(m,g,v))
            for project,a,b in self.ledger.db.execute('SELECT id,ceiling_a,ceiling_b FROM team_projects'):
                for g,v in (('A',a),('B',b)):self.ledger.db.execute('INSERT INTO team_pool_projects VALUES (?,?,?)',(project,g,v))

    def _default(self,member,group):
        row=self.ledger.db.execute('SELECT ceiling FROM team_pool_defaults WHERE member=? AND group_id=?',(member,group)).fetchone()
        if not row:raise Denied('Member pool policy is missing.',code='team_state_invalid')
        return row[0]

    @classmethod
    def initialize(cls, root, organization, baseline_a=None, baseline_b=None, *, all_traffic=False, clock=time.time):
        lease=_upgrade_lease(Path(root).parent)
        descriptor=os.open(Path(root).parent/'session.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        session=os.fdopen(descriptor,'a+b')
        try:
            try:fcntl.flock(session,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Denied('Exit the local API session before initializing the organization coordinator. No second ledger was created.',code='team_stop_required') from None
            marker=Path(root).parent/'gateway-process.json'
            if marker.exists() or marker.is_symlink():raise Denied('Stop the local API gateway before initializing the coordinator. Its recorded usage must be included in the organization baseline.',code='team_stop_required')
            if (Path(root).parent/'upgrade-pending.json').exists():raise Denied('Complete or roll back the pending upgrade before initializing shared state.',code='upgrade_pending')
            return cls._initialize(root,organization,baseline_a,baseline_b,all_traffic=all_traffic,clock=clock)
        finally:session.close();lease.close()

    @classmethod
    def _initialize(cls, root, organization, baseline_a=None, baseline_b=None, *, all_traffic=False, clock=time.time):
        root = Path(root)
        if not all_traffic:
            raise Denied('Confirm that every caller in this organization will use this coordinator. Independent gateways cannot share the same pool safely.', code='organization_usage_unknown')
        if not isinstance(organization,str) or not re.fullmatch(r'org-[A-Za-z0-9_-]{4,100}',organization):
            raise Denied('Use the organization ID from API settings.',code='team_configuration_invalid')
        p=load_policy(root.parent) if (root.parent/'verification.json').exists() else legacy()
        ceilings=policy_limits(p)
        baseline = _limits(baseline_a,baseline_b,ceilings=ceilings)
        if root.exists(): raise Denied('A coordinator directory already exists. No ledger was reset.',code='team_already_initialized')
        _private_directory(root,create=True)
        for name in ('state','members','projects','invites'): _private_directory(root/name,create=True)
        atomic_json(root/'policy.json',p)
        ledger = Ledger(root/'state',initialize=True,clock=clock)
        try:
            day = dt.datetime.fromtimestamp(clock(),dt.timezone.utc).strftime('%Y-%m-%d')
            with ledger.transaction():
                schema='''
                    CREATE TABLE team_config (coordinator TEXT NOT NULL, organization TEXT NOT NULL, revision INTEGER NOT NULL);
                    CREATE TABLE team_members (id TEXT PRIMARY KEY, project TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, active INTEGER NOT NULL,
                        default_a INTEGER NOT NULL, default_b INTEGER NOT NULL);
                    CREATE TABLE team_projects (id TEXT PRIMARY KEY, ceiling_a INTEGER NOT NULL, ceiling_b INTEGER NOT NULL);
                    CREATE TABLE team_allocations (period TEXT NOT NULL, member TEXT NOT NULL, group_id TEXT NOT NULL, ceiling INTEGER NOT NULL,
                        PRIMARY KEY(period,member,group_id));
                    CREATE TABLE team_requests (id TEXT PRIMARY KEY, member TEXT NOT NULL, project TEXT NOT NULL);
                    CREATE TABLE team_actions (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, outcome TEXT NOT NULL);
                    CREATE TABLE team_notices (period TEXT NOT NULL, member TEXT NOT NULL, group_id TEXT NOT NULL,
                        PRIMARY KEY(period,member,group_id));
                    CREATE TABLE team_extra_requests (id TEXT PRIMARY KEY, member TEXT NOT NULL, period TEXT NOT NULL, group_id TEXT NOT NULL,
                        amount INTEGER NOT NULL, state TEXT NOT NULL);
                    CREATE TABLE team_tunnel_keys (member TEXT NOT NULL, fingerprint TEXT PRIMARY KEY, public_key TEXT NOT NULL);
                '''
                for statement in schema.split(';'):
                    if statement.strip():ledger.db.execute(statement)
                ledger.db.execute('INSERT INTO team_config VALUES (?,?,0)',(uuid.uuid4().hex,organization))
                for group in ceilings:
                    ledger.db.execute('INSERT INTO budgets VALUES (?,?,?,?)',('openai:'+group,day,ceilings[group],baseline[group]))
                ledger.db.execute('UPDATE meta SET paused=0')
        finally: ledger.close()
        return cls(root,clock=clock)

    def close(self):
        self.ledger.close();self.upgrade_lease.close()

    def _mutable(self):
        if (self.root.parent/'upgrade-pending.json').exists():
            raise Denied('A harness upgrade needs completion or rollback before shared state can change.',code='upgrade_pending')

    def day(self):
        return self.ledger.check_clock().strftime('%Y-%m-%d')

    def _member(self, member, *, active=True):
        row = self.ledger.db.execute('SELECT project,token_hash,active,default_a,default_b FROM team_members WHERE id=?',(member,)).fetchone()
        if not row or (active and not row[2]):
            raise Denied('This team member is unknown or revoked. Ask the coordinator owner.',code='team_member_revoked',status=403)
        return row

    def authenticate(self, authorization):
        if not isinstance(authorization,str) or not authorization.startswith('Bearer '):
            raise Denied('A team member credential is required.',code='team_auth_failed',status=401)
        token=authorization[7:]
        if len(token)<48 or len(token)>256:
            raise Denied('The team member credential is invalid.',code='team_auth_failed',status=401)
        digest=hashlib.sha256(token.encode()).hexdigest()
        with self.mutex:
            row=self.ledger.db.execute('SELECT id,token_hash FROM team_members WHERE active=1 AND token_hash=?',(digest,)).fetchone()
            if not row or not hmac.compare_digest(row[1],digest):
                raise Denied('The team member credential is invalid or revoked.',code='team_auth_failed',status=401)
            return row[0]

    def _ensure_day(self, day):
        """Call inside the one witnessed write transaction; defaults never add twice."""
        for group in self.limits:
            row=self.ledger.db.execute('SELECT ceiling FROM budgets WHERE scope=? AND period=?',('openai:'+group,day)).fetchone()
            if row is None:self.ledger.db.execute('INSERT INTO budgets VALUES (?,?,?,0)',('openai:'+group,day,self.limits[group]))
            elif row[0]!=self.limits[group]:raise Denied('The organization budget differs from its safety policy.',code='team_state_invalid')
        for member,group,amount in self.ledger.db.execute('SELECT member,group_id,ceiling FROM team_pool_defaults'):
            if group in self.limits:
                self.ledger.db.execute('INSERT OR IGNORE INTO team_allocations VALUES (?,?,?,?)',(day,member,group,amount))

    def _used(self, column, identity, group, day):
        if column not in ('member','project'):raise AssertionError(column)
        scope='openai:'+group
        rows=self.ledger.db.execute('SELECT r.period,r.reserved,r.actual,r.phase FROM requests r JOIN team_requests t ON r.id=t.id WHERE t.'+column+'=? AND r.scope=?',(identity,scope)).fetchall()
        used=sum((actual if phase=='settled' else reserved) for period,reserved,actual,phase in rows if period==day)
        used+=sum(reserved for period,reserved,actual,phase in rows if period!=day and phase in ('reserved','unknown'))
        used+=self.ledger.db.execute('SELECT COALESCE(SUM(c.amount),0) FROM carryovers c JOIN team_requests t ON c.request_id=t.id WHERE t.'+column+'=? AND c.scope=? AND c.period=?',(identity,scope,day)).fetchone()[0]
        return used

    def _allocation(self, member, group, day):
        row=self.ledger.db.execute('SELECT ceiling FROM team_allocations WHERE period=? AND member=? AND group_id=?',(day,member,group)).fetchone()
        if row:return row[0]
        info=self._member(member,active=False)
        return self._default(member,group)

    def _pool(self, member, group, day):
        info=self._member(member)
        project=info[0]
        global_info=pool_info(self.ledger.db,group,self.limits[group],day)
        ceiling=self._allocation(member,group,day)
        used=self._used('member',member,group,day)
        project_ceiling=self.ledger.db.execute('SELECT ceiling FROM team_pool_projects WHERE project=? AND group_id=?',(project,group)).fetchone()[0]
        project_used=self._used('project',project,group,day)
        return {'group':group,'period':day,'limit':ceiling,'used_or_reserved':used,'baseline':0,
                'remaining':max(0,min(ceiling-used,global_info['remaining'],project_ceiling-project_used)),
                'organization_remaining':global_info['remaining'],'project_remaining':max(0,project_ceiling-project_used)}

    def quota(self, member):
        with self.mutex:
            day=self.day()
            if json.loads((self.ledger.root/'ledger-witness.json').read_text())!=self.ledger._head():
                raise Denied('The shared ledger cannot be verified. No quota was reset.',code='quota_reconciliation_required')
            pools={group:self._pool(member,group,day) for group in self.limits}
            return {'period':day,'coordinator_id':self.coordinator_id,'member_id':member,
                    'observed_at':dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc).isoformat(),
                    'reset_at':(dt.datetime.strptime(day,'%Y-%m-%d').replace(tzinfo=dt.timezone.utc)+dt.timedelta(days=1)).isoformat(),
                    'policy_digest':policy_digest(self.policy),'project_id':self._member(member)[0],'daily_pools':pools,'quota_guard':True,
                    'ledger_paused':bool(self.ledger.db.execute('SELECT paused FROM meta').fetchone()[0]),
                    'safety_stop':(self.ledger.root/'safety-stop.json').exists(),
                    'recorded_requests':self.ledger.db.execute('SELECT COUNT(*) FROM requests r JOIN team_requests t ON r.id=t.id WHERE t.member=?',(member,)).fetchone()[0],
                    'unresolved_requests':self.ledger.db.execute("SELECT COUNT(*) FROM requests r JOIN team_requests t ON r.id=t.id WHERE t.member=? AND r.phase IN ('reserved','unknown')",(member,)).fetchone()[0],
                    'usage_lines':usage_lines(self.policy,pools)}

    def notices(self, member):
        with self.mutex:
            day=self.day();pending=[]
            with self.ledger.transaction():
                for group in self.limits:
                    pool=self._pool(member,group,day)
                    if pool['limit']==0 or pool['used_or_reserved']*100<pool['limit']*self.policy['warning_percent']:continue
                    if self.ledger.db.execute('SELECT 1 FROM team_notices WHERE period=? AND member=? AND group_id=?',(day,member,group)).fetchone():continue
                    self.ledger.db.execute('INSERT INTO team_notices VALUES (?,?,?)',(day,member,group))
                    pending.append({'group':group,'period':day,'threshold':self.policy['warning_percent'],'remaining':pool['remaining'],
                        'message':f"API quota warning - Group {group}: {self.policy['warning_percent']}%+ used or reserved; {pool['remaining']:,} tokens left. Ask the team owner for an allocation change, or wait until 00:00 UTC."})
            return pending

    def _action(self, operation, payload, apply):
        self._mutable()
        if not isinstance(operation,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,120}',operation):
            raise Denied('Invalid administrative operation ID.',code='team_operation_invalid')
        digest=hashlib.sha256(canonical(payload)).hexdigest()
        with self.mutex, self.ledger.transaction():
            old=self.ledger.db.execute('SELECT fingerprint,outcome FROM team_actions WHERE id=?',(operation,)).fetchone()
            if old:
                if old[0]!=digest:raise Denied('The operation ID was already used with different changes.',code='team_operation_conflict',status=409)
                return json.loads(old[1])|{'replayed':True}
            day=self.day();self._ensure_day(day)
            outcome=apply(day)
            self.ledger.db.execute('UPDATE team_config SET revision=revision+1')
            revision=self.ledger.db.execute('SELECT revision FROM team_config').fetchone()[0]
            outcome.update(operation_id=operation,revision=revision,replayed=False,
                changed_at=dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc).isoformat())
            self.ledger.db.execute('INSERT INTO team_actions VALUES (?,?,?)',(operation,digest,canonical(outcome).decode()))
            return outcome

    def add_member(self, member, project, a=None, b=None):
        self._mutable()
        _identifier(member);_identifier(project,'project');limits=_limits(a,b,ceilings=self.limits)
        directory=self.root/'members'/member
        if directory.exists() or (self.root/'invites'/(member+'.json')).exists():
            raise Denied('Member files already exist; no credential was overwritten.',code='team_member_exists')
        token=secrets.token_urlsafe(48)
        with self.mutex:
            if self.ledger.db.execute('SELECT 1 FROM team_members WHERE id=?',(member,)).fetchone():raise Denied('The member already exists.',code='team_member_exists')
            totals=[self.ledger.db.execute('SELECT COALESCE(SUM(ceiling),0) FROM team_pool_defaults WHERE group_id=?',(g,)).fetchone()[0] for g in self.limits]
            if any(totals[i]+limits[g]>self.limits[g] for i,g in enumerate(self.limits)):
                raise Denied('Default allocations would exceed the organization safety pool.',code='team_allocation_invalid')
            day=self.day()
            current=[sum(self._allocation(m,g,day) for (m,) in self.ledger.db.execute('SELECT id FROM team_members')) for g in self.limits]
            if any(current[i]+limits[g]>self.limits[g] for i,g in enumerate(self.limits)):
                raise Denied('Today\'s existing allocations leave insufficient capacity for this member.',code='team_allocation_invalid')
            _private_directory(directory,create=True)
            project_directory=_private_directory(self.root/'projects'/project,create=True)
            key_path=project_directory/'openai-key.env'
            if key_path.exists() or key_path.is_symlink():
                info=key_path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
                    raise Denied('The existing project key file is unsafe.',code='team_state_unsafe')
            else:
                descriptor=os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(descriptor,'w') as out:out.write('# Fill locally. Never share the OpenAI key with a member.\nOPENAI_API_KEY=\n')
            atomic_json(directory/'verification.json',{'openai':{'enabled':True,'verified':False,'billing_policy':'free_only',
                'organization_id':self.organization_id,'project_id':project,'quota_guard':True,'org_exclusive':True,
                'policy':self.policy,
                'count_endpoint_free_confirmed':False,'local_tool_inference_free_confirmed':False}})
            # Insert only after all private inputs exist. An interrupted setup fails
            # visibly and never replaces files or grants an unnamed member access.
            with self.ledger.transaction():
                day=self.day();self._ensure_day(day)
                current=[self.ledger.db.execute('SELECT COALESCE(SUM(ceiling),0) FROM team_allocations WHERE period=? AND group_id=?',(day,g)).fetchone()[0] for g in self.limits]
                if any(current[i]+limits[g]>self.limits[g] for i,g in enumerate(self.limits)):raise Denied('Today\'s existing allocations leave insufficient capacity for this member.',code='team_allocation_invalid')
                self.ledger.db.execute('INSERT OR IGNORE INTO team_projects VALUES (?,?,?)',(project,self.limits.get('A',0),self.limits.get('B',0)))
                for g,n in self.limits.items():self.ledger.db.execute('INSERT OR IGNORE INTO team_pool_projects VALUES (?,?,?)',(project,g,n))
                self.ledger.db.execute('INSERT INTO team_members VALUES (?,?,?,1,?,?)',(member,project,hashlib.sha256(token.encode()).hexdigest(),limits.get('A',0),limits.get('B',0)))
                for g in self.limits:
                    self.ledger.db.execute('INSERT INTO team_pool_defaults VALUES (?,?,?)',(member,g,limits[g]))
                    self.ledger.db.execute('INSERT INTO team_allocations VALUES (?,?,?,?)',(day,member,g,limits[g]))
                self.ledger.db.execute('UPDATE team_config SET revision=revision+1')
            self._write_invite(member,token)
        return {'member_id':member,'project_id':project,'key_file':str(key_path),'invite_file':str(self.root/'invites'/(member+'.json')),'billing_policy':'free_only'}

    def transfer(self, donor, recipient, a=None, b=None, *, operation, revision=None):
        _identifier(donor);_identifier(recipient);amounts=_limits(a,b,ceilings=self.limits)
        if donor==recipient or not any(amounts.values()):raise Denied('Choose distinct members and a positive transfer.',code='team_allocation_invalid')
        def apply(day):
            self._member(donor,active=False);self._member(recipient)
            current=self.ledger.db.execute('SELECT revision FROM team_config').fetchone()[0]
            if revision is not None and revision!=current:raise Denied('Allocations changed; review the current values before retrying.',code='team_revision_conflict',status=409)
            for g in self.limits:
                donor_limit=self._allocation(donor,g,day)
                if donor_limit-amounts[g]<self._used('member',donor,g,day):
                    raise Denied('The donor has already used or reserved these tokens. No allocation was changed.',code='team_transfer_unavailable',status=409)
                recipient_limit=self._allocation(recipient,g,day)
                self.ledger.db.execute('UPDATE team_allocations SET ceiling=? WHERE period=? AND member=? AND group_id=?',(donor_limit-amounts[g],day,donor,g))
                self.ledger.db.execute('UPDATE team_allocations SET ceiling=? WHERE period=? AND member=? AND group_id=?',(recipient_limit+amounts[g],day,recipient,g))
            return {'period':day,'from':donor,'to':recipient,'tokens':amounts,
                'expires_at':(dt.datetime.strptime(day,'%Y-%m-%d')+dt.timedelta(days=1)).strftime('%Y-%m-%dT00:00:00Z')}
        return self._action(operation,{'kind':'transfer','from':donor,'to':recipient,'tokens':amounts,'revision':revision},apply)

    def defaults(self, member, a=None, b=None, *, operation):
        _identifier(member);limits=_limits(a,b,ceilings=self.limits)
        def apply(day):
            self._member(member,active=False)
            totals=[self.ledger.db.execute('SELECT COALESCE(SUM(ceiling),0) FROM team_pool_defaults WHERE member!=? AND group_id=?',(member,g)).fetchone()[0] for g in self.limits]
            if any(totals[i]+limits[g]>self.limits[g] for i,g in enumerate(self.limits)):raise Denied('Default allocations would exceed the safety pool.',code='team_allocation_invalid')
            for g,n in limits.items():self.ledger.db.execute('UPDATE team_pool_defaults SET ceiling=? WHERE member=? AND group_id=?',(n,member,g))
            self.ledger.db.execute('UPDATE team_members SET default_a=?,default_b=? WHERE id=?',(limits.get('A',0),limits.get('B',0),member))
            return {'member_id':member,'defaults':limits,'effective':'next UTC day; today is unchanged'}
        return self._action(operation,{'kind':'defaults','member':member,'tokens':limits},apply)

    def project_limits(self, project, a=None, b=None, *, operation):
        _identifier(project,'project');limits=_limits(a,b,ceilings=self.limits)
        def apply(day):
            if not self.ledger.db.execute('SELECT 1 FROM team_projects WHERE id=?',(project,)).fetchone():raise Denied('Unknown project.',code='team_project_unknown')
            if any(limits[g]<self._used('project',project,g,day) for g in self.limits):raise Denied('The project already used or reserved more than this limit.',code='team_transfer_unavailable',status=409)
            for g,n in limits.items():self.ledger.db.execute('UPDATE team_pool_projects SET ceiling=? WHERE project=? AND group_id=?',(n,project,g))
            self.ledger.db.execute('UPDATE team_projects SET ceiling_a=?,ceiling_b=? WHERE id=?',(limits.get('A',0),limits.get('B',0),project))
            return {'project_id':project,'limits':limits,'effective':'immediate and subsequent UTC days'}
        return self._action(operation,{'kind':'project_limits','project':project,'tokens':limits},apply)

    def revoke(self, member):
        self._mutable()
        _identifier(member)
        with self.mutex,self.ledger.transaction():
            self._member(member,active=False)
            self.ledger.db.execute('UPDATE team_members SET active=0 WHERE id=?',(member,))
            self.ledger.db.execute('UPDATE team_config SET revision=revision+1')
        if (self.root/'ssh').exists():
            from team_ssh import render_authorized_keys
            render_authorized_keys(self)
        return {'member_id':member,'revoked':True,'usage_preserved':True}

    def rotate(self, member):
        self._mutable()
        _identifier(member);token=secrets.token_urlsafe(48)
        with self.mutex:
            self._member(member)
            with self.ledger.transaction():self.ledger.db.execute('UPDATE team_members SET token_hash=? WHERE id=?',(hashlib.sha256(token.encode()).hexdigest(),member))
            path=self.root/'invites'/(member+'.json')
            self._write_invite(member,token)
        return {'member_id':member,'invite_file':str(path),'old_credential_revoked':True}

    def billing(self, member, *, charges=False):
        self._mutable()
        _identifier(member)
        with self.mutex:
            self._member(member)
            path=self.root/'members'/member/'verification.json';data=_read_private(path)
            data['openai']['billing_policy']='metered' if charges else 'free_only'
            atomic_json(path,data)
        return {'member_id':member,'billing_policy':data['openai']['billing_policy'],'quota_guard':True}

    def request_more(self, member, payload):
        self._mutable()
        if not isinstance(payload,dict) or set(payload)!={'request_id','group','amount'}:raise Denied('Use request_id, group and amount.',code='team_request_invalid')
        identity=payload['request_id'];group=payload['group'];amount=payload['amount']
        if not isinstance(identity,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{16,80}',identity) or group not in self.limits or type(amount) is not int or not 0<amount<=self.limits[group]:raise Denied('Invalid quota request.',code='team_request_invalid')
        with self.mutex,self.ledger.transaction():
            self._member(member);day=self.day()
            row=self.ledger.db.execute('SELECT member,period,group_id,amount,state FROM team_extra_requests WHERE id=?',(identity,)).fetchone()
            if row:
                if row[:4]!=(member,day,group,amount):raise Denied('The quota request ID was already used.',code='team_operation_conflict',status=409)
                return {'request_id':identity,'state':row[4],'replayed':True}
            existing=self.ledger.db.execute("SELECT id,amount FROM team_extra_requests WHERE member=? AND period=? AND group_id=? AND state='pending'",(member,day,group)).fetchone()
            if existing:return {'request_id':existing[0],'state':'pending','amount':existing[1],'replayed':True}
            self.ledger.db.execute("INSERT INTO team_extra_requests VALUES (?,?,?,?,?,'pending')",(identity,member,day,group,amount))
        if self.request_notice:self.request_notice(member,group,amount,identity)
        return {'request_id':identity,'state':'pending','replayed':False}

    def _write_invite(self,member,token):
        from team_ssh import invite_metadata
        invite={'version':1,'coordinator_id':self.coordinator_id,'member_id':member,'endpoint':'http://127.0.0.1:'+str(DEFAULT_PORT),'token':token,'policy':self.policy,'policy_digest':policy_digest(self.policy)}
        ssh=invite_metadata(self.root)
        if ssh:
            invite['ssh']=ssh;invite['endpoint']='http://127.0.0.1:'+str(ssh['remote_port'])
        atomic_json(self.root/'invites'/(member+'.json'),invite)

    def share(self,listen='127.0.0.1',ssh_port=49202,coordinator_port=DEFAULT_PORT):
        self._mutable()
        from team_ssh import configure
        with self.mutex:
            result=configure(self,listen=listen,ssh_port=ssh_port,coordinator_port=coordinator_port)
            for (member,) in self.ledger.db.execute('SELECT id FROM team_members WHERE active=1'):
                path=self.root/'invites'/(member+'.json');invite=_read_private(path)
                self._write_invite(member,invite['token'])
        return result

    def tunnel_key(self,member,public_key_file):
        self._mutable()
        from team_ssh import register_key
        result=register_key(self,member,public_key_file)
        result['invite_file']=str(self.root/'invites'/(member+'.json'))
        return result

    def approve(self, request_id, donor):
        with self.mutex:
            row=self.ledger.db.execute('SELECT member,period,group_id,amount,state FROM team_extra_requests WHERE id=?',(request_id,)).fetchone()
            if not row:raise Denied('Unknown quota request.',code='team_request_unknown')
            member,day,group,amount,state=row
            # The transfer and request state must commit in the same transaction.
            operation='approve:'+request_id
            def apply(today):
                if day!=today:raise Denied('This quota request expired at the UTC reset.',code='team_request_expired')
                self._member(member);self._member(donor,active=False)
                if member==donor:raise Denied('A quota request needs a different donor.',code='team_allocation_invalid')
                limit=self._allocation(donor,group,today)
                if limit-amount<self._used('member',donor,group,today):raise Denied('The donor lacks unused, unreserved capacity.',code='team_transfer_unavailable',status=409)
                self.ledger.db.execute('UPDATE team_allocations SET ceiling=ceiling-? WHERE period=? AND member=? AND group_id=?',(amount,today,donor,group))
                self.ledger.db.execute('UPDATE team_allocations SET ceiling=ceiling+? WHERE period=? AND member=? AND group_id=?',(amount,today,member,group))
                self.ledger.db.execute("UPDATE team_extra_requests SET state='approved' WHERE id=?",(request_id,))
                return {'request_id':request_id,'from':donor,'to':member,'group':group,'tokens':amount,'period':today}
            return self._action(operation,{'kind':'approve','request':request_id,'donor':donor},apply)

    def status(self):
        with self.mutex:
            day=self.day()
            return {'coordinator_id':self.coordinator_id,'organization_id':self.organization_id,'period':day,
                'revision':self.ledger.db.execute('SELECT revision FROM team_config').fetchone()[0],
                'organization_pools':{g:pool_info(self.ledger.db,g,self.limits[g],day) for g in self.limits},
                'members':[{'member_id':m,'project_id':p,'active':bool(active),'defaults':{g:self._default(m,g) for g in self.limits},
                    'today':{g:{'limit':self._allocation(m,g,day),'used_or_reserved':self._used('member',m,g,day)} for g in self.limits}}
                    for m,p,active,a,b in self.ledger.db.execute('SELECT id,project,active,default_a,default_b FROM team_members ORDER BY id')],
                'requests':[dict(zip(('request_id','member_id','period','group','amount','state'),r)) for r in self.ledger.db.execute('SELECT * FROM team_extra_requests ORDER BY period,id')]}

    def reconcile(self, template=None, apply=None):
        """Owner-only triage; applying evidence requires a stopped coordinator."""
        if template is not None and apply is not None:raise Denied('Choose either a review template or an apply operation.')
        with self.mutex:
            self.day()
            if json.loads((self.ledger.root/'ledger-witness.json').read_text())!=self.ledger._head():
                raise Denied('The shared ledger does not verify; no automatic repair is available.',code='quota_reconciliation_required')
            if apply is not None:
                self._mutable()
                if self.running:raise Denied('Stop the coordinator before applying a reconciliation receipt. Inspection and templates remain available while running.',code='team_stop_required')
                path=Path(apply);directory=_private_directory(self.root/'reconciliation')
                if path.parent.resolve()!=directory.resolve():raise Denied('Use a review file from the private team reconciliation directory.')
                plan=_read_private(path)
                if not isinstance(plan,dict) or not self.ledger.db.execute('SELECT 1 FROM team_requests WHERE id=?',(plan.get('request_id'),)).fetchone():
                    raise Denied('The receipt does not identify a team request.')
                return self.ledger.reconcile(plan)
            rows=self.ledger.db.execute("SELECT r.id,t.member,t.project,r.scope,r.period,r.reserved,r.phase FROM requests r JOIN team_requests t ON r.id=t.id WHERE r.phase IN ('reserved','unknown','rejected') ORDER BY r.created").fetchall()
            if template is not None:
                self._mutable()
                matches=[row for row in rows if row[0]==template]
                if len(matches)!=1:raise Denied('No matching unconfirmed team request.')
                row=matches[0];directory=_private_directory(self.root/'reconciliation',create=True)
                plan={'version':1,'resolution_id':uuid.uuid4().hex,'request_id':row[0],'expected_phase':row[6],
                    'expected_reserved_tokens':row[5],'action':'record_actual','actual_tokens':None,
                    'evidence':{'kind':'operator_verified_provider_usage','reference':'REPLACE_WITH_VERIFIED_EVIDENCE_REFERENCE','request_finished':False}}
                path=directory/('review-'+plan['resolution_id']+'.json');atomic_json(path,plan)
                return {'review_file':str(path),'instruction':'Fill confirmed completed usage and evidence locally. Stop the coordinator before applying. Never put prompts or credentials in evidence.'}
            return {'read_only':True,'safety_stop':(self.ledger.root/'safety-stop.json').exists(),
                'requests':[dict(zip(('request_id','member_id','project_id','scope','period','reserved_tokens','phase'),row)) for row in rows]}


class MemberLedger:
    """Server-only adapter: request amounts and usage never come from a client."""
    def __init__(self, team, member, credential_hash=None):
        self.team,self.member,self.root=team,member,team.ledger.root
        self.credential_hash=credential_hash

    def active(self):
        member=self.team._member(self.member)
        if self.credential_hash is not None and not hmac.compare_digest(member[1],self.credential_hash):
            raise Denied('The member credential changed before dispatch. Pair again; no unsent request was dispatched.',code='team_auth_failed',status=401)
        return member

    def daily_remaining(self, group, ceiling):
        self.team._mutable()
        if group not in self.team.limits or ceiling!=self.team.limits[group]:raise Denied('Coordinator safety policy differs from its receipt.',code='team_state_invalid')
        with self.team.mutex:
            self.active()
            if (self.root/'safety-stop.json').exists():raise Denied('The coordinator needs usage reconciliation.',code='quota_reconciliation_required')
            return self.team._pool(self.member,group,self.team.day())

    def reserve_daily(self, group, ceiling, amount, payload):
        if type(amount) is not int or amount<=0:raise Denied('Invalid reservation.')
        with self.team.mutex,self.team.ledger.transaction():
            day=self.team.day();self.team._ensure_day(day)
            info=self.daily_remaining(group,ceiling)
            if self.team.ledger.db.execute('SELECT paused FROM meta').fetchone()[0]:raise Denied('The coordinator is paused.',code='gateway_stopped')
            if amount>info['remaining']:raise Denied(f"Group {group} needs up to {amount:,} tokens; {info['remaining']:,} remain in the member/project/organization allocation. Ask the team owner for more quota or wait until 00:00 UTC. No model request was sent.",code='daily_token_limit',status=429,details=info|{'required':amount})
            identity=uuid.uuid4().hex
            self.team.ledger.db.execute("INSERT INTO requests VALUES (?,?,?,?,?,NULL,'reserved',?)",(identity,'openai:'+group,day,hashlib.sha256(canonical(payload)).hexdigest(),amount,self.team.clock()))
            self.team.ledger.db.execute('INSERT INTO team_requests VALUES (?,?,?)',(identity,self.member,self.team._member(self.member)[0]))
            return identity

    def _owned(self, request_id):
        row=self.team.ledger.db.execute('SELECT member FROM team_requests WHERE id=?',(request_id,)).fetchone()
        if not row or row[0]!=self.member:raise Denied('The request belongs to another member.',code='team_request_forbidden')

    def dispatch_daily(self, request_id):
        self.team._mutable()
        with self.team.mutex,self.team.ledger.transaction():
            self._owned(request_id);self.active();day=self.team.day()
            if self.team.ledger.db.execute('SELECT paused FROM meta').fetchone()[0]:raise Denied('The coordinator is paused.',code='gateway_stopped')
            row=self.team.ledger.db.execute('SELECT period,phase FROM requests WHERE id=?',(request_id,)).fetchone()
            if row!=(day,'reserved'):raise Denied('The UTC date changed before dispatch; resend the request.',code='quota_day_changed')
            self.team.ledger.db.execute("UPDATE requests SET phase='unknown' WHERE id=?",(request_id,))

    def settle(self, request_id, actual):
        with self.team.mutex:self._owned(request_id);return self.team.ledger.settle(request_id,actual)

    def note_usage_conflict(self, request_id):
        with self.team.mutex:
            self._owned(request_id)
            return self.team.ledger.note_usage_conflict(request_id)

    def reject(self, request_id):
        with self.team.mutex:self._owned(request_id);return self.team.ledger.reject(request_id)

    def void_unsent(self, request_id):
        with self.team.mutex:self._owned(request_id);return self.team.ledger.void_unsent(request_id)

    def begin_operation(self, payload, operation_id=None, namespace='local'):
        self.team._mutable()
        with self.team.mutex:
            self.active()
            return self.team.ledger.begin_operation(payload,operation_id,namespace='member:'+self.member)

    def mark_operation(self, correlation_id, phase, request_id=None, provider_request_id=None):
        with self.team.mutex:
            row=self.team.ledger.db.execute('SELECT namespace FROM operations WHERE correlation_id=?',(correlation_id,)).fetchone()
            if row!=('member:'+self.member,):raise Denied('The operation belongs to another member.',code='team_request_forbidden')
            return self.team.ledger.mark_operation(correlation_id,phase,request_id,provider_request_id)


class MemberBroker(Broker):
    def __init__(self, team, member, transport=upstream, *, credential_hash=None):
        self.team,self.member=team,member
        super().__init__(team.root/'members'/member,MemberLedger(team,member,credential_hash),transport,clock=team.clock)
        self.key_path=team.root/'projects'/team._member(member)[0]/'openai-key.env'

    def policy(self,receipt=None):return self.team.policy

    def openai(self, payload, send_headers, send_chunk, cancelled=lambda:False, **options):
        return super().openai(payload,send_headers,send_chunk,
            cancelled=lambda:self.team.stopping.is_set() or cancelled(),**options)

    def receipt(self, provider):
        with self.team.mutex:
            member=self.ledger.active()
            if (self.team.root/'paused').exists():raise Denied('The coordinator is paused.',code='gateway_stopped')
            receipt=super().receipt(provider)
            if receipt.get('organization_id')!=self.team.organization_id or receipt.get('project_id')!=member[0] or receipt.get('quota_guard') is not True:
                raise Denied('Coordinator member account binding is invalid.',code='team_account_binding_invalid')
            return receipt


def make_server(root, port=DEFAULT_PORT, transport=upstream, *, clock=time.time):
    team=Team(root,clock=clock)
    try:team._mutable()
    except Exception:team.close();raise
    admissions={};broker_lock=threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def setup(self):
            super().setup();self.connection.settimeout(30)
        def log_message(self,*_):pass
        def reply(self,status,payload):
            body=canonical(payload);self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('Connection','close')
            self.end_headers();self.close_connection=True;self.wfile.write(body)
        def fail(self,error,started=False):
            body=public_error(error)
            if started or getattr(self,'expect_stream',False):
                if not started:
                    self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.end_headers()
                event={'type':'response.failed','response':{'id':'resp_team_error','status':'failed','error':{'code':'api_gateway_error','message':'['+body['code']+'] '+body['message']},'usage':None}}
                try:self.wfile.write(b'event: response.failed\ndata: '+canonical(event)+b'\n\n');self.wfile.flush()
                except OSError:pass
                self.close_connection=True
            else:self.reply(getattr(error,'status',503),{'error':body})
        def auth(self):
            for header in ('Host','Authorization','Content-Length','Transfer-Encoding','Content-Encoding','Idempotency-Key'):
                if len(self.headers.get_all(header,[]))>1:raise Denied('Duplicate coordinator request header: '+header+'.',code='team_headers_invalid')
            if self.headers.get('Host') not in {'127.0.0.1:'+str(server.server_port),'localhost:'+str(server.server_port)}:raise Denied('Unexpected coordinator Host header.',code='team_host_invalid')
            authorization=self.headers.get('Authorization')
            member=team.authenticate(authorization)
            self.member_token_hash=hashlib.sha256(authorization[7:].encode()).hexdigest()
            return member
        def do_GET(self):
            try:
                member=self.auth()
                if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding') or self.headers.get('Content-Length','0')!='0':
                    raise Denied('GET bodies and encoded requests are disabled.',code='team_headers_invalid')
                if self.path=='/identity':return self.reply(200,{'service':SERVICE,'version':1,'coordinator_id':team.coordinator_id,'member_id':member,'project_id':team._member(member)[0],'policy_digest':policy_digest(team.policy)})
                if self.path=='/v1/quota':return self.reply(200,team.quota(member))
                if self.path=='/v1/models':return self.reply(200,{'object':'list','data':[{'id':m,'object':'model'} for m in team.policy['models']]})
                raise Denied('Endpoint disabled')
            except Denied as error:self.fail(error)
            except Exception:self.fail(Denied('Shared state is unavailable. No quota was reset.',code='team_state_unavailable',status=503))
        def do_POST(self):
            started=False;acquired=False;admission=None;self.expect_stream=False
            try:
                member=self.auth()
                if self.path not in {'/v1/responses','/v1/notices/claim','/v1/quota/request'}:raise Denied('Endpoint disabled')
                if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding'):raise Denied('Encoded request denied')
                length=int(self.headers.get('Content-Length','-1'))
                if not 0<length<=4_000_000:raise Denied('Request size invalid')
                self.connection.settimeout(30);payload=decode_json(self.rfile.read(length))
                if self.path=='/v1/notices/claim':
                    if payload!={}:raise Denied('Unsupported notice request')
                    return self.reply(200,{'notices':team.notices(member)})
                if self.path=='/v1/quota/request':return self.reply(200,team.request_more(member,payload))
                self.expect_stream=isinstance(payload,dict) and payload.get('stream') is True
                operation=self.headers.get('Idempotency-Key')
                if not operation:raise Denied('The shared relay requires a request ID. Update the client; no provider request was sent.',code='team_operation_required')
                with broker_lock:
                    admission=admissions.setdefault(member,threading.Lock())
                acquired=admission.acquire(blocking=False)
                if not acquired:raise Denied('Another request is in flight; retry only after checking status')
                broker=MemberBroker(team,member,transport,credential_hash=self.member_token_hash)
                def headers(content_type):
                    nonlocal started
                    self.send_response(200);self.send_header('Content-Type',content_type);self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.end_headers();self.close_connection=True;started=True
                def chunk(body):self.wfile.write(body);self.wfile.flush()
                def cancelled():
                    try:
                        readable,_,_=select.select([self.connection],[],[],0)
                        return bool(readable) and self.connection.recv(1,socket.MSG_PEEK)==b''
                    except OSError:return True
                broker.openai(payload,headers,chunk,cancelled=cancelled,operation_id=operation,operation_namespace='member:'+member)
            except Denied as error:self.fail(error,started)
            except Exception:self.fail(Denied('The coordinator state or connection is unavailable. Dispatched reservations remain held; no automatic retry was made.',code='team_state_unavailable',status=503),started)
            finally:
                if acquired:admission.release()
        def do_CONNECT(self):self.reply(403,{'error':{'code':'endpoint_disabled','message':'Proxying is disabled.'}})
    class Server(ThreadingHTTPServer):
        slots=threading.BoundedSemaphore(32)
        def process_request(self,request,client_address):
            if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
            try:super().process_request(request,client_address)
            except BaseException:self.slots.release();raise
        def process_request_thread(self,request,client_address):
            try:super().process_request_thread(request,client_address)
            finally:self.slots.release()
    try:server=Server(('127.0.0.1',port),Handler)
    except Exception:team.close();raise
    server.daemon_threads=False;server.team=team;server.ledger=team.ledger
    team.running=True
    server.start_admin=lambda:_start_admin(server)
    def start_tunnel():
        from team_ssh import start
        server.tunnel=start(team,server.server_port)
        return server.tunnel
    server.start_tunnel=start_tunnel
    def close_shared():
        team.stopping.set()
        if getattr(server,'tunnel',None):server.tunnel.stop();server.tunnel=None
        if getattr(server,'admin',None):
            server.admin.shutdown();server.admin.server_close();server.admin_thread.join()
            path=team.root/'admin.sock'
            if path.exists():path.unlink()
            server.admin=None
        team.close()
    server.close_shared=close_shared
    return server


def _admin(team, payload):
    if not isinstance(payload,dict) or set(payload)!={'action','arguments'} or not isinstance(payload['arguments'],dict):raise Denied('Invalid owner command.')
    allowed={'status','add_member','transfer','defaults','project_limits','revoke','rotate','billing','approve','reconcile','share','tunnel_key'}
    action=payload['action']
    if action not in allowed:raise Denied('Unknown owner command.')
    return getattr(team,action)(**payload['arguments'])


def _start_admin(server):
    if getattr(server,'admin',None):return
    path=server.team.root/'admin.sock'
    if len(os.fsencode(path))>=104:raise Denied('The private coordinator directory is too long for its owner control socket. Use a shorter private installation path.',code='team_path_too_long')
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid():raise Denied('Unexpected owner control socket path.',code='team_state_unsafe')
        # The exclusive Ledger lease is held, so this socket cannot belong to a
        # live authoritative server using the same state.
        path.unlink()
    class AdminHandler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                raw=self.rfile.readline(16385)
                if len(raw)>16384 or not raw.endswith(b'\n'):raise Denied('Owner command is too large.')
                result={'result':_admin(server.team,decode_json(raw))}
            except Denied as error:result={'error':public_error(error),'status':error.status}
            except Exception:result={'error':{'message':'Owner command failed; no automatic repair was attempted.','code':'team_owner_command_failed'},'status':503}
            self.wfile.write(canonical(result)+b'\n')
    admin=socketserver.ThreadingUnixStreamServer(str(path),AdminHandler)
    os.chmod(path,0o600);admin.daemon_threads=False
    server.admin=admin;server.admin_thread=threading.Thread(target=admin.serve_forever,name='team-owner-control');server.admin_thread.start()


def _owner_call(root, action, arguments):
    root=_private_directory(root);path=root/'admin.sock'
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:raise Denied('Unsafe owner control socket.',code='team_state_unsafe')
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(5)
        try:
            try:client.connect(str(path))
            except (ConnectionRefusedError,FileNotFoundError):pass
            else:
                client.sendall(canonical({'action':action,'arguments':arguments})+b'\n')
                with client.makefile('rb') as source:raw=source.readline(1_000_001)
                if len(raw)>1_000_000:raise Denied('Owner response exceeds its limit.')
                response=decode_json(raw)
                if 'error' in response:raise Denied(response['error']['message'],code=response['error'].get('code'),status=response.get('status',403))
                return response['result']
        finally:client.close()
    team=Team(root)
    try:return _admin(team,{'action':action,'arguments':arguments})
    finally:team.close()


def command(root, args):
    parser=argparse.ArgumentParser(prog='codex-api team')
    sub=parser.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--organization',required=True);init.add_argument('--baseline-a',type=int);init.add_argument('--baseline-b',type=int);init.add_argument('--baseline',action='append',default=[]);init.add_argument('--all-traffic-coordinated',action='store_true')
    serve=sub.add_parser('serve');serve.add_argument('--port',type=int,default=DEFAULT_PORT)
    share=sub.add_parser('share');share.add_argument('--listen',default='127.0.0.1');share.add_argument('--ssh-port',type=int,default=49202);share.add_argument('--coordinator-port',type=int,default=DEFAULT_PORT)
    sub.add_parser('status');sub.add_parser('allocations');sub.add_parser('requests')
    member=sub.add_parser('member').add_subparsers(dest='member_action',required=True)
    add=member.add_parser('add');add.add_argument('member');add.add_argument('--project',required=True);add.add_argument('--a',type=int,default=0);add.add_argument('--b',type=int,default=0)
    for action in ('revoke','rotate'):
        item=member.add_parser(action);item.add_argument('member')
    billing=member.add_parser('billing');billing.add_argument('member');choice=billing.add_mutually_exclusive_group(required=True);choice.add_argument('--allow-api-charges',action='store_true');choice.add_argument('--free-only',action='store_true')
    tunnel_key=member.add_parser('tunnel-key');tunnel_key.add_argument('member');tunnel_key.add_argument('--public-key',dest='public_key_file',required=True)
    transfer=sub.add_parser('transfer');transfer.add_argument('--from',dest='donor',required=True);transfer.add_argument('--to',dest='recipient',required=True);transfer.add_argument('--a',type=int,default=0);transfer.add_argument('--b',type=int,default=0);transfer.add_argument('--operation',default=None);transfer.add_argument('--revision',type=int)
    defaults=sub.add_parser('defaults');defaults.add_argument('member');defaults.add_argument('--a',type=int);defaults.add_argument('--b',type=int);defaults.add_argument('--operation')
    project=sub.add_parser('project-limit');project.add_argument('project');project.add_argument('--a',type=int);project.add_argument('--b',type=int);project.add_argument('--operation')
    approve=sub.add_parser('approve');approve.add_argument('request_id');approve.add_argument('--from',dest='donor',required=True)
    reconcile=sub.add_parser('reconcile');review=reconcile.add_mutually_exclusive_group();review.add_argument('--template');review.add_argument('--apply')
    for item in (add,transfer,defaults,project):item.add_argument('--tokens',action='append',default=[])
    parsed=parser.parse_args(args);team_root=Path(root)/'team'
    if parsed.command=='init':
        if parsed.baseline and (parsed.baseline_a is not None or parsed.baseline_b is not None):raise Denied('Use named --baseline or legacy --baseline-a/--baseline-b, not both. No coordinator was created.',code='policy_invalid')
        from configuration import baselines
        p=load_policy(root)
        prior=baselines(parsed.baseline,p) if parsed.baseline else parsed.baseline_a
        team=Team.initialize(team_root,parsed.organization,prior,None if parsed.baseline else parsed.baseline_b,all_traffic=parsed.all_traffic_coordinated)
        try:result={'coordinator_id':team.coordinator_id,'state':'initialized','daily_token_limits':team.limits,'safety_margin_percent':team.policy['safety_margin_percent']}
        finally:team.close()
    elif parsed.command=='serve':
        if not 1024<=parsed.port<=65535:raise Denied('Choose a coordinator port from 1024 to 65535.')
        server=make_server(team_root,port=parsed.port)
        try:
            server.start_admin()
            server.start_tunnel()
            server.team.request_notice=lambda member,group,amount,identity:print(f'Quota request - {member}, Group {group}, {amount:,} tokens. Review: codex-api team requests. Request ID: {identity}',flush=True)
            print('Coordinator listening on 127.0.0.1:'+str(server.server_port)+'. Remote members need an encrypted tunnel. Press Ctrl+C to stop.')
            try:server.serve_forever(poll_interval=.2)
            except KeyboardInterrupt:pass
        finally:
            server.team.stopping.set()
            server.server_close();server.close_shared()
        return
    else:
        values=vars(parsed).copy();action=values.pop('command')
        if action in ('status','allocations','requests'):
            result=_owner_call(team_root,'status',{})
            if action=='allocations':result={k:result[k] for k in ('period','revision','members')}
            elif action=='requests':result={'requests':result['requests']}
        else:
            if action=='member':
                action=values.pop('member_action')
                if action=='add':action='add_member'
                elif action=='billing':values={'member':values['member'],'charges':values['allow_api_charges']}
                elif action=='tunnel-key':action='tunnel_key'
            elif action=='project-limit':action='project_limits'
            tokens=values.pop('tokens',[])
            if tokens:
                from configuration import baselines
                if values.get('a') not in (None,0) or values.get('b') not in (None,0):raise Denied('Use named --tokens or legacy A/B flags, not both.')
                values['a']=baselines(tokens,load_policy(root),flag='--tokens');values['b']=None
            if action in ('transfer','defaults','project_limits') and not values.get('operation'):values['operation']=uuid.uuid4().hex
            result=_owner_call(team_root,action,values)
    print(json.dumps(result,indent=2))
    if parsed.command=='member' and parsed.member_action=='add':
        print('Fill the private key file locally; never put an OpenAI key in the invite or chat. Share only the invite through an encrypted channel. Free-only requests remain blocked until eligibility is verified.')
    return result
