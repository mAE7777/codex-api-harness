"""Fail-closed request policy and durable, single-process quota reservations."""
from __future__ import annotations
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid

from policy import LEGACY_MODELS as MODELS, LEGACY_LIMITS as DAILY_LIMITS, LEGACY_LABELS as POOL_LABELS, MAX_TOKENS, MAX_POOLS
REQUEST_DEADLINE_SECONDS = 600
UTC_NEW_DAY_GUARD_SECONDS = 15
UTC_OVERLAP_SECONDS = REQUEST_DEADLINE_SECONDS + UTC_NEW_DAY_GUARD_SECONDS
LOCAL_FUNCTIONS = {"exec_command", "write_stdin", "shell", "shell_command",
                   "update_plan", "request_user_input", "request_user_input_async", "view_image", "wait", "sleep"}
LOCAL_CUSTOM = {"apply_patch", "exec"}
HARNESS_TOOLS = {'status','fetch','search','extract','files_search'}
HARNESS_FUNCTIONS = {'mcp__harness__'+name for name in HARNESS_TOOLS}
ROOT_FIELDS = {"model", "input", "instructions", "tools", "tool_choice",
               "parallel_tool_calls", "reasoning", "text", "include", "store",
               "stream", "service_tier", "max_output_tokens", "temperature",
               "top_p", "truncation", "prompt_cache_key", "metadata", "client_metadata"}


class Denied(Exception):
    def __init__(self, message, *, code=None, status=403, details=None):
        super().__init__(message)
        self.code, self.status, self.details = code, status, details or {}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def utc_admission(now, *, counted=False):
    """Briefly avoid a provider whose UTC day could still be the previous day."""
    instant=dt.datetime.fromtimestamp(now,dt.timezone.utc)
    midnight=instant.replace(hour=0,minute=0,second=0,microsecond=0)
    elapsed=(instant-midnight).total_seconds()
    if elapsed<UTC_NEW_DAY_GUARD_SECONDS:
        retry=math.ceil(UTC_NEW_DAY_GUARD_SECONDS-elapsed)
        tail='Token counting may already have occurred.' if counted else 'No token-counting request was sent in this attempt.'
        raise Denied('UTC daily quota transition: requests resume at 00:00:15 UTC. No model request was sent. '+tail+' Retry manually after '+str(retry)+' seconds.',code='utc_day_transition',status=429,details={'retry_after_seconds':retry,'resume_at':(midnight+dt.timedelta(seconds=UTC_NEW_DAY_GUARD_SECONDS)).isoformat()})


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(canonical(value)); out.flush(); os.fsync(out.fileno())
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if temp.exists(): temp.unlink()


def valid_limits(limits):
    return isinstance(limits,dict) and 1<=len(limits)<=MAX_POOLS and all(isinstance(g,str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,15}',g) and g!='metered' and type(v) is int and 0<v<=MAX_TOKENS for g,v in limits.items())


def pool_info(db, group, ceiling, day):
    """Shared accounting formula for admission and read-only quota views."""
    scope = 'openai:' + group
    row = db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?', (scope, day)).fetchone()
    if row and row[0] != ceiling:
        raise Denied('The daily limit differs from the ledger; run codex-api doctor.', code='quota_settings_changed')
    baseline = row[1] if row else db.execute("SELECT COALESCE(SUM(actual),0) FROM requests WHERE scope='openai:metered' AND period=?", (day,)).fetchone()[0]
    spent = db.execute("SELECT COALESCE(SUM(CASE WHEN phase='settled' THEN actual ELSE reserved END),0) FROM requests WHERE scope=? AND period=?", (scope, day)).fetchone()[0]
    carry = db.execute("SELECT COALESCE(SUM(reserved),0) FROM requests WHERE scope=? AND period!=? AND phase IN ('reserved','unknown')", (scope, day)).fetchone()[0]
    has_carry = db.execute("SELECT 1 FROM sqlite_master WHERE name='carryovers'").fetchone()
    if has_carry: carry += db.execute('SELECT COALESCE(SUM(amount),0) FROM carryovers WHERE scope=? AND period=?', (scope, day)).fetchone()[0]
    return {'group':group, 'period':day, 'limit':ceiling, 'baseline':baseline,
            'used_or_reserved':spent+carry, 'remaining':max(0, ceiling-baseline-spent-carry)}


@contextlib.contextmanager
def readonly_database(root):
    """Avoid SQLite sidecar creation when stopped, without ignoring a live WAL."""
    root = Path(root)
    lease = os.open(root/'process.lock', os.O_RDONLY | os.O_NOFOLLOW)
    locked = False
    db = None
    try:
        try:
            fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError: pass
        wal = root/'usage.sqlite3-wal'
        # The shared process lease prevents a writer from appearing while an
        # immutable read is open. Never use immutable against an existing WAL.
        immutable = locked and (not wal.exists() or wal.stat().st_size == 0)
        uri = 'file:'+str(root/'usage.sqlite3')+'?mode=ro'+('&immutable=1' if immutable else '')
        db = sqlite3.connect(uri, uri=True, isolation_level=None)
        db.execute('PRAGMA query_only=ON')
        yield db
    finally:
        if db is not None: db.close()
        os.close(lease)


def read_quota(root, limits, *, now=None, policy=None):
    """One consistent, witnessed read transaction. Never reserves or repairs usage."""
    root = Path(root)
    from policy import limits as policy_limits
    if not valid_limits(limits) or policy is not None and limits!=policy_limits(policy):
        raise Denied('Daily quota settings are unavailable; run codex-api doctor.', code='quota_settings_changed')
    if (root/'usage.sqlite3').is_symlink() or (root/'ledger-witness.json').is_symlink() or not (root/'usage.sqlite3').is_file():
        raise Denied('Usage ledger is missing; run codex-api doctor.', code='quota_state_unavailable')
    now = time.time() if now is None else now
    day = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime('%Y-%m-%d')
    for attempt in range(4):
        try:
            with readonly_database(root) as db:
                db.execute('BEGIN')
                identity, sequence, paused = db.execute('SELECT * FROM meta').fetchone()
                witness = json.loads((root/'ledger-witness.json').read_text())
                if witness != {'identity':identity, 'sequence':sequence}:
                    if attempt < 3: time.sleep(.01); continue
                    raise Denied('Ledger and witness differ; run codex-api doctor. No quota was reset.', code='quota_reconciliation_required')
                if db.execute("SELECT 1 FROM requests WHERE scope='openai:metered' AND phase!='settled'").fetchone():
                    raise Denied('Earlier unclassified usage is unknown; run codex-api reconcile.', code='quota_history_unknown')
                pools = {g:pool_info(db, g, limits[g], day) for g in limits}
                for p in pools.values(): p['used_or_reserved'] += p['baseline']
                result = {'period':day, 'observed_at':dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(),
                          'reset_at':(dt.datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=dt.timezone.utc)+dt.timedelta(days=1)).isoformat(),
                          'daily_pools':pools, 'quota_guard':True, 'ledger_paused':bool(paused),
                          'recorded_requests':db.execute('SELECT COUNT(*) FROM requests').fetchone()[0],
                          'unresolved_requests':db.execute("SELECT COUNT(*) FROM requests WHERE phase IN ('reserved','unknown')").fetchone()[0],
                          'safety_stop':(root/'safety-stop.json').exists()}
                from policy import usage_lines, legacy
                result['usage_lines'] = usage_lines(policy or legacy({'daily_token_limits':limits}),pools)
                return result
        except (sqlite3.Error, OSError, ValueError, TypeError) as error:
            raise Denied('Usage state cannot be verified; run codex-api doctor.', code='quota_state_unavailable') from error


def _tool(tool, namespace=None):
    if not isinstance(tool, dict): raise Denied("Invalid tool definition")
    kind, name = tool.get("type"), tool.get("name")
    if kind == "function" and (name in LOCAL_FUNCTIONS | HARNESS_FUNCTIONS or namespace=='mcp__harness' and name in HARNESS_TOOLS):
        if set(tool) - {"type", "name", "description", "parameters", "strict", "defer_loading"}:
            raise Denied("Unknown local function option")
    elif kind == "custom" and name in LOCAL_CUSTOM:
        if set(tool) - {"type", "name", "description", "format", "defer_loading"}:
            raise Denied("Unknown local custom-tool option")
    elif kind == "namespace" and name in {"functions","clock","mcp__harness"}:
        if set(tool) - {"type", "name", "description", "tools"}: raise Denied("Unknown namespace option")
        children = tool.get("tools")
        if not isinstance(children, list) or not children: raise Denied("Empty namespace")
        for child in children:
            if not isinstance(child,dict) or child.get("type") == "namespace": raise Denied("Invalid nested namespace")
            if name=='clock' and (child.get('type')!='function' or child.get('name')!='sleep'):
                raise Denied('Only the local clock sleep tool is allowed')
            if name=='mcp__harness' and (child.get('type')!='function' or child.get('name') not in HARNESS_TOOLS):raise Denied('Only bundled harness MCP tools are allowed')
            _tool(child,namespace=name)
    else:
        raise Denied("Hosted or unreviewed tool denied")


def normalize(payload, output_cap=4096, *, policy=None):
    if not isinstance(payload, dict) or set(payload) - ROOT_FIELDS:
        raise Denied("Unknown request field or endpoint capability")
    from policy import validate, legacy, tier, PolicyError
    try:p=validate(policy) if policy is not None else legacy()
    except PolicyError as error:raise Denied(str(error),code='policy_invalid') from None
    model = payload.get("model")
    if not isinstance(model,str) or model not in p['models']:
        raise Denied('The model is outside the owner-approved policy. Select an allowed model with /model.',code='model_not_allowed')
    try:selected_tier=tier(payload.get('service_tier',p['defaults']['service_tier']))
    except (PolicyError,TypeError):raise Denied('This service tier is not approved. Use the tier selected in the owner policy.',code='service_tier_disabled') from None
    if selected_tier!=p['defaults']['service_tier']:
        raise Denied('This service tier differs from the owner-approved policy. No automatic tier fallback is allowed.',code='service_tier_disabled')
    if output_cap>p['models'][model]['max_output_tokens']:
        raise Denied('The output cap exceeds the reviewed model limit.',code='policy_invalid')
    if payload.get("store", False) is not False: raise Denied("Response storage denied")
    tools = payload.get("tools", [])
    if not isinstance(tools, list): raise Denied("Invalid tools")
    for tool in tools: _tool(tool)
    choice = payload.get("tool_choice", "auto")
    if choice not in ("auto", "none", "required"):
        raise Denied("Explicit tool routing requires review")
    include = payload.get("include", [])
    if not isinstance(include, list) or set(include) - {"reasoning.encrypted_content"}:
        raise Denied("Hosted-tool output request denied")
    source = payload.get("input")
    declarations = []
    if isinstance(source, str):
        pass
    elif isinstance(source, list):
        for item in source:
            if not isinstance(item, dict): raise Denied("Invalid input item")
            kind = item.get("type", "message")
            item_fields = {
                'additional_tools': {'type','id','role','tools'},
                'message': {'type','id','role','content','status','phase'},
                'function_call': {'type','id','call_id','name','arguments','namespace','status'},
                'custom_tool_call': {'type','id','call_id','name','input','namespace','status'},
                'function_call_output': {'type','id','call_id','output'},
                'custom_tool_call_output': {'type','id','call_id','output'},
                'reasoning': {'type','id','summary','content','encrypted_content','status'},
            }
            if kind not in item_fields or set(item)-item_fields[kind]: raise Denied('Unknown input-item field denied')
            if kind == "additional_tools":
                if set(item) - {"type", "id", "role", "tools"} or item.get('role') not in {'developer','system'}:
                    raise Denied("Invalid client tool declaration")
                declared = item.get('tools')
                if not isinstance(declared,list) or not declared: raise Denied("Empty client tool declaration")
                for tool in declared: _tool(tool)
                declarations.append(declared)
            elif kind == "message":
                if item.get("role") not in {"system", "developer", "user", "assistant"}:
                    raise Denied("Invalid message role")
                content = item.get("content")
                if isinstance(content, str): continue
                if not isinstance(content, list): raise Denied("Invalid message content")
                for part in content:
                    if not isinstance(part, dict): raise Denied("Invalid message part")
                    if part.get("type") in {"input_text", "output_text"}:
                        if set(part)-{'type','text','annotations','logprobs'} or not isinstance(part.get('text'),str):
                            raise Denied('Unknown text input option denied')
                        continue
                    if part.get("type") == "input_image":
                        if set(part)-{'type','image_url','detail'}: raise Denied('Unknown image input option denied')
                        url = part.get("image_url", "")
                        if isinstance(url, str) and url.startswith(("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,")):
                            continue
                    raise Denied("External file, URL, audio or unknown input denied")
            elif kind in {"function_call", "custom_tool_call"}:
                if item.get('namespace') not in {None,'functions','clock','mcp__harness'}: raise Denied('Unknown tool-history namespace')
                if item.get('namespace')=='clock' and (kind!='function_call' or item.get('name')!='sleep'):
                    raise Denied('Unknown clock tool history')
                if item.get('namespace')=='mcp__harness' and (kind!='function_call' or item.get('name') not in HARNESS_TOOLS):raise Denied('Unknown harness tool history')
                if item.get("name") not in LOCAL_FUNCTIONS | LOCAL_CUSTOM | HARNESS_FUNCTIONS and not (item.get('namespace')=='mcp__harness' and item.get('name') in HARNESS_TOOLS):
                    raise Denied("Unreviewed tool history denied")
            elif kind not in {"function_call_output", "custom_tool_call_output", "reasoning"}:
                raise Denied("Stateful, hosted or unknown input item denied")
    else:
        raise Denied("Complete replayed input is required")
    maximum = payload.get("max_output_tokens", output_cap)
    if type(maximum) is not int or not 1 <= maximum <= output_cap:
        raise Denied("Output cap exceeded")
    result = dict(payload)
    # Codex client telemetry is not an inference capability and is never forwarded.
    result.pop("client_metadata", None)
    if declarations:
        # Convert Codex's local history format to documented Responses API tools.
        # Validate before lifting; hosted types cannot hide in the transcript.
        reviewed = declarations[0]
        if any(canonical(d) != canonical(reviewed) for d in declarations) or (tools and canonical(tools) != canonical(reviewed)):
            raise Denied("Conflicting client tool declarations")
        result['tools'] = reviewed
        result['input'] = [i for i in source if i.get('type') != 'additional_tools']
    reasoning=result.get('reasoning',{})
    if not isinstance(reasoning,dict) or set(reasoning)-{'effort','summary'}:raise Denied('Unsupported reasoning field.',code='reasoning_not_allowed')
    effort=reasoning.get('effort')
    if effort is not None and effort not in p['models'][model]['reasoning_efforts']:
        raise Denied('The reasoning effort is unsupported by this approved model.',code='reasoning_not_allowed')
    result.update(store=False, service_tier=selected_tier, max_output_tokens=maximum, parallel_tool_calls=False)
    if result.get("truncation", "disabled") != "disabled": raise Denied("Server truncation denied")
    return result


class Ledger:
    def __init__(self, root, *, initialize=False, clock=time.time):
        self.root, self.clock = Path(root), clock
        self.overlap_seconds = UTC_OVERLAP_SECONDS
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lockfile = (self.root / "process.lock").open("a+b")
        self.db = None
        deadline = time.monotonic()+.15
        while True:
            try:
                fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() < deadline: time.sleep(.01); continue
                self.lockfile.close()
                raise Denied("Another gateway or a quota reader owns the ledger")
        self.mutex = threading.RLock()
        try: self._open(initialize)
        except Exception:
            self.close()
            raise
        self.last_wall = self.clock()
        self.last_mono = time.monotonic()

    def _open(self, initialize):
        db = self.root / "usage.sqlite3"
        witness = self.root / "ledger-witness.json"
        if not db.exists() and not initialize: raise Denied("Missing ledger; explicit initialization required")
        if initialize and (db.exists() or witness.exists()): raise Denied("Initialization cannot reset an existing ledger")
        self.db = sqlite3.connect(db, isolation_level=None, check_same_thread=False)
        os.chmod(db, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=1000")
        if initialize:
            self.db.executescript("""
                CREATE TABLE meta (id TEXT NOT NULL, sequence INTEGER NOT NULL, paused INTEGER NOT NULL);
                CREATE TABLE budgets (scope TEXT, period TEXT, ceiling INTEGER NOT NULL, baseline INTEGER NOT NULL, PRIMARY KEY(scope, period));
                CREATE TABLE requests (id TEXT PRIMARY KEY, scope TEXT NOT NULL, period TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    reserved INTEGER NOT NULL, actual INTEGER, phase TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE carryovers (request_id TEXT, period TEXT, scope TEXT, amount INTEGER NOT NULL, PRIMARY KEY(request_id,period));
            """)
            self.db.execute("INSERT INTO meta VALUES (?,0,1)", (uuid.uuid4().hex,))
            self._write_witness()
        if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok": raise Denied("Corrupt quota ledger")
        if json.loads(witness.read_text()) != self._head(): raise Denied("Ledger/witness mismatch; reconcile before use")
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='carryovers'").fetchone():
            with self.transaction():
                self.db.execute("CREATE TABLE carryovers (request_id TEXT, period TEXT, scope TEXT, amount INTEGER NOT NULL, PRIMARY KEY(request_id,period))")
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='resolutions'").fetchone():
            with self.transaction():
                self.db.execute('CREATE TABLE resolutions (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL, action TEXT NOT NULL, actual INTEGER, evidence_hash TEXT NOT NULL, created REAL NOT NULL)')
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='quota_notices'").fetchone():
            with self.transaction():
                self.db.execute('CREATE TABLE quota_notices (period TEXT NOT NULL, group_id TEXT NOT NULL, threshold INTEGER NOT NULL, claimed REAL NOT NULL, PRIMARY KEY(period,group_id,threshold))')
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='operations'").fetchone():
            with self.transaction():
                self.db.execute('''CREATE TABLE operations (
                    correlation_id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
                    operation_hash TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    phase TEXT NOT NULL, request_id TEXT, provider_request_id TEXT,
                    created REAL NOT NULL, updated REAL NOT NULL,
                    UNIQUE(namespace, operation_hash))''')
        # A crash with a merely reserved request also requires reconciliation.

    def _head(self):
        identity, sequence, _ = self.db.execute("SELECT * FROM meta").fetchone()
        return {"identity": identity, "sequence": sequence}

    def _write_witness(self):
        atomic_json(self.root / "ledger-witness.json", self._head())

    @contextlib.contextmanager
    def transaction(self):
        with self.mutex:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("UPDATE meta SET sequence=sequence+1")
                self.db.execute("COMMIT")
                try: self._write_witness()
                except Exception:
                    # All later admissions must fail until the operator repairs the state.
                    self.failed = True
                    raise
            except Exception:
                if self.db.in_transaction: self.db.execute("ROLLBACK")
                raise

    def configure_budget(self, scope, period, ceiling, baseline=0):
        if not all(type(v) is int and v >= 0 for v in (ceiling, baseline)) or baseline > ceiling:
            raise Denied("Invalid budget")
        with self.transaction():
            if self.db.execute("SELECT 1 FROM budgets WHERE scope=? AND period=?", (scope, period)).fetchone():
                raise Denied("Existing budgets cannot be reset")
            self.db.execute("INSERT INTO budgets VALUES (?,?,?,?)", (scope, period, ceiling, baseline))

    def begin_operation(self, payload, operation_id=None, namespace='local'):
        """Claim an explicit logical operation before any counting request.

        Replays are refused, including operations interrupted before dispatch.
        There is deliberately no response-content cache or implicit prompt dedup.
        Only hashes of caller identifiers and request bodies are persisted.
        """
        if not isinstance(namespace, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', namespace):
            raise Denied('The operation namespace is invalid.', code='invalid_operation_id')
        if operation_id is None: operation_id = uuid.uuid4().hex
        if not isinstance(operation_id, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{8,128}', operation_id):
            raise Denied('Idempotency-Key must contain 8 to 128 letters, digits, dots, colons, underscores or hyphens.', code='invalid_operation_id')
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        operation_hash = hashlib.sha256(operation_id.encode('ascii')).hexdigest()
        correlation_id = uuid.uuid4().hex
        self.check_clock()
        with self.transaction():
            prior = self.db.execute('SELECT correlation_id,payload_hash,phase,request_id FROM operations WHERE namespace=? AND operation_hash=?', (namespace, operation_hash)).fetchone()
            if prior:
                details = {'correlation_id': prior[0], 'operation_phase': prior[2]}
                if prior[3]: details['request_id'] = prior[3]
                if prior[1] != digest:
                    raise Denied('This Idempotency-Key was already used with a different request. No counting or model request was sent. Use a new key only for an intentional new operation.', code='operation_id_conflict', status=409, details=details)
                raise Denied('This operation was already admitted. It was not sent again and no response content is cached. Check its recorded state; use a new Idempotency-Key only for an intentional new request.', code='duplicate_operation', status=409, details=details)
            if self.db.execute('SELECT paused FROM meta').fetchone()[0]: raise Denied('Gateway is paused')
            now = self.clock()
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?,NULL,NULL,?,?)', (correlation_id, namespace, operation_hash, digest, 'admitted', now, now))
        return correlation_id

    def mark_operation(self, correlation_id, phase, request_id=None, provider_request_id=None):
        phases = {'admitted', 'counting', 'reserved', 'dispatched', 'completed', 'failed'}
        if phase not in phases or not isinstance(correlation_id, str) or not re.fullmatch(r'[0-9a-f]{32}', correlation_id):
            raise Denied('Invalid operation transition.', code='operation_state_invalid')
        if request_id is not None and (not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-f]{32}', request_id)):
            raise Denied('Invalid operation attempt identity.', code='operation_state_invalid')
        if provider_request_id is not None and (not isinstance(provider_request_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', provider_request_id)):
            raise Denied('Invalid provider request identity.', code='operation_state_invalid')
        transitions = {'admitted': {'counting','reserved','dispatched','failed'},
                       'counting': {'reserved','failed'}, 'reserved': {'dispatched','failed'},
                       'dispatched': {'completed','failed'}, 'completed': set(), 'failed': set()}
        with self.transaction():
            prior = self.db.execute('SELECT phase,request_id,provider_request_id FROM operations WHERE correlation_id=?', (correlation_id,)).fetchone()
            if not prior or phase != prior[0] and phase not in transitions[prior[0]]:
                raise Denied('The operation state changed; no request was repeated.', code='operation_state_invalid')
            if request_id is not None and prior[1] is not None and prior[1] != request_id:
                raise Denied('An operation cannot acquire another provider attempt.', code='operation_state_invalid')
            if provider_request_id is not None and prior[2] is not None and prior[2] != provider_request_id:
                raise Denied('The provider request identity changed.', code='operation_state_invalid')
            self.db.execute('UPDATE operations SET phase=?,request_id=COALESCE(request_id,?),provider_request_id=COALESCE(provider_request_id,?),updated=? WHERE correlation_id=?', (phase, request_id, provider_request_id, self.clock(), correlation_id))

    def pause(self, paused=True):
        with self.transaction(): self.db.execute("UPDATE meta SET paused=?", (int(paused),))

    def check_clock(self):
        now, mono = self.clock(), time.monotonic()
        if abs((now - self.last_wall) - (mono - self.last_mono)) > 5:
            self.failed = True
            raise Denied("Clock changed or machine resumed; reverify quota")
        self.last_wall, self.last_mono = now, mono
        if getattr(self, "failed", False): raise Denied("Ledger requires reconciliation")
        return dt.datetime.fromtimestamp(now, dt.timezone.utc)

    def reserve(self, scope, period, amount, payload):
        if type(amount) is not int or amount <= 0: raise Denied("Invalid reservation")
        self.check_clock()
        request_id = uuid.uuid4().hex
        with self.transaction():
            if self.db.execute("SELECT paused FROM meta").fetchone()[0]: raise Denied("Gateway is paused")
            if self.db.execute("SELECT 1 FROM requests WHERE scope=? AND phase IN ('reserved','unknown')", (scope,)).fetchone():
                raise Denied("Earlier request is unresolved")
            row = self.db.execute("SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?", (scope, period)).fetchone()
            if row is None: raise Denied("No verified free budget for this period")
            spent = self.db.execute("SELECT COALESCE(SUM(CASE WHEN phase='settled' THEN actual ELSE reserved END),0) FROM requests WHERE scope=? AND period=?", (scope, period)).fetchone()[0]
            if row[1] + spent + amount > row[0]: raise Denied("Free budget cannot cover the whole request")
            self.db.execute("INSERT INTO requests VALUES (?,?,?,?,?,NULL,'reserved',?)",
                (request_id, scope, period, hashlib.sha256(canonical(payload)).hexdigest(), amount, self.clock()))
        return request_id

    def dispatch(self, request_id):
        self.check_clock()
        with self.transaction():
            if self.db.execute("SELECT paused FROM meta").fetchone()[0]: raise Denied("Dispatch was cancelled")
            row = self.db.execute("SELECT period,phase FROM requests WHERE id=?", (request_id,)).fetchone()
            if row is None or row[1] != "reserved": raise Denied("Invalid dispatch permit")
            now = dt.datetime.fromtimestamp(self.clock(), dt.timezone.utc)
            if row[0] not in {now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")}:
                raise Denied("Quota period changed before dispatch")
            if now.hour == 23 and now.minute >= 55: raise Denied("UTC rollover guard window")
            self.db.execute("UPDATE requests SET phase='unknown' WHERE id=?", (request_id,))

    def begin_metered(self, payload):
        """Record an explicitly authorized metered request without claiming free quota."""
        request_id = uuid.uuid4().hex
        now = self.clock()
        period = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")
        with self.transaction():
            if self.db.execute("SELECT paused FROM meta").fetchone()[0]: raise Denied("Gateway is paused")
            self.db.execute("INSERT INTO requests VALUES (?,?,?,?,0,NULL,'unknown',?)",
                (request_id, "openai:metered", period, hashlib.sha256(canonical(payload)).hexdigest(), now))
        return request_id

    def daily_remaining(self, group, ceiling):
        """One durable daily pool; legacy unclassified usage is charged to both groups."""
        if (self.root/'safety-stop.json').exists():
            raise Denied('Recorded token usage needs reconciliation before further model requests.',code='quota_reconciliation_required')
        now = self.check_clock()
        period, scope = now.strftime("%Y-%m-%d"), "openai:" + group
        with self.transaction():
            if self.db.execute("SELECT 1 FROM requests WHERE scope='openai:metered' AND phase!='settled'").fetchone():
                raise Denied("An earlier trial request has incomplete usage data. Remaining quota cannot be determined safely.", code="quota_history_unknown")
            row = self.db.execute("SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?", (scope,period)).fetchone()
            if row is None:
                baseline = self.db.execute("SELECT COALESCE(SUM(actual),0) FROM requests WHERE scope='openai:metered' AND period=?", (period,)).fetchone()[0]
                self.db.execute("INSERT INTO budgets VALUES (?,?,?,?)", (scope,period,ceiling,baseline))
            elif row[0] != ceiling:
                raise Denied("The daily limit differs from the ledger. Reconcile the settings first; recorded usage will not be reset.", code="quota_settings_changed")
        return pool_info(self.db, group, ceiling, period)

    def reserve_daily(self, group, ceiling, amount, payload):
        if type(amount) is not int or amount <= 0: raise Denied("Invalid reservation")
        with self.mutex:
            info = self.daily_remaining(group,ceiling)
            if info['remaining'] < amount:
                raise Denied(f"Group {group} requires up to {amount:,} tokens, but only {info['remaining']:,} remain. The model request was blocked before dispatch. Select an allowed model with sufficient quota or retry after 00:00 UTC.", code="daily_token_limit", status=429, details=info | {"required":amount})
            request_id=uuid.uuid4().hex
            with self.transaction():
                if self.db.execute("SELECT paused FROM meta").fetchone()[0]: raise Denied("Gateway is paused")
                self.db.execute("INSERT INTO requests VALUES (?,?,?,?,?,NULL,'reserved',?)",(request_id,"openai:"+group,info['period'],hashlib.sha256(canonical(payload)).hexdigest(),amount,self.clock()))
            return request_id

    def reject(self, request_id):
        # An explicit provider rejection has no terminal model usage. Keep the debit
        # conservatively, including the UTC overlap, without leaving it in flight.
        with self.transaction():
            row=self.db.execute('SELECT scope,period,created,reserved,phase FROM requests WHERE id=?',(request_id,)).fetchone()
            if row is None or row[4]!='unknown':return
            self.db.execute("UPDATE requests SET phase='rejected' WHERE id=?",(request_id,))
            today=dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc).strftime('%Y-%m-%d')
            self._terminal_carry(request_id,row[0],row[1],row[2],row[3],today)

    def note_usage_conflict(self, request_id):
        """Keep uncertain usage fully reserved and stop further model admission."""
        with self.mutex:
            row=self.db.execute('SELECT phase FROM requests WHERE id=?',(request_id,)).fetchone()
            if row!=('unknown',):raise Denied('A usage conflict requires an unresolved dispatched request.',code='operation_state_invalid')
            path=self.root/'safety-stop.json'
            if not path.exists():atomic_json(path,{'reason':'terminal_usage_conflict','request_id':request_id})

    def void_unsent(self, request_id):
        with self.transaction():
            self.db.execute("UPDATE requests SET phase='not_sent',reserved=0,actual=0 WHERE id=? AND phase='reserved'",(request_id,))

    def dispatch_daily(self, request_id):
        self.check_clock()
        with self.transaction():
            if self.db.execute("SELECT paused FROM meta").fetchone()[0]: raise Denied("Dispatch was cancelled")
            row=self.db.execute("SELECT period,phase FROM requests WHERE id=?",(request_id,)).fetchone()
            now=dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc)
            if row is None or row[1]!='reserved' or row[0]!=now.strftime('%Y-%m-%d'):
                raise Denied("The UTC date changed during token counting; resend the request.",code="quota_day_changed")
            self.db.execute("UPDATE requests SET phase='unknown' WHERE id=?",(request_id,))

    def settle(self, request_id, actual):
        if type(actual) is not int or actual < 0: raise Denied("Missing or invalid terminal usage")
        with self.mutex:
            prior=self.db.execute('SELECT reserved,scope FROM requests WHERE id=?',(request_id,)).fetchone()
            if prior and prior[1]!='openai:metered' and actual>prior[0]:
                atomic_json(self.root/'safety-stop.json',{'reason':'usage_above_reservation','request_id':request_id})
                raise Denied('Actual usage exceeded the reservation. Further model requests are blocked until the count discrepancy is reconciled.',code='usage_above_reservation')
        with self.transaction():
            row = self.db.execute("SELECT reserved,actual,phase,scope,period,created FROM requests WHERE id=?", (request_id,)).fetchone()
            if row is None: raise Denied("Unknown request")
            if row[2] == "settled":
                if row[1] != actual: raise Denied("Conflicting duplicate usage")
                return
            if row[2] != "unknown" or (row[3] != "openai:metered" and actual > row[0]):
                raise Denied("Usage exceeded reservation or invalid phase")
            self.db.execute("UPDATE requests SET actual=?,phase='settled' WHERE id=?", (actual, request_id))
            today=dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc).strftime('%Y-%m-%d')
            self._terminal_carry(request_id,row[3],row[4],row[5],actual,today)

    def _terminal_carry(self, request_id, scope, period, created, amount, today):
        """Conservatively cover ambiguous UTC attribution without a blackout.

        This runs inside a terminal-state or reconciliation witnessed transaction.
        A near-midnight request can count against the next local day even when
        its terminal event arrived before local midnight. This is a safety
        overlap, not a claim about which provider UTC bucket was actually used.
        """
        targets=set()
        if scope.startswith('openai:') and period!=today:targets.add(today)
        if scope.startswith('openai:') and scope!='openai:metered' and re.fullmatch(r'\d{4}-\d{2}-\d{2}',period):
            started=dt.datetime.fromtimestamp(created,dt.timezone.utc)
            if started.strftime('%Y-%m-%d')==period:
                midnight=started.replace(hour=0,minute=0,second=0,microsecond=0)+dt.timedelta(days=1)
                seconds=midnight.timestamp()-created
                if 0<seconds<=self.overlap_seconds:targets.add(midnight.strftime('%Y-%m-%d'))
        for target in targets:
            # One request/day primary key prevents a genuine next-day terminal
            # from being counted a second time by the overlap rule.
            self.db.execute('INSERT OR REPLACE INTO carryovers VALUES (?,?,?,?)',(request_id,target,scope,amount))

    def status(self):
        with self.mutex:
            return {"paused": bool(self.db.execute("SELECT paused FROM meta").fetchone()[0]),
                "unresolved": self.db.execute("SELECT COUNT(*) FROM requests WHERE phase IN ('reserved','unknown')").fetchone()[0],
                "requests": self.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]}

    def claim_daily_notices(self, limits, *, warning_percent=90):
        """At most one UI notice per UTC day/group; this never changes a budget."""
        if not valid_limits(limits) or type(warning_percent) is not int or not 1<=warning_percent<=99:
            raise Denied('Daily quota settings cannot be verified',code='quota_settings_changed')
        with self.mutex:
            self.check_clock()
            if json.loads((self.root/'ledger-witness.json').read_text()) != self._head():
                raise Denied('The quota ledger cannot be verified',code='quota_reconciliation_required')
            if self.db.execute("SELECT 1 FROM requests WHERE scope='openai:metered' AND phase!='settled'").fetchone():
                raise Denied('Earlier usage is unknown',code='quota_history_unknown')
            now=self.clock();day=dt.datetime.fromtimestamp(now,dt.timezone.utc).strftime('%Y-%m-%d')
            pending=[]
            for group in limits:
                info=pool_info(self.db,group,limits[group],day)
                used=info['baseline']+info['used_or_reserved']
                if used*100 < limits[group]*warning_percent:continue
                if self.db.execute('SELECT 1 FROM quota_notices WHERE period=? AND group_id=? ',(day,group)).fetchone():continue
                pending.append({'group':group,'period':day,'threshold':warning_percent,'remaining':info['remaining'],
                    'message':f"API quota warning - Group {group}: {warning_percent}%+ used or reserved; {info['remaining']:,} tokens left. Resets 00:00 UTC."})
            if pending:
                with self.transaction():
                    for notice in pending:self.db.execute('INSERT INTO quota_notices VALUES (?,?,?,?)',(day,notice['group'],warning_percent,now))
            return pending

    def reconcile(self, plan):
        result=self._reconcile(plan)
        # A crash between the durable receipt and this optional clear is safe;
        # replaying the identical receipt can finish the clear without a refund.
        with self.mutex:
            path=self.root/'safety-stop.json'
            if path.exists():
                stop=json.loads(path.read_text())
                if (stop.get('reason')=='terminal_usage_conflict'
                    and self.db.execute('SELECT 1 FROM resolutions WHERE request_id=?',(stop.get('request_id'),)).fetchone()
                    and not self.db.execute("SELECT 1 FROM requests WHERE scope LIKE 'openai:%' AND phase IN ('reserved','unknown','rejected')").fetchone()):
                    if json.loads((self.root/'ledger-witness.json').read_text())!=self._head():
                        raise Denied('Usage receipt and witness differ; the safety stop was retained.',code='quota_reconciliation_required')
                    path.unlink()
                    descriptor=os.open(self.root,os.O_RDONLY)
                    try:os.fsync(descriptor)
                    finally:os.close(descriptor)
            result['safety_stop_preserved']=path.exists()
        return result

    def _reconcile(self, plan):
        """Apply a reviewed host-only receipt; never infer that missing usage is zero."""
        keys = {'version','resolution_id','request_id','expected_phase','expected_reserved_tokens','action','actual_tokens','evidence'}
        if not isinstance(plan, dict) or set(plan) != keys or type(plan['version']) is not int or plan['version'] != 1:
            raise Denied('Invalid reconciliation receipt')
        for key in ('resolution_id','request_id'):
            if not isinstance(plan[key], str) or len(plan[key]) != 32 or any(c not in '0123456789abcdef' for c in plan[key]):
                raise Denied('Invalid reconciliation identity')
        action, evidence = plan['action'], plan['evidence']
        kinds = {'record_actual':'operator_verified_provider_usage', 'confirm_unused':'operator_verified_no_usage', 'confirm_consumed':'operator_verified_completed'}
        if action not in kinds or not isinstance(evidence, dict) or set(evidence) != {'kind','reference','request_finished'}:
            raise Denied('Invalid reconciliation evidence')
        reference = evidence.get('reference')
        if evidence.get('kind') != kinds[action] or evidence.get('request_finished') is not True or not isinstance(reference,str) or not 3 <= len(reference) <= 512:
            raise Denied('Review the completed request and provide the required evidence reference')
        if reference.startswith('REPLACE_'): raise Denied('Replace the evidence placeholder with a verified reference')
        if any(ord(c)<32 for c in reference): raise Denied('Invalid evidence reference')
        if type(plan['expected_reserved_tokens']) is not int or plan['expected_reserved_tokens'] < 0:
            raise Denied('Invalid expected reservation')
        actual = plan['actual_tokens']
        if action == 'record_actual':
            if type(actual) is not int or not 0 <= actual <= 2**53-1: raise Denied('Confirmed actual_tokens must be a non-negative integer')
        elif actual is not None: raise Denied('Only record_actual accepts actual_tokens')
        digest = hashlib.sha256(canonical(plan)).hexdigest()
        with self.transaction():
            prior = self.db.execute('SELECT fingerprint FROM resolutions WHERE id=? OR request_id=?', (plan['resolution_id'],plan['request_id'])).fetchone()
            if prior:
                if prior[0] != digest: raise Denied('Conflicting reconciliation; recorded usage was not changed')
                return {'applied':False, 'request_id':plan['request_id'], 'action':action}
            row = self.db.execute('SELECT scope,period,reserved,phase,created FROM requests WHERE id=?', (plan['request_id'],)).fetchone()
            if not row or not re.fullmatch(r'openai:[A-Za-z][A-Za-z0-9_-]{0,15}',row[0]) or row[0]=='openai:metered': raise Denied('This receipt requires a classified daily-pool request')
            scope, period, reserved, phase, created = row
            if phase not in {'reserved','unknown','rejected'} or phase != plan['expected_phase'] or reserved != plan['expected_reserved_tokens']:
                raise Denied('Request state changed; review a new receipt before applying')
            charged = actual if action == 'record_actual' else reserved if action == 'confirm_consumed' else 0
            if action == 'record_actual' and actual > reserved:
                atomic_json(self.root/'safety-stop.json', {'reason':'usage_above_reservation', 'request_id':plan['request_id']})
            new_phase = 'settled' if action == 'record_actual' else 'resolved_conservative' if action == 'confirm_consumed' else 'reconciled_unused'
            self.db.execute('UPDATE requests SET actual=?,reserved=?,phase=? WHERE id=?',
                            (actual if action == 'record_actual' else None if action == 'confirm_consumed' else 0,
                             reserved if action != 'confirm_unused' else 0, new_phase,plan['request_id']))
            today = self.check_clock().strftime('%Y-%m-%d')
            self._terminal_carry(plan['request_id'],scope,period,created,charged,today)
            self.db.execute('INSERT INTO resolutions VALUES (?,?,?,?,?,?,?)',
                            (plan['resolution_id'],plan['request_id'],digest,action,actual,hashlib.sha256(canonical(evidence)).hexdigest(),self.clock()))
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE name='runtime_requests'").fetchone():
                # A total-only receipt cannot reconstruct the input/output price
                # split. Keep its full USD upper bound unless no model use was
                # specifically verified; counting may still have incurred cost.
                self.db.execute("UPDATE runtime_requests SET phase='reconciled',actual_tokens=?,cost_actual=CASE WHEN ?='confirm_unused' THEN CASE WHEN counted=1 THEN count_hold ELSE 0 END ELSE cost_hold END,completed=? WHERE request_id=?",
                    (charged,action,self.clock(),plan['request_id']))
        return {'applied':True, 'request_id':plan['request_id'], 'action':action,
                'charged_tokens':charged, 'safety_stop_preserved':(self.root/'safety-stop.json').exists()}

    def close(self):
        if self.db is not None: self.db.close()
        self.lockfile.close()
