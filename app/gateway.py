"""Local-only broker. Upstream origins and routes are constants, never client input."""
from __future__ import annotations
import datetime as dt
from email.utils import format_datetime, parsedate_to_datetime
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
import select
from pathlib import Path
import socket
import ssl
import signal
import threading
import time
import urllib.parse

from guard import Denied, Ledger, atomic_json, canonical, normalize, read_quota, utc_admission
from policy import load as load_policy, from_receipt, limits as policy_limits, model_pools, PolicyError
from transport_control import RequestControl
from workspace_policy import check_workspace

from settings import ROOT, PORT


def credentials(path, *, allow_empty=False):
    p = Path(path)
    if p.is_symlink() or p.stat().st_mode & 0o077: raise Denied("Credential file permissions are unsafe")
    result = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if name in result: raise Denied("Duplicate credential field")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'": value = value[1:-1]
        if allow_empty and not value: continue
        if not value or any(c in value for c in "\r\n\x00"): raise Denied("Credential is missing or malformed")
        result[name] = value
    return result


def decode_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: raise Denied("Duplicate JSON field")
            out[key] = value
        return out
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Denied("Non-finite JSON number")))
    except (ValueError, TypeError): raise Denied("Malformed JSON")


def upstream(host, path, body, headers, method="POST", *, control=None, phase='provider'):
    class ControlledConnection(http.client.HTTPSConnection):
        def connect(self):
            if control: control.check()
            super().connect()
            self._api_socket = self.sock
            if control: control.check()
        def send(self, data):
            if control: control.check()
            return super().send(data)
    connection = ControlledConnection(host, 443, timeout=30, context=ssl.create_default_context())
    if control: control.track(connection)
    try:
        encoded = None if body is None else canonical(body)
        if control: control.check()
        connection.request(method, path, body=encoded, headers={"Content-Type":"application/json", **headers})
        connection._api_socket = connection.sock
        if connection.sock is not None: connection.sock.settimeout(30 if phase == 'input_count' else max(120,control.phase_timeout) if control else 120)
        if control: control.check()
        return connection, connection.getresponse()
    except Denied:
        connection.close(); raise
    except TimeoutError:
        connection.close()
        if control: control.check()
        raise Denied('The API connection or response wait timed out. No automatic retry was made; possibly dispatched usage retains its reservation.', code='api_timeout', status=504, details={'phase':phase})
    except Exception:
        connection.close()
        if control: control.check()
        raise Denied('Unable to connect to the API service; no automatic retry was made.', code='api_connection_failed', status=502)


def provider_error(response):
    status=response.status
    try:
        raw=response.read(65537)
        data=decode_json(raw) if len(raw)<=65536 else {}
        error=data.get('error',{}) if isinstance(data,dict) else {}
        if not isinstance(error,dict): error={}
    except Exception: error={}
    def identifier(value):
        return value if isinstance(value,str) and re.fullmatch(r'[a-zA-Z0-9_.\[\]-]{1,128}',value) else None
    code=identifier(error.get('code')) or identifier(error.get('type')) or 'upstream_error'
    if code in {'credit_balance_exhausted','insufficient_quota'}:
        message='OpenAI balance or billing quota is insufficient. Check Billing. No automatic top-up or subscription fallback will occur.'
    elif code=='project_spend_limit_exceeded': message='The OpenAI project spending hard limit was reached. Check project Limits.'
    elif code=='organization_spend_limit_exceeded': message='The OpenAI organization spending hard limit was reached. Check organization Limits.'
    elif code=='context_length_exceeded': message='The conversation exceeds the model context limit. Use /new, or /compact if quota remains.'
    elif status==401: message='The OpenAI API key is invalid, expired, or bound to another account. Update the API key; subscription login is not required.'
    elif status==429: message='An OpenAI request or token rate limit was reached. Retry manually later.'
    elif status==403: message='OpenAI denied access. Check the API key Responses, model, and project permissions.'
    elif status==404: message='OpenAI could not find the model or resource, or this project lacks access. Select another allowed model.'
    elif status==400: message='OpenAI rejected a request parameter. Check the configuration using the parameter and error code.'
    elif status>=500: message='OpenAI is temporarily unavailable. No automatic retry was made; retry later.'
    else: message='OpenAI rejected the request. Check the status and error code.'
    details={'upstream_status':status,'upstream_code':code}
    param=identifier(error.get('param'))
    if param: details['param']=param; message+=' Parameter: '+param+'.'
    request_id=identifier(response.getheader('x-request-id',''))
    if request_id: details['request_id']=request_id
    retry=response.getheader('Retry-After','')
    if isinstance(retry,str) and re.fullmatch(r'\d{1,5}',retry):
        details['retry_after_seconds']=int(retry);message+=f' Retry after {int(retry)} seconds.'
    # Deliberately do not forward arbitrary provider messages: they may echo keys or prompts.
    return Denied(message,code=code,status=status,details=details)


def public_error(error):
    message=str(error)
    code=getattr(error,'code',None)
    if not code:
        mapping=[
            ('Model is not one', 'model_not_allowed','Select an owner-approved model with /model.'),
            ('Hosted or unreviewed tool','tool_disabled','This hosted or unreviewed tool is disabled. Use an approved local tool instead.'),
            ('Paid service tier','service_tier_disabled','Use the service tier selected in the owner policy.'),
            ('External file, URL, audio','input_type_disabled','This external file, URL, or audio input is disabled.'),
            ('Endpoint disabled','endpoint_disabled','This endpoint or feature is disabled. Changing the request URL will not enable it.'),
            ('Gateway is paused','gateway_stopped','The API environment is stopping. Run codex-api again to start it.'),
            ('Invalid gateway credential','gateway_auth_failed','The sandbox and local gateway credentials do not match. Exit and restart API Codex.'),
            ('Another request is in flight','request_in_progress','A request is already running. Wait for it to finish or cancel it before retrying.'),
            ('is disabled','provider_disabled','This provider is disabled. No fallback provider will be used.'),
            ('Unknown request field','unsupported_request','The CLI request contains an unsupported field. The gateway adapter needs an update.'),
        ]
        for token,kind,description in mapping:
            if token in message: code,message=kind,description; break
        else: code,message='local_policy_rejected','The local policy rejected the request: '+message
    return {'message':message,'type':'api_gateway_error','code':code,**getattr(error,'details',{})}


def stream_failure(error):
    code=error.get('code','')
    status=429 if code in {'rate_limit_exceeded','rate_limit_error','slow_down','insufficient_quota','credit_balance_exhausted','project_spend_limit_exceeded','organization_spend_limit_exceeded'} else 401 if code=='invalid_api_key' else 400
    class EventResponse:
        def read(self,_):return canonical({'error':error})
        def getheader(self,*_):return ''
    response=EventResponse();response.status=status
    return provider_error(response)


def read_json(response, limit=512_000):
    if response.status != 200: raise provider_error(response)
    data = response.read(limit + 1)
    if len(data) > limit: raise Denied("Upstream response exceeds size limit")
    return decode_json(data)


def terminal_tokens(usage):
    """Validate authoritative terminal counters before presenting success."""
    if usage is None:
        raise Denied('Complete terminal usage was not received. The full reservation was retained; usage was not treated as zero.', code='terminal_usage_missing', status=502)
    if not isinstance(usage, dict):
        raise Denied('Terminal token usage is invalid. The full reservation was retained; no usage was guessed.', code='terminal_usage_invalid', status=502)
    counters = [usage.get('input_tokens'), usage.get('output_tokens')]
    maximum = 2**53-1
    if any(type(v) is not int or not 0 <= v <= maximum for v in counters) or sum(counters) > maximum:
        raise Denied('Terminal token usage is invalid. The full reservation was retained; no usage was guessed.', code='terminal_usage_invalid', status=502)
    total = sum(counters)
    if 'total_tokens' in usage and (type(usage['total_tokens']) is not int or usage['total_tokens'] != total):
        raise Denied('Terminal token totals disagree. The full reservation was retained; no usage was guessed.', code='terminal_usage_invalid', status=502)
    return total


def verify_provider_clock(response, now):
    """Use this existing TLS response as bounded clock evidence; no extra call."""
    header=response.getheader('Date')
    if not isinstance(header,str) or not re.fullmatch(r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT',header):
        raise Denied('The token-count response has no valid GMT Date header. The provider clock could not be verified, so no model request was sent. Counting may already have occurred.',code='provider_clock_unverified',status=503)
    try:
        instant=parsedate_to_datetime(header)
        if format_datetime(instant,usegmt=True)!=header:raise ValueError()
        offset=instant.timestamp()-now
    except (ValueError,TypeError,OverflowError):
        raise Denied('The token-count response Date header is invalid. No model request was sent. Counting may already have occurred.',code='provider_clock_unverified',status=503)
    # Five seconds of clock tolerance plus one second of HTTP Date precision.
    if abs(offset)>6:
        raise Denied('The local UTC clock and provider Date differ by more than six seconds. No model request was sent. Check automatic date/time synchronization, then retry manually. Counting may already have occurred.',code='provider_clock_mismatch',status=503,details={'provider_offset_seconds':round(offset,3)})


class Broker:
    def __init__(self, root, ledger, transport=upstream, clock=time.time):
        self.root, self.ledger, self.transport, self.clock = Path(root), ledger, transport, clock
        self.admission = threading.Lock()
        self.workspace_guard = check_workspace if self.root == ROOT else lambda: None

    def policy(self, receipt=None):
        try:return from_receipt(receipt) if receipt is not None else load_policy(self.root)
        except (PolicyError,OSError,ValueError) as error:raise Denied('The owner policy cannot be verified: '+str(error),code='policy_invalid') from None

    def receipt(self, provider):
        if (self.root / "paused").exists(): raise Denied("Gateway is paused")
        if provider=='openai' and (self.root/'team').exists():
            raise Denied('This installation owns an organization coordinator. Use a separate client joined to it; an independent personal ledger cannot run alongside it.',code='team_client_required')
        data = json.loads((self.root / "verification.json").read_text())
        entry = data.get(provider, {})
        if provider == "openai" and entry.get("billing_policy") == "metered":
            if entry.get("enabled") is not True: raise Denied("OpenAI is disabled")
            if not all(isinstance(entry.get(k), str) and entry[k] for k in ("project_id", "organization_id")):
                raise Denied("OpenAI account/project binding is missing")
            return entry
        if provider=='openai' and entry.get('enabled') and entry.get('verified') is not True:
            raise Denied('Free-only mode: OpenAI complimentary eligibility is unverified. No counting or generation request was sent. Review SETUP.md; allow API charges only if you explicitly choose to.',code='free_eligibility_unconfirmed')
        if not entry.get("enabled") or entry.get("verified") is not True:
            raise Denied(provider + " is disabled: free eligibility is not verified")
        now = self.clock()
        if not (entry.get("verified_at", now + 1) <= now < entry.get("valid_until", 0)):
            raise Denied(provider + " verification expired; requests stopped")
        if provider == "openai":
            required = ("sharing_enabled", "org_traffic_accounted", "count_endpoint_free_confirmed", "local_tool_inference_free_confirmed")
            if not all(entry.get(k) is True for k in required): raise Denied("OpenAI free-use prerequisites remain unverified")
            if entry.get("tier") not in {"build", "launch", "grow"}: raise Denied("OpenAI usage tier is unknown")
            if not all(isinstance(entry.get(k), str) and entry[k] for k in ("project_id", "organization_id")):
                raise Denied("OpenAI account/project binding is missing")
        elif provider == "tavily":
            if entry.get("paygo_disabled") is not True or entry.get("auto_upgrade_disabled") is not True:
                raise Denied("Tavily paid usage is not disabled")
        elif provider == "exa":
            if entry.get("no_payment_method") is not True or entry.get("auto_topup_disabled") is not True:
                raise Denied("Exa payment safety is not verified")
        else: raise Denied("Provider disabled")
        return entry

    def unchanged(self, provider, receipt):
        if canonical(self.receipt(provider)) != canonical(receipt): raise Denied("Verification changed before dispatch")

    def openai(self, payload, send_headers, send_chunk, cancelled=lambda:False, *, operation_id=None, operation_namespace='local', run_id=None):
        operation = {}
        p=self.policy()
        from runtime_controls import Runtime
        authority=self.team.ledger if hasattr(self,'team') else self.ledger
        controls_root=self.team.root.parent if hasattr(self,'team') else self.root
        namespace='member:'+self.member if hasattr(self,'member') else 'local'
        operation['runtime']=Runtime(controls_root,authority,p,namespace=namespace,clock=self.clock)
        operation['run_id']=run_id
        self.ledger.overlap_seconds=p['defaults']['request_deadline_seconds']+15
        with RequestControl(cancelled, lambda:(self.root/'paused').exists() or (self.root/'policy-pending.json').exists(),total=p['defaults']['request_deadline_seconds']) as control:
            try:
                result = self._openai(payload, send_headers, send_chunk, control, operation, operation_id, operation_namespace)
                if operation.get('id'): self.ledger.mark_operation(operation['id'], 'completed')
                return result
            except Exception as error:
                try: control.check()
                except Denied as cancelled_error: error = cancelled_error
                if operation.get('id'):
                    # Admission itself is durable, even if a counting call failed.
                    # A later replay must never silently retry an uncertain call.
                    self.ledger.mark_operation(operation['id'], 'failed')
                    operation['runtime'].failed(operation['id'],error)
                    if isinstance(error, Denied): error.details.setdefault('correlation_id', operation['id'])
                    else: error.correlation_id = operation['id']
                raise error

    def _openai(self, payload, send_headers, send_chunk, control, operation, operation_id, operation_namespace):
        def request(path, body, headers, phase, timeout):
            def call():
                if self.transport is upstream:
                    return self.transport('api.openai.com', path, body, headers, control=control, phase=phase)
                return self.transport('api.openai.com', path, body, headers)
            return control.call(call, phase, timeout, returns_connection=True)
        receipt = self.receipt("openai")
        self.workspace_guard()
        if (self.ledger.root/'safety-stop.json').exists():
            raise Denied('Recorded token usage needs reconciliation. No counting or model request was sent; run codex-api reconcile.',code='quota_reconciliation_required')
        daily=receipt.get('quota_guard') is True
        p=self.policy(receipt)
        cap=p['defaults']['output_token_cap'] if daily else min(4096,p['defaults']['output_token_cap'])
        normalized = normalize(payload,output_cap=cap,policy=p)
        if receipt.get('billing_policy')!='metered' and p['defaults']['service_tier']!='default':
            raise Denied('Free-only mode does not establish complimentary eligibility for this service tier. No request was sent.',code='free_eligibility_unconfirmed')
        utc_admission(self.clock())
        operation['id'] = self.ledger.begin_operation(normalized, operation_id, namespace=operation_namespace)
        runtime=operation['runtime']
        runtime.start(operation['id'],normalized,operation['run_id'])
        if runtime.config['spending'] and not daily:
            raise Denied('Reviewed cost limits require exact counting and the daily token guard.',code='controls_invalid')
        key = credentials(getattr(self,'key_path',self.root / "openai-key.env"))["OPENAI_API_KEY"]
        headers = {"Authorization": "Bearer " + key, "OpenAI-Organization": receipt["organization_id"], "OpenAI-Project": receipt["project_id"]}
        metered = receipt.get("billing_policy") == "metered"
        if daily:
            if receipt.get('org_exclusive') is not True:
                raise Denied('The organization has calls outside this gateway. Remaining shared quota cannot be determined safely.',code='organization_usage_unknown')
            group=model_pools(p)[normalized['model']]
            ceiling=policy_limits(p)[group]
            info=self.ledger.daily_remaining(group,ceiling)
            if info['remaining'] < normalized['max_output_tokens']:
                raise Denied(f"Group {group} has {info['remaining']:,} tokens remaining, which cannot cover this output reservation. No counting or model request was sent. Choose an allowed model with sufficient quota or wait until 00:00 UTC.",code='daily_token_limit',status=429,details=info)
            count_fields={k:v for k,v in normalized.items() if k in {'model','input','instructions','tools','tool_choice','parallel_tool_calls','reasoning','text','truncation'}}
            self.ledger.mark_operation(operation['id'], 'counting')
            utc_admission(self.clock())
            runtime.count_started(operation['id'])
            conn,response=request('/v1/responses/input_tokens',count_fields,headers,'input_count',30)
            try:
                if response.status==200:verify_provider_clock(response,self.clock())
                count=control.call(lambda:read_json(response).get('input_tokens'),'input_count',30)
            finally: conn.close()
            if type(count) is not int or count<0: raise Denied('Exact input token counting failed. No model request was sent.',code='input_count_unavailable')
            control.check()
            if count+normalized['max_output_tokens']>p['models'][normalized['model']]['context_window']:raise Denied('The counted input plus output reservation exceeds the approved model context window. Start a new conversation or compact it; no model request was sent.',code='context_length_exceeded')
            runtime.reserve(operation['id'],count,normalized['max_output_tokens'])
            request_id=self.ledger.reserve_daily(group,ceiling,count+normalized['max_output_tokens'],normalized)
        elif metered:
            if runtime.config['session_tokens'] is not None:
                raise Denied('A run token limit requires exact counting and the daily guard.',code='controls_invalid')
            # Do not call a separate counting endpoint or assert unverified free eligibility.
            request_id = self.ledger.begin_metered(normalized)
        else:
            count_fields = {k: v for k, v in normalized.items() if k in {"model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "text", "truncation"}}
            self.ledger.mark_operation(operation['id'], 'counting')
            utc_admission(self.clock())
            runtime.count_started(operation['id'])
            conn, response = request('/v1/responses/input_tokens', count_fields, headers, 'input_count', 30)
            try:
                if response.status==200:verify_provider_clock(response,self.clock())
                count = control.call(lambda:read_json(response).get('input_tokens'), 'input_count', 30)
            finally: conn.close()
            if type(count) is not int or count < 0: raise Denied("Exact input count is unavailable")
            runtime.reserve(operation['id'],count,normalized['max_output_tokens'])
            now = self.ledger.check_clock()
            period = now.strftime("%Y-%m-%d")
            group = model_pools(p)[normalized["model"]]
            request_id = self.ledger.reserve("openai:" + group, period, count + normalized["max_output_tokens"], normalized)
        self.ledger.mark_operation(operation['id'], 'reserved', request_id=request_id)
        try:
            control.check()
            self.workspace_guard()
            self.unchanged("openai", receipt)
            utc_admission(self.clock(),counted=daily or not metered)
            runtime.dispatch(operation['id'],request_id)
            if daily: self.ledger.dispatch_daily(request_id)
            elif not metered: self.ledger.dispatch(request_id)
            self.ledger.mark_operation(operation['id'], 'dispatched')
        except Exception:
            if daily or not metered:self.ledger.void_unsent(request_id)
            raise
        phase_timeout=900 if p['defaults']['service_tier']=='flex' else 120
        conn, response = request('/v1/responses', normalized, headers, 'response_headers', phase_timeout)
        terminal = None
        terminal_response = None
        disconnected = False
        def accept_terminal(candidate, *, settle=True):
            nonlocal terminal
            try:actual = terminal_tokens(candidate)
            except Denied:
                if terminal is not None:self.ledger.note_usage_conflict(request_id)
                raise
            if terminal is not None and terminal != candidate:
                self.ledger.note_usage_conflict(request_id)
                raise Denied('Conflicting terminal usage records were received. The full reservation is retained and further model requests are stopped until reconciliation.', code='terminal_usage_conflict', status=502)
            if terminal is None:
                if settle:
                    self.ledger.settle(request_id, actual)
                    runtime.settle(operation['id'],candidate,terminal_response)
                terminal = candidate
        try:
            provider_request_id = response.getheader('x-request-id', '')
            if isinstance(provider_request_id, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', provider_request_id):
                self.ledger.mark_operation(operation['id'], 'dispatched', provider_request_id=provider_request_id)
                with runtime.ledger.transaction():runtime.ledger.db.execute('UPDATE runtime_requests SET provider_request_id=? WHERE id=?',(provider_request_id,operation['id']))
            if response.status != 200:
                error=control.call(lambda:provider_error(response), 'response_error', 30)
                if 400<=response.status<500: self.ledger.reject(request_id)
                raise error
            if normalized.get("stream", False):
                if "text/event-stream" not in response.getheader("Content-Type", ""): raise Denied("Unexpected upstream streaming format")
                send_headers("text/event-stream")
                event_data, event_lines, event_size, total_size = [], [], 0, 0
                terminal_chunks=[]
                control.begin('response_stream', phase_timeout)
                while True:
                    control.check()
                    line = response.readline(1_000_001)
                    control.touch()
                    if not line: break
                    event_size += len(line); total_size += len(line)
                    if event_size > 1_000_000 or total_size > 16_000_000: raise Denied("Stream size exceeded")
                    event_lines.append(line)
                    if line.startswith(b"data:"):
                        event_data.append(line[5:].lstrip(b" ").rstrip(b"\r\n"))
                    if line in (b"\n", b"\r\n"):
                        raw = b"\n".join(event_data)
                        if raw and raw != b"[DONE]":
                            event = decode_json(raw)
                            if event.get("type") in {"response.completed", "response.incomplete", "response.failed"}:
                                response_body = event.get('response')
                                terminal_response = response_body
                                if not isinstance(response_body, dict): accept_terminal(False,settle=False)
                                candidate = response_body.get('usage')
                                if event.get('type')=='response.failed':
                                    if terminal is not None:self.ledger.note_usage_conflict(request_id)
                                    failure=response_body.get('error')
                                    if isinstance(failure,dict):raise stream_failure(failure)
                                    terminal_tokens(candidate)
                                    raise Denied('OpenAI reported a failed response without a valid error record. The full reservation is retained and no terminal success was forwarded.',code='upstream_response_failed',status=502)
                                accept_terminal(candidate,settle=False)
                            failure=event.get('error',event) if event.get('type')=='error' else None
                            if isinstance(failure,dict):raise stream_failure(failure)
                        chunk=b''.join(event_lines)
                        if terminal is not None or raw==b'[DONE]':
                            # Keep every terminal event private until clean EOF
                            # proves there is no later conflicting usage record.
                            terminal_chunks.append(chunk)
                        elif not disconnected:
                            try:send_chunk(chunk)
                            except (BrokenPipeError,ConnectionResetError):
                                disconnected=True
                                control.abort(Denied('The client disconnected; the full reservation is retained for unconfirmed usage.',code='client_cancelled')); control.check()
                        event_data,event_lines,event_size=[],[],0
                control.check()
                if event_lines:
                    raise Denied('The stream ended inside an unfinished event. The full reservation is retained and no terminal success was forwarded.',code='terminal_usage_missing',status=502)
                if terminal is not None:
                    self.ledger.settle(request_id,terminal_tokens(terminal))
                    runtime.settle(operation['id'],terminal,terminal_response)
                    for chunk in terminal_chunks:
                        try:send_chunk(chunk)
                        except (BrokenPipeError,ConnectionResetError):break
            else:
                body = control.call(lambda:read_json(response, limit=4_000_000), 'response_body', 120)
                terminal_response = body
                accept_terminal(body.get("usage") if isinstance(body, dict) else False)
                send_headers("application/json")
                try: send_chunk(canonical(body))
                except (BrokenPipeError, ConnectionResetError): pass
        except (OSError,ValueError):
            control.check()
            raise
        finally:
            conn.close()
        if terminal is None:
            control.check()
            raise Denied('Complete terminal usage was not received. The full reservation was retained; usage was not treated as zero.',code='terminal_usage_missing',status=502)

    def tavily_usage(self, key):
        conn, response = self.transport("api.tavily.com", "/usage", None, {"Authorization": "Bearer " + key}, method="GET")
        try:
            if response.status!=200:raise Denied('Tavily free balance could not be confirmed. No search request was sent.',code='tool_usage_unconfirmed')
            result = read_json(response)
        finally: conn.close()
        account, current_key = result.get("account", {}), result.get("key", {})
        if not isinstance(account,dict) or not isinstance(current_key,dict):raise Denied('Tavily account usage is unavailable.',code='tool_usage_unconfirmed')
        if account.get("current_plan") != "Researcher": raise Denied("Tavily plan is not free Researcher")
        used, limit = account.get("plan_usage"), account.get("plan_limit")
        if type(used) not in (int, float) or type(limit) not in (int, float) or not 0 <= used < limit <= 1000:
            raise Denied("Tavily free remaining credits are unconfirmed or depleted")
        if type(account.get('paygo_usage')) not in (int,float) or account['paygo_usage'] != 0: raise Denied("Tavily paid usage is nonzero or unverified",code='tool_usage_unconfirmed')
        # null means unspecified, not zero. The separate current UI receipt proves PAYGO is off.
        key_limit = current_key.get("limit")
        if 'limit' not in current_key or type(current_key.get('usage')) not in (int,float) or current_key['usage']<0:raise Denied('Tavily key usage is unverified.',code='tool_usage_unconfirmed')
        if key_limit is not None:
            key_used = current_key.get("usage")
            if type(key_limit) not in (int, float) or type(key_used) not in (int, float) or key_used + 1 > key_limit:
                raise Denied("Tavily key budget is unavailable")
        if used + 1 > limit: raise Denied("Whole Tavily operation cannot fit free balance")

    def search(self, payload, extract=False):
        from harness_tools import search
        return search(self,payload,extract=extract)


def make_server(root, ledger, port=PORT, transport=upstream):
    root = Path(root)
    token = (root / "gateway.token").read_text().strip()
    if len(token) < 40: raise Denied("Gateway credential is missing")
    if (root/'team-client.json').exists():
        from team_client import RemoteBroker
        broker=RemoteBroker(root)
    else:broker = Broker(root, ledger, transport)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_): pass  # no prompt, query, credential or tool output logging

        def fail(self,error,streaming=False):
            body=public_error(error)
            try: atomic_json(root/'last-error.json',{'at':time.time(),'status':getattr(error,'status',503),**body})
            except OSError: pass
            if not streaming and getattr(self,'expect_stream',False):
                # Codex collapses HTTP 429 bodies into a generic retry/quota error.
                # A standard Responses SSE error preserves the actionable message.
                self.send_response(200);self.send_header('Content-Type','text/event-stream')
                self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.end_headers()
                streaming=True
            if streaming:
                event={'type':'response.failed','response':{'id':'resp_local_gateway_error','status':'failed','error':{'code':'api_gateway_error','message':'['+body['code']+'] '+body['message']},'usage':None}}
                try: self.wfile.write(b'event: response.failed\ndata: '+canonical(event)+b'\n\n');self.wfile.flush()
                except (BrokenPipeError,ConnectionResetError): pass
                self.close_connection=True
            else: self.reply(getattr(error,'status',503),{'error':body})

        def reply(self, status, body):
            data = canonical(body)
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close"); self.close_connection = True
            self.end_headers(); self.wfile.write(data)

        def authorized(self):
            if len(self.headers.get_all('Host',[]))!=1 or len(self.headers.get_all('Authorization',[]))!=1:
                raise Denied('Ambiguous gateway authentication headers.',code='gateway_auth_failed')
            host = self.headers.get("Host", "")
            if host not in {"127.0.0.1:" + str(port), "localhost:" + str(port), "host.docker.internal:" + str(port)}:
                raise Denied("Unexpected Host header")
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, "Bearer " + token): raise Denied("Invalid gateway credential")

        def do_GET(self):
            if self.path == "/health": return self.reply(200, {"service":"codex-api", "pid":os.getpid(), "service_ready":True, "paused":(root/'paused').exists()})
            try:
                self.authorized()
                if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding') or self.headers.get_all('Content-Length') not in (None,['0']):raise Denied('GET request bodies are disabled.',code='unsupported_request')
                if self.path == '/v1/quota':
                    if hasattr(broker,'quota'):return self.reply(200,broker.quota())
                    profile = json.loads((root/'verification.json').read_text()).get('openai', {})
                    return self.reply(200, read_quota(root/'state', policy_limits(broker.policy(profile)), now=broker.clock(),policy=broker.policy(profile)))
                if self.path == '/v1/report':
                    if hasattr(broker,'report'):return self.reply(200,broker.report())
                    from activity import snapshot
                    return self.reply(200,snapshot(root,broker.policy(),now=broker.clock()))
                if self.path == '/tools/status':
                    if hasattr(broker,'team') or (root/'team-client.json').exists():raise Denied('Shared search and public fetch are disabled; local file search remains available.',code='tool_shared_disabled')
                    from harness_tools import status
                    with ledger.mutex:return self.reply(200,status(root,ledger.db,broker.clock()))
                if self.path != "/v1/models": raise Denied("Endpoint disabled")
                self.reply(200, {"object": "list", "data": [{"id": name, "object": "model"} for name in broker.policy()['models']]})
            except Denied as error: self.fail(error)

        def do_POST(self):
            started = False
            acquired = False
            self.expect_stream=False
            try:
                self.authorized()
                if self.path not in {"/v1/responses", "/v1/notices/claim", "/v1/quota/request", "/tools/search", "/tools/extract", "/tools/call"}: raise Denied("Endpoint disabled")
                if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Encoding") or len(self.headers.get_all('Content-Length',[]))!=1: raise Denied("Encoded or ambiguously framed request denied",code='unsupported_request')
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 < length <= 4_000_000: raise Denied("Request size invalid")
                self.connection.settimeout(30)
                payload = decode_json(self.rfile.read(length))
                if self.path == '/v1/notices/claim':
                    if payload != {}:raise Denied('Unsupported notice request')
                    if hasattr(broker,'notices'):return self.reply(200,broker.notices())
                    profile=json.loads((root/'verification.json').read_text()).get('openai',{})
                    if profile.get('quota_guard') is not True:raise Denied('Daily quota protection is unavailable')
                    return self.reply(200,{'notices':ledger.claim_daily_notices(policy_limits(broker.policy(profile)),warning_percent=broker.policy(profile)['warning_percent'])})
                if self.path == '/v1/quota/request':
                    if not hasattr(broker,'request_more'):raise Denied('Quota requests are available only in shared mode.',code='endpoint_disabled')
                    return self.reply(200,broker.request_more(payload))
                self.expect_stream=isinstance(payload,dict) and payload.get('stream') is True
                operation_keys = self.headers.get_all('Idempotency-Key', [])
                if len(operation_keys) > 1 or operation_keys and self.path != '/v1/responses':
                    raise Denied('Use one Idempotency-Key only on a Responses request.', code='invalid_operation_id')
                operation_id = operation_keys[0] if operation_keys else None
                acquired = broker.admission.acquire(blocking=False)
                if not acquired: raise Denied("Another request is in flight; retry only after checking status")
                if (root / "paused").exists(): raise Denied("Gateway is paused")
                def headers(content_type):
                    nonlocal started
                    self.send_response(200); self.send_header("Content-Type", content_type)
                    self.send_header("Cache-Control", "no-store"); self.send_header("Connection", "close")
                    self.end_headers(); self.close_connection = True; started = True
                def chunk(data): self.wfile.write(data); self.wfile.flush()
                def cancelled():
                    try:
                        readable,_,_=select.select([self.connection],[],[],0)
                        return bool(readable) and self.connection.recv(1,socket.MSG_PEEK)==b''
                    except OSError:return True
                if self.path == "/v1/responses": broker.openai(payload, headers, chunk,cancelled=cancelled,operation_id=operation_id)
                elif self.path == '/tools/call':
                    if (root/'team-client.json').exists():raise Denied('Shared search and public fetch are disabled; local file search remains available.',code='tool_shared_disabled')
                    from harness_tools import call
                    self.reply(200,call(broker,payload))
                else: self.reply(200, broker.search(payload, extract=self.path == "/tools/extract"))
            except Denied as error:
                self.fail(error,streaming=started)
            except (TimeoutError,socket.timeout):
                self.fail(Denied('The API response timed out. No automatic retry was made; the full reservation was retained for dispatched requests.',code='api_timeout',status=504),streaming=started)
            except Exception as error:
                correlation_id = getattr(error, 'correlation_id', None)
                details = {'correlation_id':correlation_id} if isinstance(correlation_id,str) and re.fullmatch(r'[0-9a-f]{32}',correlation_id) else {}
                self.fail(Denied('The local configuration, ledger, or connection state is unavailable. Run codex-api status for details.',code='gateway_state_unavailable',status=503,details=details),streaming=started)
            finally:
                if acquired: broker.admission.release()

        def do_CONNECT(self): self.reply(403, {"error": {"message": "Proxying is disabled"}})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    port = server.server_port
    server.daemon_threads = False
    server.broker = broker
    return server


def serve(root=ROOT, port=PORT):
    root = Path(root)
    ledger = Ledger(root / "state")
    server = make_server(root, ledger, port)
    ledger.pause(False)
    def shutdown(*_):
        # Stop admission persistently before waiting for existing responses to drain.
        (root / "paused").touch(mode=0o600, exist_ok=True)
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try: server.serve_forever()
    finally:
        server.server_close(); ledger.pause(True); ledger.close()


if __name__ == "__main__":
    os.umask(0o077)
    serve()
