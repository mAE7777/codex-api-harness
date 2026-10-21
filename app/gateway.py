"""Local-only broker. Upstream origins and routes are constants, never client input."""
from __future__ import annotations
import datetime as dt
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

from guard import Denied, Ledger, MODELS, DAILY_LIMITS, atomic_json, canonical, normalize, read_quota
from transport_control import RequestControl
from workspace_policy import check_workspace

from settings import ROOT, PORT


def credentials(path):
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
        if connection.sock is not None: connection.sock.settimeout(30 if phase == 'input_count' else 120)
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
            ('Model is not one', 'model_not_allowed','Only the five approved models are allowed. Select one with /model.'),
            ('Hosted or unreviewed tool','tool_disabled','This hosted or unreviewed tool is disabled. Use an approved local tool instead.'),
            ('Paid service tier','service_tier_disabled','Fast, Flex, and Ultrafast service tiers are disabled. Use the standard tier.'),
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


class Broker:
    def __init__(self, root, ledger, transport=upstream, clock=time.time):
        self.root, self.ledger, self.transport, self.clock = Path(root), ledger, transport, clock
        self.admission = threading.Lock()
        self.workspace_guard = check_workspace if self.root == ROOT else lambda: None

    def receipt(self, provider):
        if (self.root / "paused").exists(): raise Denied("Gateway is paused")
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

    def openai(self, payload, send_headers, send_chunk, cancelled=lambda:False):
        with RequestControl(cancelled, lambda:(self.root/'paused').exists()) as control:
            try:
                return self._openai(payload, send_headers, send_chunk, control)
            except Exception:
                control.check()
                raise

    def _openai(self, payload, send_headers, send_chunk, control):
        def request(path, body, headers, phase, timeout):
            def call():
                if self.transport is upstream:
                    return self.transport('api.openai.com', path, body, headers, control=control, phase=phase)
                return self.transport('api.openai.com', path, body, headers)
            return control.call(call, phase, timeout, returns_connection=True)
        receipt = self.receipt("openai")
        self.workspace_guard()
        daily=receipt.get('quota_guard') is True
        cap=receipt.get('output_token_cap',4096) if daily else 4096
        if type(cap) is not int or not 1<=cap<=16384: raise Denied('Invalid configured output cap')
        normalized = normalize(payload,output_cap=cap)
        key = credentials(self.root / "openai-key.env")["OPENAI_API_KEY"]
        headers = {"Authorization": "Bearer " + key, "OpenAI-Organization": receipt["organization_id"], "OpenAI-Project": receipt["project_id"]}
        metered = receipt.get("billing_policy") == "metered"
        if daily:
            if receipt.get('org_exclusive') is not True:
                raise Denied('The organization has calls outside this gateway. Remaining shared quota cannot be determined safely.',code='organization_usage_unknown')
            group=MODELS[normalized['model']]
            ceiling=receipt.get('daily_token_limits',{}).get(group)
            if type(ceiling) is not int or not 1<=ceiling<=DAILY_LIMITS[group]: raise Denied('Invalid configured daily limit')
            info=self.ledger.daily_remaining(group,ceiling)
            if info['remaining'] < normalized['max_output_tokens']:
                raise Denied(f"Group {group} has {info['remaining']:,} tokens remaining, which cannot cover this output reservation. No counting or model request was sent. Use /model to select the other group or wait until 00:00 UTC.",code='daily_token_limit',status=429,details=info)
            count_fields={k:v for k,v in normalized.items() if k in {'model','input','instructions','tools','tool_choice','parallel_tool_calls','reasoning','text','truncation'}}
            conn,response=request('/v1/responses/input_tokens',count_fields,headers,'input_count',30)
            try: count=control.call(lambda:read_json(response).get('input_tokens'),'input_count',30)
            finally: conn.close()
            if type(count) is not int or count<0: raise Denied('Exact input token counting failed. No model request was sent.',code='input_count_unavailable')
            control.check()
            request_id=self.ledger.reserve_daily(group,ceiling,count+normalized['max_output_tokens'],normalized)
        elif metered:
            # Do not call a separate counting endpoint or assert unverified free eligibility.
            request_id = self.ledger.begin_metered(normalized)
        else:
            count_fields = {k: v for k, v in normalized.items() if k in {"model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "text", "truncation"}}
            conn, response = request('/v1/responses/input_tokens', count_fields, headers, 'input_count', 30)
            try: count = control.call(lambda:read_json(response).get('input_tokens'), 'input_count', 30)
            finally: conn.close()
            if type(count) is not int or count < 0: raise Denied("Exact input count is unavailable")
            now = self.ledger.check_clock()
            period = now.strftime("%Y-%m-%d")
            group = MODELS[normalized["model"]]
            request_id = self.ledger.reserve("openai:" + group, period, count + normalized["max_output_tokens"], normalized)
        try:
            control.check()
            self.workspace_guard()
            self.unchanged("openai", receipt)
            if daily: self.ledger.dispatch_daily(request_id)
            elif not metered: self.ledger.dispatch(request_id)
        except Exception:
            if daily:self.ledger.void_unsent(request_id)
            raise
        conn, response = request('/v1/responses', normalized, headers, 'response_headers', 120)
        terminal = None
        disconnected = False
        try:
            if response.status != 200:
                error=control.call(lambda:provider_error(response), 'response_error', 30)
                if 400<=response.status<500: self.ledger.reject(request_id)
                raise error
            if normalized.get("stream", False):
                if "text/event-stream" not in response.getheader("Content-Type", ""): raise Denied("Unexpected upstream streaming format")
                send_headers("text/event-stream")
                event_data, event_lines, event_size, total_size = [], [], 0, 0
                control.begin('response_stream', 120)
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
                                candidate = event.get("response", {}).get("usage")
                                if candidate is not None:
                                    if terminal is not None and terminal != candidate: raise Denied("Conflicting terminal usage")
                                    terminal = candidate
                            failure=event.get('response',{}).get('error') if event.get('type')=='response.failed' else event.get('error',event) if event.get('type')=='error' else None
                            if isinstance(failure,dict):raise stream_failure(failure)
                        if not disconnected:
                            try:send_chunk(b''.join(event_lines))
                            except (BrokenPipeError,ConnectionResetError):
                                disconnected=True
                                if daily: control.abort(Denied('The client disconnected; the full reservation is retained for unconfirmed usage.',code='client_cancelled')); control.check()
                        event_data,event_lines,event_size=[],[],0
            else:
                body = control.call(lambda:read_json(response, limit=4_000_000), 'response_body', 120)
                terminal = body.get("usage")
                send_headers("application/json")
                try: send_chunk(canonical(body))
                except (BrokenPipeError, ConnectionResetError): pass
        except (OSError,ValueError):
            control.check()
            raise
        finally:
            conn.close()
            if isinstance(terminal, dict):
                tokens_in, tokens_out = terminal.get("input_tokens"), terminal.get("output_tokens")
                if type(tokens_in) is int and type(tokens_out) is int and tokens_in >= 0 and tokens_out >= 0:
                    self.ledger.settle(request_id, tokens_in + tokens_out)
        if terminal is None:
            control.check()
            raise Denied('Complete terminal usage was not received. The full reservation was retained; usage was not treated as zero.',code='terminal_usage_missing',status=502)

    def tavily_usage(self, key):
        conn, response = self.transport("api.tavily.com", "/usage", None, {"Authorization": "Bearer " + key}, method="GET")
        try: result = read_json(response)
        finally: conn.close()
        account, current_key = result.get("account", {}), result.get("key", {})
        if account.get("current_plan") != "Researcher": raise Denied("Tavily plan is not free Researcher")
        used, limit = account.get("plan_usage"), account.get("plan_limit")
        if type(used) not in (int, float) or type(limit) not in (int, float) or not 0 <= used < limit <= 1000:
            raise Denied("Tavily free remaining credits are unconfirmed or depleted")
        if account.get("paygo_usage", 0) != 0: raise Denied("Tavily reports paid usage")
        # null means unspecified, not zero. The separate current UI receipt proves PAYGO is off.
        key_limit = current_key.get("limit")
        if key_limit is not None:
            key_used = current_key.get("usage")
            if type(key_limit) not in (int, float) or type(key_used) not in (int, float) or key_used + 1 > key_limit:
                raise Denied("Tavily key budget is unavailable")
        if used + 1 > limit: raise Denied("Whole Tavily operation cannot fit free balance")

    def search(self, payload, extract=False):
        allowed = {"provider", "url"} if extract else {"provider", "query"}
        if not isinstance(payload, dict) or set(payload) != allowed: raise Denied("Unreviewed search option denied")
        provider = payload["provider"]
        receipt = self.receipt(provider)
        if extract:
            if provider != "tavily": raise Denied("Only reviewed Tavily extraction is enabled")
            url = payload["url"]
            if not isinstance(url, str) or len(url) > 2048: raise Denied("Invalid URL")
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443): raise Denied("Only public HTTPS URLs are allowed")
            host = parsed.hostname or ""
            if "." not in host or host.endswith((".local", ".internal", ".localhost")): raise Denied("Private URL denied")
            try: addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            except socket.gaierror: raise Denied("URL hostname cannot be verified")
            if any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses): raise Denied("Private URL denied")
            request = {"urls": [url], "extract_depth": "basic", "include_images": False, "include_usage": True}
            route = "/extract"
        else:
            query = payload["query"]
            if not isinstance(query, str) or not 1 <= len(query) <= 1000 or any(c in query for c in ("sk-proj-", "tvly-", "BEGIN PRIVATE KEY")):
                raise Denied("Search query is invalid or contains credential markers")
            request = {"query": query}
            route = "/search"
        keys = credentials(self.root / "search-keys.env")
        now = self.ledger.check_clock(); period = now.strftime("%Y-%m")
        if provider == "tavily":
            key = keys["TAVILY_API_KEY"]
            self.tavily_usage(key)
            if not extract: request.update(search_depth="basic", auto_parameters=False, max_results=5, include_answer=False, include_images=False, include_usage=True)
            host, amount, headers = "api.tavily.com", 1, {"Authorization": "Bearer " + key}
        elif provider == "exa":
            if extract: raise Denied("Exa standalone extraction is disabled")
            key = keys["EXA_API_KEY"]
            request.update(type="lite", numResults=5, contents={"highlights": True})
            host, amount, headers = "api.exa.ai", 20_000, {"x-api-key": key}  # conservative microdollar debit; never refund from estimates
        else: raise Denied("Provider is disabled")
        request_id = self.ledger.reserve(provider, period, amount, request)
        self.unchanged(provider, receipt)
        self.ledger.dispatch(request_id)
        conn, response = self.transport(host, route, request, headers)
        try: result = read_json(response)
        finally: conn.close()
        if provider == "tavily":
            credits = result.get("usage", {}).get("credits")
            if type(credits) not in (int, float) or credits not in (0, 1): raise Denied("Tavily usage is missing or exceeded reservation")
            self.ledger.settle(request_id, int(credits))
        else:
            estimate = result.get("costDollars", {}).get("total")
            if type(estimate) not in (int, float) or not 0 <= estimate <= amount / 1_000_000:
                raise Denied("Exa cost is missing or above conservative debit")
            self.ledger.settle(request_id, amount)
        # Tool results are untrusted source material. No response URLs are fetched here.
        return {"provider": provider, "request_id": request_id, "data": result}


def make_server(root, ledger, port=PORT, transport=upstream):
    root = Path(root)
    token = (root / "gateway.token").read_text().strip()
    if len(token) < 40: raise Denied("Gateway credential is missing")
    broker = Broker(root, ledger, transport)

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
            host = self.headers.get("Host", "")
            if host not in {"127.0.0.1:" + str(port), "localhost:" + str(port), "host.docker.internal:" + str(port)}:
                raise Denied("Unexpected Host header")
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, "Bearer " + token): raise Denied("Invalid gateway credential")

        def do_GET(self):
            if self.path == "/health": return self.reply(200, {"service":"codex-api", "pid":os.getpid(), "service_ready":True, "paused":(root/'paused').exists()})
            try:
                self.authorized()
                if self.path == '/v1/quota':
                    profile = json.loads((root/'verification.json').read_text()).get('openai', {})
                    return self.reply(200, read_quota(root/'state', profile.get('daily_token_limits', {}), now=broker.clock()))
                if self.path != "/v1/models": raise Denied("Endpoint disabled")
                self.reply(200, {"object": "list", "data": [{"id": name, "object": "model"} for name in MODELS]})
            except Denied as error: self.fail(error)

        def do_POST(self):
            started = False
            acquired = False
            self.expect_stream=False
            try:
                self.authorized()
                if self.path not in {"/v1/responses", "/v1/notices/claim", "/tools/search", "/tools/extract"}: raise Denied("Endpoint disabled")
                if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"): raise Denied("Encoded request denied")
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 < length <= 4_000_000: raise Denied("Request size invalid")
                self.connection.settimeout(30)
                payload = decode_json(self.rfile.read(length))
                if self.path == '/v1/notices/claim':
                    if payload != {}:raise Denied('Unsupported notice request')
                    profile=json.loads((root/'verification.json').read_text()).get('openai',{})
                    if profile.get('quota_guard') is not True:raise Denied('Daily quota protection is unavailable')
                    return self.reply(200,{'notices':ledger.claim_daily_notices(profile.get('daily_token_limits',{}))})
                self.expect_stream=isinstance(payload,dict) and payload.get('stream') is True
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
                if self.path == "/v1/responses": broker.openai(payload, headers, chunk,cancelled=cancelled)
                else: self.reply(200, broker.search(payload, extract=self.path == "/tools/extract"))
            except Denied as error:
                self.fail(error,streaming=started)
            except (TimeoutError,socket.timeout):
                self.fail(Denied('The API response timed out. No automatic retry was made; the full reservation was retained for dispatched requests.',code='api_timeout',status=504),streaming=started)
            except Exception:
                self.fail(Denied('The local configuration, ledger, or connection state is unavailable. Run codex-api status for details.',code='gateway_state_unavailable',status=503),streaming=started)
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
