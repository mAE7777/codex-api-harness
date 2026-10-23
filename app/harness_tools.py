"""Reviewed free tools. No provider discovery, payment fallback or URL proxy."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import threading
import time
import urllib.parse
import uuid

from guard import Denied, Ledger, atomic_json, canonical, readonly_database
from policy import read_json

MAX_BODY = 1024 * 1024
MAX_TEXT = 48000
PROVIDERS = {'tavily': ('TAVILY_API_KEY', 1), 'exa': ('EXA_API_KEY', 20000),
             'brave': ('BRAVE_API_KEY', 5000)}
FIELDS = {'verified_at', 'valid_until', 'period', 'ceiling', 'baseline',
          'exclusive_account', 'paid_disabled', 'auto_topup_disabled', 'reference'}
SECRET = re.compile(r'(?i)sk-(?:proj-|svcacct-)?[a-z0-9_-]{16,}|tvly-[a-z0-9_-]{16,}|github_pat_|gh[pousr]_[a-z0-9]{16,}|BEGIN.{0,30}PRIVATE.KEY|(?:api[_-]?key|token|password|secret|signature|credential)\s*[=:]')
DNS_SLOTS = threading.BoundedSemaphore(2)


def fail(message, code='tool_policy_invalid'):
    raise Denied(message, code=code)


def defaults():
    return {'version': 1, 'fetch_hosts': [], 'search': {p: None for p in PROVIDERS}}


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def search_credentials(root):
    from gateway import credentials
    path=Path(root)/'search-keys.env'
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 16384: raise OSError()
        values=credentials(path,allow_empty=True)
    except (OSError,ValueError,Denied): fail('Private search credentials are unavailable or unsafe. Use tools credentials; never paste a key into chat.', 'tool_key_missing')
    allowed={name for name,_ in PROVIDERS.values()}|{'BRAVE_SEARCH_API_KEY'}
    if set(values)-allowed:fail('Unknown search credential field; use only the supported private file.', 'tool_key_missing')
    if 'BRAVE_SEARCH_API_KEY' in values:
        if 'BRAVE_API_KEY' in values:fail('Keep only one Brave key field.', 'tool_key_missing')
        values['BRAVE_API_KEY']=values.pop('BRAVE_SEARCH_API_KEY')
    return values


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower() or '.' not in value:
        fail('Use exact lower-case public hostnames, without wildcards or URLs.')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.')):
        fail('Invalid public hostname.')
    if value.endswith(('.local', '.localhost', '.internal', '.home', '.test', '.invalid')):
        fail('Private and reserved hostnames are disabled.')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    fail('IP literals are disabled; use a reviewed public hostname.')


def validate(value):
    if not isinstance(value, dict) or set(value) != set(defaults()) or type(value['version']) is not int or value['version'] != 1:
        fail('Unknown tool policy fields or version.')
    hosts = value['fetch_hosts']
    if not isinstance(hosts, list) or len(hosts) > 64 or not all(isinstance(h,str) for h in hosts) or len(set(hosts)) != len(hosts):
        fail('Choose up to 64 distinct exact fetch hosts.')
    for host in hosts: hostname(host)
    if not isinstance(value['search'], dict) or set(value['search']) != set(PROVIDERS): fail('Unknown search provider.')
    for provider, row in value['search'].items():
        if row is None: continue
        extra = {'no_payment_method'} if provider == 'exa' else {'prepaid_only', 'zero_paid_balance'} if provider == 'brave' else set()
        if not isinstance(row, dict) or set(row) != FIELDS | extra: fail('Incomplete free account evidence for ' + provider + '.')
        for name in ('exclusive_account', 'paid_disabled', 'auto_topup_disabled', *extra):
            if row[name] is not True: fail(provider + ': paid usage, other callers or automatic upgrades are not ruled out.')
        for name in ('verified_at', 'valid_until', 'ceiling', 'baseline'):
            if type(row[name]) is not int or not 0 <= row[name] <= 10**12: fail('Invalid tool evidence number.')
        if not 0 < row['valid_until'] - row['verified_at'] <= 31 * 86400: fail('Tool evidence must expire within 31 days.')
        if not isinstance(row['period'], str): fail('Invalid free allowance month.')
        try: instant = dt.datetime.strptime(row['period'], '%Y-%m').replace(tzinfo=dt.timezone.utc)
        except ValueError: fail('Use an exact YYYY-MM allowance period.')
        if instant.strftime('%Y-%m') != row['period']: fail('Use an exact YYYY-MM allowance period.')
        if not row['baseline'] <= row['ceiling'] or row['ceiling'] < PROVIDERS[provider][1]: fail('The verified free budget cannot fit one conservative request.')
        if provider == 'tavily' and row['ceiling'] > 1000: fail('Researcher supports at most 1000 free credits.')
        if not isinstance(row['reference'], str) or not re.fullmatch(r'https://[A-Za-z0-9./_?=&%#:+-]{1,480}', row['reference']): fail('Provide an account-plan reference, without credentials.')
        if SECRET.search(row['reference']): fail('Credential-bearing evidence links are disabled.')
    return value


def load(root):
    path = Path(root) / 'tools.json'
    return validate(read_json(path, private=True)) if path.exists() or path.is_symlink() else defaults()


def schema(ledger):
    if not ledger.db.execute("SELECT 1 FROM sqlite_master WHERE name='tool_config'").fetchone():
        with ledger.transaction():
            ledger.db.execute('CREATE TABLE tool_config (id INTEGER PRIMARY KEY, digest TEXT NOT NULL)')
            ledger.db.execute('CREATE TABLE tool_credentials (provider TEXT PRIMARY KEY, digest TEXT NOT NULL)')


def verified(root, db):
    value = load(root)
    table = db.execute("SELECT 1 FROM sqlite_master WHERE name='tool_config'").fetchone()
    row = db.execute('SELECT digest FROM tool_config WHERE id=1').fetchone() if table else None
    if row and row[0] != digest(value) or not row and value != defaults():
        fail('Tool policy changed or disappeared. Apply the exact reviewed draft again.', 'tool_policy_changed')
    return value


def status(root, db, now=None):
    value = verified(root, db); now = time.time() if now is None else now
    period = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime('%Y-%m')
    rows = {}
    for provider, row in value['search'].items():
        state = 'disabled' if row is None else 'ready' if row['verified_at'] <= now < row['valid_until'] and row['period'] == period else 'evidence_expired'
        budget = db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?', (provider, period)).fetchone()
        spent = db.execute("SELECT COALESCE(SUM(CASE WHEN phase='settled' THEN actual ELSE reserved END),0) FROM requests WHERE scope=? AND period=?", (provider, period)).fetchone()[0]
        unfinished = db.execute("SELECT id,period,reserved,phase FROM requests WHERE scope=? AND phase IN ('reserved','unknown')", (provider,)).fetchall()
        unresolved = bool(unfinished)
        remaining = max(0, budget[0] - budget[1] - spent) if budget else None
        if state == 'ready' and (not budget or budget != (row['ceiling'], row['baseline'])): state = 'budget_unverified'
        if state == 'ready' and unresolved: state = 'unconfirmed_request'
        if state == 'ready' and remaining < PROVIDERS[provider][1]: state = 'free_limit'
        rows[provider] = {'state': state, 'remaining': remaining, 'unit': 'credits' if provider == 'tavily' else 'micro_usd', 'period': period,
                          'unconfirmed': [dict(zip(('request_id','period','held','phase'),r)) for r in unfinished]}
    return {'version': 1, 'fetch_hosts': value['fetch_hosts'], 'search': rows, 'provider_requests': 0,
            'media': 'disabled', 'fallback': 'disabled'}


def public_url(value, hosts):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value: fail('Invalid public HTTPS URL.', 'tool_url_denied')
    decoded = value
    for _ in range(3): decoded = urllib.parse.unquote(decoded)
    if SECRET.search(decoded) or re.search(r'(?i)/\.(?:env|git|aws|ssh)(?:/|$)|[\r\n\x00]', decoded): fail('Potential credential-bearing URL stopped before any request.', 'tool_url_denied')
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment: raise ValueError()
        host = hostname(parsed.hostname or '')
        if parsed.netloc not in (host, host + ':443'): raise ValueError()
    except (ValueError, Denied): fail('Use a public HTTPS hostname on port 443, without credentials or a fragment.', 'tool_url_denied')
    if host not in hosts: fail('This fetch host is not approved. Review it with codex-api tools template/check/apply in the host terminal.', 'tool_host_not_approved')
    return parsed, host


def public_addresses(host):
    if not DNS_SLOTS.acquire(blocking=False): fail('Earlier DNS checks are still unresolved. No new lookup or request sent.', 'tool_dns_unverified')
    result = []; done = threading.Event()
    def resolve():
        try: result.append(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError: pass
        finally: DNS_SLOTS.release(); done.set()
    threading.Thread(target=resolve, daemon=True).start()
    if not done.wait(5) or not result: fail('Public DNS could not be verified within five seconds. No request sent.', 'tool_dns_unverified')
    rows = result[0]
    addresses = sorted({row[4][0] for row in rows})
    def unsafe(address):
        ip = ipaddress.ip_address(address)
        return not ip.is_global or isinstance(ip, ipaddress.IPv6Address) and (ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None)
    if not addresses or any(unsafe(a) for a in addresses):
        fail('DNS includes a private, mapped or reserved address. No request sent.', 'tool_private_address')
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context()); self.address = address

    def connect(self):
        # The only DNS lookup happened before admission. TLS still validates the
        # original hostname; neither an environment proxy nor a second DNS query is used.
        raw = socket.socket(socket.AF_INET6 if ':' in self.address else socket.AF_INET, socket.SOCK_STREAM)
        self._api_socket = raw
        raw.settimeout(self.timeout)
        try:
            raw.connect((self.address, 443))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            self._api_socket = self.sock
        except BaseException:
            raw.close(); raise


class Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.hidden = 0; self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'noscript', 'template'}: self.hidden += 1
        elif not self.hidden and tag in {'p', 'div', 'br', 'li', 'h1', 'h2', 'h3', 'pre'}: self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript', 'template'}: self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden: self.parts.append(data)


def clean(value):
    return ''.join(c for c in value if c in '\n\t' or 32 <= ord(c) < 127 or ord(c) >= 160)


def fetch(url, hosts, *, connection=PinnedHTTPS, clock=time.monotonic):
    end = clock() + 25
    visited = set()
    for _ in range(4):
        if url in visited: fail('Redirect loop stopped.', 'tool_redirect_denied')
        visited.add(url); parsed, host = public_url(url, hosts); addresses = public_addresses(host)
        remaining = end - clock()
        if remaining <= 0: fail('Public fetch deadline reached.', 'tool_timeout')
        conn = connection(host, addresses[0], min(8, remaining))
        def abort(target=conn):
            sock = getattr(target, '_api_socket', None)
            if sock is not None:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
            target.close()
        timer = threading.Timer(remaining, abort); timer.daemon = True; timer.start()
        try:
            path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
            conn.request('GET', path, headers={'Accept': 'text/html,text/plain,application/json', 'Accept-Encoding': 'identity', 'User-Agent': 'codex-api-harness/0.5'})
            response = conn.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader('Location')
                if not isinstance(location, str): fail('Redirect has no valid destination.', 'tool_redirect_denied')
                url = urllib.parse.urljoin(url, location); continue
            if response.status != 200: fail('Public fetch returned HTTP ' + str(response.status) + '; no retry or fallback.', 'tool_http_error')
            if response.getheader('Content-Encoding', 'identity').lower() not in ('identity', ''): fail('Compressed fetch responses are disabled.', 'tool_content_denied')
            kind = response.getheader('Content-Type', '').split(';')[0].lower().strip()
            if kind not in {'text/html', 'text/plain', 'text/markdown', 'application/json'}: fail('Only bounded text and HTML responses are supported.', 'tool_content_denied')
            raw = bytearray()
            while len(raw) <= MAX_BODY:
                if clock() >= end: fail('Public fetch deadline reached.', 'tool_timeout')
                chunk = response.read1(min(65536, MAX_BODY + 1 - len(raw)))
                if not chunk: break
                raw.extend(chunk)
            if len(raw) > MAX_BODY: fail('Public page exceeds the 1 MiB limit.', 'tool_content_denied')
            text = bytes(raw).decode('utf-8', errors='replace')
            if kind == 'text/html':
                parser = Text(); parser.feed(text); text = ''.join(parser.parts)
            text = clean(text)
            return {'url': url, 'text': text[:MAX_TEXT], 'truncated': len(text) > MAX_TEXT,
                    'untrusted': True, 'external_api_cost': 0}
        except (OSError, http.client.HTTPException): fail('Public fetch could not complete. No automatic retry or alternate service was used.', 'tool_connection_failed')
        finally: timer.cancel(); conn.close()
    fail('Too many redirects. No further request sent.', 'tool_redirect_denied')


def call(broker, payload):
    if not isinstance(payload, dict) or set(payload) != {'name', 'arguments'} or not isinstance(payload['arguments'], dict): fail('Unsupported tool call.', 'tool_arguments_invalid')
    name, arguments = payload['name'], payload['arguments']
    if name == 'status' and arguments == {}:
        with broker.ledger.mutex: return status(broker.root, broker.ledger.db, broker.clock())
    with broker.ledger.mutex: policy = verified(broker.root, broker.ledger.db)
    if name == 'fetch' and set(arguments) == {'url'}: return fetch(arguments['url'], policy['fetch_hosts'])
    if name in {'search', 'extract'} and set(arguments) == {'provider', 'query' if name == 'search' else 'url'}:
        return search(broker, arguments, extract=name == 'extract')
    fail('Unknown tool or argument. Media, arbitrary commands and remote MCP are disabled.', 'tool_arguments_invalid')


def search(broker, payload, *, extract=False):
    with broker.ledger.mutex: return _search(broker,payload,extract=extract)


def _search(broker, payload, *, extract=False):
    from gateway import read_json as response_json
    allowed = {'provider', 'url' if extract else 'query'}
    if not isinstance(payload, dict) or set(payload) != allowed or not isinstance(payload['provider'],str) or payload['provider'] not in PROVIDERS: fail('Unsupported search provider or option.', 'tool_arguments_invalid')
    provider = payload['provider']; policy = verified(broker.root, broker.ledger.db)
    state = status(broker.root, broker.ledger.db, broker.clock())['search'][provider]['state']
    if state != 'ready': fail(provider + ': ' + state + '. No provider request sent; review codex-api tools status.', 'tool_' + state)
    row = policy['search'][provider]
    if extract:
        if provider != 'tavily': fail('Only basic Tavily extraction is supported.', 'tool_arguments_invalid')
        parsed = urllib.parse.urlsplit(payload['url']) if isinstance(payload['url'], str) else None
        public_url(payload['url'], [parsed.hostname] if parsed else [])
        public_addresses(parsed.hostname)
        request = {'urls': [payload['url']], 'extract_depth': 'basic', 'include_images': False, 'include_usage': True}
    else:
        query = payload['query']
        if not isinstance(query, str) or not 1 <= len(query) <= 1000 or SECRET.search(query) or any(ord(c) < 32 for c in query): fail('Query is invalid or contains credential markers.', 'tool_arguments_invalid')
        request = {'query': query}
    keys = search_credentials(broker.root); key = keys.get(PROVIDERS[provider][0])
    if not key: fail(provider + ' key is missing. Use the private search-keys.env file; never paste it into chat.', 'tool_key_missing')
    binding = broker.ledger.db.execute('SELECT digest FROM tool_credentials WHERE provider=?', (provider,)).fetchone()
    if binding != (hashlib.sha256(key.encode()).hexdigest(),): fail('Search credential changed. Review the new account before applying its free evidence.', 'tool_key_changed')
    headers = {'Authorization': 'Bearer ' + key}; method = 'POST'
    if provider == 'tavily':
        broker.tavily_usage(key)
        if not extract: request.update(search_depth='basic', auto_parameters=False, max_results=5, include_answer=False, include_images=False, include_usage=True)
        host, path = 'api.tavily.com', '/extract' if extract else '/search'
    elif provider == 'exa':
        request.update(type='lite', numResults=5, contents={'highlights': True})
        host, path, headers = 'api.exa.ai', '/search', {'x-api-key': key}
    else:
        host, path, headers, method = 'api.search.brave.com', '/res/v1/web/search?' + urllib.parse.urlencode({'q': query, 'count': 5}), {'X-Subscription-Token': key}, 'GET'
    amount = PROVIDERS[provider][1]
    identity = broker.ledger.reserve(provider, row['period'], amount, request)
    if verified(broker.root, broker.ledger.db) != policy: fail('Tool policy changed before dispatch.', 'tool_policy_changed')
    if not row['verified_at'] <= broker.clock() < row['valid_until']: fail('Free evidence expired before dispatch.', 'tool_evidence_expired')
    broker.ledger.dispatch(identity)
    conn, response = broker.transport(host, path, None if method == 'GET' else request, headers, method=method)
    try:
        if response.status!=200:fail(provider+' returned HTTP '+str(response.status)+'. The full tool hold remains; no retry or provider fallback.', 'tool_provider_error')
        result = response_json(response, limit=512000)
    finally: conn.close()
    if not isinstance(result, dict): fail('Search result is invalid; the full reservation remains held.', 'tool_usage_unconfirmed')
    actual = amount
    if provider == 'tavily':
        usage = result.get('usage')
        credits = usage.get('credits') if isinstance(usage, dict) else None
        if type(credits) not in (int, float) or credits not in (0, 1): fail('Search usage is missing or exceeds the hold. Review it before retrying.', 'tool_usage_unconfirmed')
        actual = int(credits)
    elif provider == 'exa':
        costs=result.get('costDollars'); estimate=costs.get('total') if isinstance(costs,dict) else None
        if type(estimate) not in (int,float) or not 0<=estimate<=amount/1000000:fail('Exa cost estimate is missing or exceeds the conservative hold. No further search will be admitted until reviewed.', 'tool_usage_unconfirmed')
    # Exa costDollars is estimated; Brave does not supply authoritative per-call
    # cost. Keep the full reviewed upper debit rather than refunding an estimate.
    broker.ledger.settle(identity, actual)
    return {'provider': provider, 'request_id': identity, 'data': result, 'untrusted': True}


def apply(root, draft, reviewed_digest):
    from maintenance import stopped
    value = validate(read_json(Path(draft), private=True))
    if digest(value) != reviewed_digest: fail('Review the exact current tool policy digest before applying.')
    with stopped(Path(root)):
        if (Path(root)/'team-client.json').exists() or (Path(root)/'team').exists():fail('Search and host fetch configuration is personal-only in this release.', 'tool_shared_disabled')
        ledger = Ledger(Path(root) / 'state')
        try:
            schema(ledger)
            keys = search_credentials(root) if any(value['search'].values()) else {}
            with ledger.transaction():
                for provider, row in value['search'].items():
                    if row is None: continue
                    now = ledger.check_clock()
                    if row['period'] != now.strftime('%Y-%m') or not row['verified_at'] <= now.timestamp() < row['valid_until']: fail('Search evidence must cover the current month and time.')
                    budget = ledger.db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=? AND period=?', (provider, row['period'])).fetchone()
                    if budget and budget != (row['ceiling'], row['baseline']): fail('An existing tool budget cannot be reset or rebased. Preserve its ceiling and baseline.')
                    if not budget: ledger.db.execute('INSERT INTO budgets VALUES (?,?,?,?)', (provider, row['period'], row['ceiling'], row['baseline']))
                    key = keys.get(PROVIDERS[provider][0])
                    if not key: fail(provider + ' credential is missing; no tool enabled.', 'tool_key_missing')
                    previous = ledger.db.execute('SELECT digest FROM tool_credentials WHERE provider=?', (provider,)).fetchone()
                    key_digest = hashlib.sha256(key.encode()).hexdigest()
                    if previous and previous[0] != key_digest and budget:
                        fail('A new search key needs a new installation or a newly verified allowance period; existing budget cannot be rebound.', 'tool_key_changed')
                    ledger.db.execute('INSERT OR REPLACE INTO tool_credentials VALUES (?,?)', (provider, key_digest))
                ledger.db.execute('INSERT OR REPLACE INTO tool_config VALUES (1,?)', (digest(value),))
            # A crash between the witnessed commit and file replacement blocks
            # all tools until this exact draft is reapplied; it never enables one.
            atomic_json(Path(root) / 'tools.json', value)
        finally: ledger.close()
    return {'applied': True, 'model_policy_changed': False, 'provider_requests': 0}


def resolve(root, identity, reference):
    from maintenance import stopped
    if not isinstance(identity,str) or not re.fullmatch(r'[a-f0-9]{32}',identity) or not isinstance(reference,str) or not 3<=len(reference)<=512 or SECRET.search(reference) or any(ord(c)<32 for c in reference):fail('Use the complete request ID and a non-secret reference to its confirmed completion.')
    with stopped(Path(root)):
        ledger=Ledger(Path(root)/'state')
        try:
            with ledger.transaction():
                row=ledger.db.execute('SELECT scope,reserved,phase FROM requests WHERE id=?',(identity,)).fetchone()
                if not row or row[0] not in PROVIDERS:fail('This is not a search request.')
                if row[2]=='settled':return {'resolved':False,'already_settled':True,'refund':0}
                if row[2] not in {'reserved','unknown'}:fail('This tool request has an unsupported recovery state.')
                ledger.db.execute("UPDATE requests SET actual=reserved,phase='settled' WHERE id=?",(identity,))
                fingerprint=digest({'request_id':identity,'held':row[1],'completion_reference':reference})
                ledger.db.execute('INSERT INTO resolutions VALUES (?,?,?,?,?,?,?)',(uuid.uuid4().hex,identity,fingerprint,'confirm_consumed',row[1],hashlib.sha256(reference.encode()).hexdigest(),ledger.clock()))
            return {'resolved':True,'conservative_debit':row[1],'refund':0,'provider_requests':0}
        finally:ledger.close()


def command(root, args):
    parser = argparse.ArgumentParser(prog='codex-api tools')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('status')
    sub.add_parser('template')
    sub.add_parser('credentials')
    check = sub.add_parser('check'); check.add_argument('path', type=Path)
    install = sub.add_parser('apply'); install.add_argument('path', type=Path); install.add_argument('--reviewed-digest', required=True)
    recovery=sub.add_parser('resolve');recovery.add_argument('id');recovery.add_argument('--reviewed-complete',action='store_true',required=True);recovery.add_argument('--reference',required=True)
    options = parser.parse_args(args)
    if options.action == 'resolve':result=resolve(root,options.id,options.reference)
    elif options.action == 'status':
        with readonly_database(Path(root) / 'state') as db: result = status(root, db)
    elif options.action == 'credentials':
        path=Path(root)/'search-keys.env'
        if not path.exists() and not path.is_symlink():
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as output:output.write('# Optional private search keys. Fill only verified providers; never mount or commit.\nTAVILY_API_KEY=\nEXA_API_KEY=\nBRAVE_API_KEY=\n')
        if path.is_symlink() or not path.is_file() or path.stat().st_mode&0o077:fail('The private credential file is unsafe; it was preserved.')
        result={'file':str(path),'contents_read':False,'provider_requests':0}
    elif options.action == 'template':
        path = Path(root) / 'tools.draft.json'
        if path.exists() or path.is_symlink(): fail('The private tool draft already exists; it was preserved.')
        atomic_json(path, load(root)); result = {'draft': str(path), 'next': 'Review fetch hosts and actual free account facts; then use tools check/apply.'}
    elif options.action == 'check':
        value = validate(read_json(options.path, private=True)); result = {'digest': digest(value), 'policy': value, 'provider_requests': 0}
    else: result = apply(root, options.path, options.reviewed_digest)
    print(json.dumps(result, indent=2))
