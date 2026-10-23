"""Dedicated entry point. Never invokes the subscription Codex binary."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

from guard import Denied, atomic_json, read_quota
from policy import load as load_policy, limits as policy_limits, model_pools, verify_guest, PolicyError
from gateway import credentials
from workspace_policy import check_workspace

from settings import ROOT, WORKSPACE, SBX, NAME, PORT


def clean_env():
    return {k: v for k, v in os.environ.items() if k in {"HOME", "PATH", "USER", "LOGNAME", "TMPDIR", "LANG", "TERM"}}


def workspace_check():
    check_workspace(WORKSPACE)


def integrity():
    if (ROOT/'upgrade-pending.json').exists():raise Denied('An interrupted code activation is pending. Run codex-api upgrade recover; no session was started.',code='upgrade_recovery_required')
    manifest = json.loads((ROOT / "installation.json").read_text())
    if manifest.get('layout_version')==2:
        from releases import validate_layout, active_payload
        validate_layout(ROOT)
        if Path(__file__).resolve().parent.parent != active_payload(ROOT):
            raise Denied('The installed code generation changed before this operation. Run the command again.',code='upgrade_recovery_required')
    native_policy=None
    for relative, expected in manifest["files"].items():
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise Denied("Installed file changed: " + relative)
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:raise Denied("Installed file changed: " + relative)
        if relative=='kit/requirements.toml':native_policy=data
    if manifest.get('external_sbx_sha256') and hashlib.sha256(SBX.read_bytes()).hexdigest()!=manifest['external_sbx_sha256']:
        raise Denied('The pinned Docker Sandboxes executable changed; review the runtime update before starting.')
    from extensions import verify_build
    verify_build(ROOT)
    from workspace_policy import validate_managed_requirements, protected_paths
    if native_policy is None:raise Denied('The native filesystem policy is missing from the integrity manifest.',code='protected_paths_invalid')
    validate_managed_requirements(native_policy,WORKSPACE,protected_paths(ROOT))
    return manifest


def blockers():
    issues = []
    if (ROOT/'team').exists() and not (ROOT/'team-client.json').exists():issues.append('This installation owns a shared coordinator. Start a separate joined client instead of an independent personal gateway.')
    try: integrity()
    except Exception: issues.append("Installation integrity has not been verified")
    try: verify_guest(ROOT)
    except (PolicyError,OSError,ValueError) as error:issues.append('Model and quota policy needs configuration or preparation: '+str(error))
    try: workspace_check()
    except Denied as error: issues.append(str(error))
    try:
        if (ROOT/'team-client.json').exists():
            from team_client import RemoteBroker
            RemoteBroker(ROOT)
        else: credentials(ROOT / "openai-key.env")["OPENAI_API_KEY"]
    except Exception: issues.append("The private team connection is invalid" if (ROOT/'team-client.json').exists() else "The restricted OpenAI API key for this installation has not been configured")
    try:
        ready = json.loads((ROOT / "readiness.json").read_text())
        policy = json.loads((ROOT / "verification.json").read_text()).get("openai", {}).get("billing_policy", "free_only")
        for key, message in {
            "docker_authenticated": "Docker Sandboxes login is incomplete",
            "image_built": "The dedicated Codex/Playwright image has not been built",
            "filesystem_tested": "Sandbox filesystem isolation has not been tested",
            "network_tested": "Sandbox outbound network restrictions have not been tested",
            "host_integrations_absent": "Isolation from host credentials, SSH, browsers, and MCP has not been tested",
            "codex_protocol_tested": "Codex local tools and gateway round trips have not been tested",
            "openai_free_verified": "OpenAI token-count pricing, local-tool eligibility, and remaining organization quota are not fully verified",
        }.items():
            if key == "openai_free_verified": continue  # Provider eligibility gates requests, not opening the CLI.
            if ready.get(key) is not True: issues.append(message)
    except Exception: issues.append("Startup verification records are missing")
    if (ROOT/'settings.json').is_file():
        try:
            from provision import host_issues
            issues.extend(host_issues())
        except Exception: issues.append('Current Docker host and network policy could not be verified')
    return issues


def process_identity(pid):
    response = subprocess.run(["/bin/ps", "-ww", "-p", str(pid), "-o", "lstart=", "-o", "command="], capture_output=True, text=True)
    return response.stdout.strip() if response.returncode == 0 else None


def sandbox_inventory():
    response = subprocess.run([str(SBX), 'ls', '--json'], capture_output=True, text=True, env=clean_env(), check=True)
    listing = json.loads(response.stdout)
    rows = listing if isinstance(listing,list) else listing.get('sandboxes')
    if not isinstance(rows,list): raise Denied('Cannot verify sandbox inventory')
    return rows


def owned_sandbox():
    marker = ROOT / 'sandbox-created.json'
    if not marker.exists(): return None
    record = json.loads(marker.read_text())
    if record.get('name') != NAME or not record.get('id'): raise Denied('Sandbox ownership identity is missing')
    rows = [row for row in sandbox_inventory() if row.get('name') == NAME]
    if not rows: return None
    row = rows[0]
    if row.get('id') != record['id'] or row.get('workspaces') != [str(WORKSPACE)]:
        raise Denied('Sandbox identity changed; refusing to control a different environment')
    return row


def stop():
    (ROOT / "paused").touch(mode=0o600, exist_ok=True)
    marker = ROOT / "gateway-process.json"
    if marker.exists():
        record = json.loads(marker.read_text())
        pid, identity = record["pid"], record["identity"]
        if process_identity(pid) == identity and "gateway" in identity:
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 10
            while process_identity(pid) == identity and time.monotonic() < deadline: time.sleep(0.1)
            if process_identity(pid) == identity: raise Denied("The gateway is waiting for an active request to finish. New requests are blocked; retry codex-api stop shortly.")
        elif process_identity(pid) is not None:
            raise Denied("The PID belongs to another process. New requests are blocked; the other process was left running.")
        marker.unlink(missing_ok=True)
    owned = ROOT / "sandbox-created.json"
    if owned.exists():
        if owned_sandbox() is not None:
            subprocess.run([str(SBX), "stop", NAME], env=clean_env(), check=True, capture_output=True, text=True)


def quota_snapshot():
    if (ROOT/'team-client.json').exists():
        from team_client import RemoteBroker
        return RemoteBroker(ROOT).quota()
    profile = json.loads((ROOT/'verification.json').read_text()).get('openai', {})
    if profile.get('quota_guard') is not True:
        raise Denied('Daily quota protection is not enabled; run codex-api doctor.', code='quota_state_unavailable')
    p=load_policy(ROOT)
    result = read_quota(ROOT/'state', policy_limits(p),policy=p)
    result['billing_policy'] = profile.get('billing_policy', 'free_only')
    return result


def runtime_state():
    marker = ROOT/'gateway-process.json'
    if not marker.exists(): return 'stopped' if (ROOT/'paused').exists() else 'stale'
    try:
        record = json.loads(marker.read_text())
        identity = process_identity(record['pid'])
        if identity is None: return 'stale'
        if identity != record['identity'] or 'gateway' not in identity: return 'foreign_process'
        client = http.client.HTTPConnection('127.0.0.1', PORT, timeout=.4)
        try:
            client.request('GET', '/health')
            response = client.getresponse()
            health = json.loads(response.read(4096))
            if response.status != 200 or health.get('pid') != record['pid']: return 'unresponsive'
        finally: client.close()
        return 'stopping' if (ROOT/'paused').exists() else 'running'
    except (OSError, ValueError, KeyError, http.client.HTTPException): return 'unresponsive'


def subscription_unchanged():
    # Configuration only. Never read subscription auth.json or keychain state.
    original = json.loads((ROOT/'installation.json').read_text()).get('subscription_config_sha256')
    path = Path.home()/'.codex/config.toml'
    if path.is_symlink(): return False
    current = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return current == original


def status(as_json=False, usage_only=False):
    if usage_only:
        result = quota_snapshot()
        print(json.dumps(result, ensure_ascii=False, indent=2) if as_json else '\n'.join(result['usage_lines']))
        return result
    result = {'mode':runtime_state(), 'startup_blockers':blockers()}
    try: result.update(quota_snapshot())
    except (Denied, OSError, ValueError) as error:
        result['quota_error'] = getattr(error, 'code', None) or 'quota_state_unavailable'
        result['daily_pools'] = {}
    result['subscription_config_unchanged'] = subscription_unchanged()
    last = ROOT/'last-error.json'
    if last.exists(): result['last_error'] = json.loads(last.read_text())
    if as_json: print(json.dumps(result, ensure_ascii=False, indent=2)); return result
    print('API Codex: '+result['mode'])
    print('Billing policy: '+result.get('billing_policy','unavailable')+'; token budgets do not prove free eligibility.')
    print('Request quota protection: '+('enabled; resets daily at 00:00 UTC' if result.get('quota_guard') else 'unavailable'))
    for line in result.get('usage_lines', []): print(line)
    print(f"Recorded requests: {result.get('recorded_requests',0)}; unresolved: {result.get('unresolved_requests',0)}.")
    print('Subscription configuration: '+('unchanged' if result['subscription_config_unchanged'] else 'differs from the installation baseline'))
    for item in result['startup_blockers']: print('Startup check: '+item)
    if result.get('quota_error'): print('Quota: ['+result['quota_error']+'] Run codex-api doctor.')
    if 'last_error' in result: print('Last error (historical): ['+result['last_error']['code']+'] '+result['last_error']['message'])
    return result


def doctor(as_json=False, bundle=False):
    checks = []
    def check(name, callback, code):
        try:
            value = callback()
            if value is False: raise ValueError()
            checks.append({'check':name, 'status':'PASS'})
        except Exception:
            checks.append({'check':name, 'status':'FAIL', 'code':code})
    check('Installation integrity', integrity, 'integrity_failed')
    check('Workspace policy', workspace_check, 'workspace_policy_failed')
    if (ROOT/'team-client.json').exists():
        from team_client import RemoteBroker
        check('Private team connection', lambda:RemoteBroker(ROOT).quota(), 'team_unavailable')
    else:check('Dedicated API key file', lambda: bool(credentials(ROOT/'openai-key.env').get('OPENAI_API_KEY')), 'invalid_api_key')
    check('Owner and guest policy',lambda:verify_guest(ROOT),'policy_invalid')
    check('Quota ledger and limits', quota_snapshot, 'quota_state_unavailable')
    check('Subscription configuration unchanged', subscription_unchanged, 'subscription_config_changed')
    mode = runtime_state()
    checks.append({'check':'Gateway lifecycle', 'status':'PASS' if mode in {'running','stopped'} else 'FAIL', 'state':mode})
    ready = json.loads((ROOT/'readiness.json').read_text()) if (ROOT/'readiness.json').is_file() else {}
    checks.append({'check':'Saved isolation acceptance', 'status':'PASS' if all(ready.get(k) is True for k in ('filesystem_tested','network_tested','host_integrations_absent')) else 'FAIL', 'scope':'saved test results; not a live sandbox penetration test'})
    verification = json.loads((ROOT/'verification.json').read_text()).get('openai', {})
    if not (ROOT/'team-client.json').exists():checks.append({'check':'Provider free eligibility', 'status':'PASS' if all(verification.get(k) is True for k in ('count_endpoint_free_confirmed','local_tool_inference_free_confirmed')) else 'WARN', 'code':'free_eligibility_unconfirmed'})
    try:
        quota = quota_snapshot()
        if quota['unresolved_requests']: checks.append({'check':'Unconfirmed usage', 'status':'WARN', 'code':'quota_reconciliation_required', 'count':quota['unresolved_requests']})
        if quota['safety_stop']: checks.append({'check':'Usage safety stop', 'status':'FAIL', 'code':'usage_above_reservation'})
    except (Denied, OSError, ValueError): pass
    result = {'version':1, 'checks':checks, 'passed':not any(c['status']=='FAIL' for c in checks), 'provider_requests':0, 'redacted':True}
    if bundle:
        destination = ROOT/'diagnostics'/('doctor-'+time.strftime('%Y%m%dT%H%M%S', time.gmtime())+'.json')
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        atomic_json(destination, result)
    if as_json: print(json.dumps(result, indent=2))
    else:
        for item in checks:
            suffix = ' ['+item['code']+']' if item.get('code') else ' ('+item['state']+')' if item.get('state') else ''
            print(item['status']+' '+item['check']+suffix)
        print('No provider requests were made. Use codex-api explain CODE for guidance.')
    if bundle: print('Diagnostic bundle: '+str(destination), file=sys.stderr if as_json else sys.stdout)
    return result


def explain(code=None, as_json=False):
    from diagnostics import explanation
    if code == 'permissions':
        p=load_policy(ROOT)
        result = {'workspace':str(WORKSPACE), 'models':list(p['models']), 'service_tier':p['defaults']['service_tier'],
                  'host_credentials':'not mounted; real API keys stay on host', 'network':'local gateway; GET/HEAD only on registry.npmjs.org:443, pypi.org:443, files.pythonhosted.org:443',
                  'managed_hooks':'fixed local quota notices only; user, project and plugin hooks are skipped',
                  'sensitive_files':'native process-start read masks plus host checks before each model request; no project copy',
                  'disabled':['OpenAI hosted tools','media generation','audio','subscription login','unreviewed host plugins and skills'],
                  'extensions':'reviewed immutable skill snapshots; native plugins, MCP and plugin hooks stay disabled',
                  'shared_mode':'optional authoritative coordinator over host-side SSH; no local fallback',
                  'preferences':'allowlisted private model, reasoning, and UI choices only'}
    else:
        if code is None:
            path = ROOT/'last-error.json'
            if not path.is_file(): print('No saved error. Use codex-api explain permissions or codex-api doctor.'); return {}
            code = json.loads(path.read_text()).get('code', 'local_policy_rejected')
        import re
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,96}', code): raise Denied('Invalid error code')
        result = explanation(code)
    if as_json: print(json.dumps(result, indent=2))
    else:
        for key, value in result.items(): print(key.replace('_',' ').capitalize()+': '+(', '.join(value) if isinstance(value,list) else str(value)))
    return result


def prepare(configure_host=False):
    from provision import prepare as provision
    provision(configure_host=configure_host)


def start(agent_args=()):
    with (ROOT/'session.lock').open('a+b') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('An API Codex session is already running. Return to its terminal; the existing session remains active.')
        return _start(agent_args)


def _start(agent_args=()):
    issues = blockers()
    if issues: raise Denied("Startup blocked:\n- " + "\n- ".join(issues))
    if owned_sandbox() is None: raise Denied('The dedicated sandbox is missing; model requests remain disabled.')
    previous=signal.getsignal(signal.SIGINT)
    state={'attaching':True,'cancel_start':False}
    def interrupt(*_):
        if state['attaching']:state['cancel_start']=True
    signal.signal(signal.SIGINT,interrupt)
    child=None
    try:
        (ROOT / "paused").unlink(missing_ok=True)
        code = "import sys;sys.path.insert(0," + repr(str((ROOT / "app").resolve())) + ");from gateway import serve;serve()"
        with (ROOT / "gateway.log").open("ab") as log:
            child = subprocess.Popen([sys.executable, "-I", "-c", code], env=clean_env(), stdout=log, stderr=log, start_new_session=True)
        time.sleep(0.3)
        identity = process_identity(child.pid)
        if not identity or child.poll() is not None:raise Denied("The gateway failed to start; model requests remain disabled.")
        atomic_json(ROOT / "gateway-process.json", {"pid": child.pid, "identity": identity})
        if state['cancel_start']:raise KeyboardInterrupt()
        prefix=([str(SBX),'exec',NAME,'/usr/local/bin/codex-api-entrypoint']
                if any(a in {'exec','e','review','--version','-V','--help','-h'} for a in agent_args)
                else [str(SBX),'run','--name',NAME,'--'])
        launch = [*prefix, "--no-daemon", "-c", 'model_providers.quota_gateway.name="API Codex — isolated API gateway"',
                  "-c", 'skills.config=[{path="/home/agent/.codex-api/skills/.system/imagegen/SKILL.md",enabled=false}]', *agent_args]
        # Native Codex owns Ctrl+C once attached; a turn cancellation must not
        # tear down the sandbox. All startup paths still run the cleanup below.
        state['attaching']=False
        if sys.stdout.isatty() and not any(a in agent_args for a in ('exec','--help','-h','--version','-V')):
            print('API Codex | Ctrl+C cancels a task; when idle, Ctrl+C or /quit exits and stops the dedicated environment.',flush=True)
        completed=subprocess.run(launch,env=clean_env())
        if any(a in {'exec','e','review'} for a in agent_args):show_noninteractive_notices()
        if completed.returncode not in (0,130,-signal.SIGINT):raise Denied('API Codex exited with status '+str(completed.returncode)+'. See the preceding CLI message; the dedicated environment was stopped.')
    finally:
        try:
            if (ROOT/'gateway-process.json').exists():stop()
            else:
                (ROOT/'paused').touch(mode=0o600,exist_ok=True)
                if child is not None and child.poll() is None:
                    child.terminate();child.wait(timeout=5)
        finally:
            signal.signal(signal.SIGINT,previous)
    if sys.stdout.isatty() and not any(a in agent_args for a in ('exec','--help','-h','--version','-V')):
        print('API session closed. Resume this isolated environment with: codex-api resume --last',flush=True)


def show_noninteractive_notices():
    """Keep automation stdout valid JSON; informational warnings use stderr."""
    try:
        token=(ROOT/'gateway.token').read_text().strip()
        conn=http.client.HTTPConnection('127.0.0.1',PORT,timeout=.6)
        try:
            conn.request('POST','/v1/notices/claim',body='{}',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            response=conn.getresponse();data=response.read(16385)
            if response.status!=200 or len(data)>16384:return
            notices=json.loads(data).get('notices',[])
            if not isinstance(notices,list) or len(notices)>8:return
            messages=[n.get('message') for n in notices if isinstance(n,dict)]
            if len(messages)!=len(notices) or not all(isinstance(m,str) and m.isascii() and m.startswith('API quota warning - Group ') and len(m)<=512 and not any(ord(c)<32 for c in m) for m in messages):return
            for message in messages:print(message,file=sys.stderr,flush=True)
        finally:conn.close()
    except (OSError,ValueError,TypeError,AttributeError,http.client.HTTPException):pass


def reset(_lease=None):
    if _lease is None:
        with (ROOT/'session.lock').open('a+b') as lease:
            try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Denied('Exit the active API session before removing its sandbox. The running session was left unchanged.')
            return reset(_lease=lease)
    stop()
    marker = ROOT / "sandbox-created.json"
    if marker.exists():
        if owned_sandbox() is not None:
            subprocess.run([str(SBX), "rm", NAME, "--force"], env=clean_env(), check=True)
        marker.unlink()
    ready = json.loads((ROOT / "readiness.json").read_text())
    for key in ready: ready[key] = False
    atomic_json(ROOT / "readiness.json", ready)
    print("Dedicated sandbox removed. Project files, credentials, and the usage ledger were preserved.")


def retire():
    with (ROOT/'session.lock').open('a+b') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('Exit the active API session before archiving it. The running session was left unchanged.')
        integrity()
        reset(_lease=lease)
        # The builder, daemon and global policies may belong to other users of SBX.
        # Never prune them or call global reset, logout, or daemon stop here.
        destination=ROOT.with_name(ROOT.name+'-disabled-'+time.strftime('%Y%m%d-%H%M%S',time.gmtime()))
        if destination.exists(): raise Denied('The archive destination already exists.')
        ROOT.rename(destination)
        print('Dedicated environment disabled and archived. Project files and subscription configuration are unchanged. Credentials and usage ledger: '+str(destination))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["status", "usage", "doctor", "explain", "reconcile", "help", "start", "pause", "stop", "login", "prepare", "reset", "retire", "configure", "credentials", "billing", "policy", "team", "extensions", "protect", "upgrade"])
    parser.add_argument("agent_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    # Pre-0.3 launchers route unknown words through start; retain that launcher
    # verbatim while recognizing the new owner-only policy command here.
    if args.command=='start' and args.agent_args[:1]==['policy']:args.command='policy';args.agent_args=args.agent_args[1:]
    if args.agent_args and args.command not in {'start','doctor','explain','reconcile','configure','prepare','billing','policy','credentials','team','extensions','protect','upgrade'} and not (args.command in {'status','usage'} and args.agent_args==['--json']): parser.error("This maintenance command does not accept these arguments")
    try:
        if (ROOT/'policy-pending.json').exists() and args.command not in {'policy','status','usage','doctor','explain','stop','pause','help'}:raise Denied('Repeat the original reviewed policy apply before changing this installation.',code='policy_change_pending')
        if (ROOT/'upgrade-pending.json').exists() and args.command not in {'upgrade','status','usage','doctor','explain','stop','pause','help'}:
            raise Denied('Complete codex-api upgrade recover before changing this installation.',code='upgrade_recovery_required')
        if args.command in {'status','usage'}: status(as_json=args.agent_args==['--json'],usage_only=args.command=='usage')
        elif args.command=='doctor':
            if len(args.agent_args)!=len(set(args.agent_args)) or set(args.agent_args)-{'--json','--bundle'}: parser.error('doctor accepts --json and --bundle')
            return 0 if doctor(as_json='--json' in args.agent_args,bundle='--bundle' in args.agent_args)['passed'] else 1
        elif args.command=='explain':
            rest=[a for a in args.agent_args if a!='--json']
            if len(rest)>1 or args.agent_args.count('--json')>1:parser.error('explain accepts one error code or permissions, plus --json')
            explain(rest[0] if rest else None,as_json='--json' in args.agent_args)
        elif args.command=='reconcile':
            from recovery import command
            command(ROOT,args.agent_args)
        elif args.command=='configure':
            from onboarding import command
            command(ROOT,args.agent_args)
        elif args.command=='credentials':
            if args.agent_args:
                from maintenance import rotation
                rotation(ROOT,args.agent_args)
            else:
                from onboarding import credentials_location
                credentials_location(ROOT)
        elif args.command=='team':
            if args.agent_args[:1]==['join']:
                from team_client import command
                command(ROOT,args.agent_args[1:])
            elif args.agent_args==['keygen']:
                from team_client import keygen
                keygen(ROOT)
            elif args.agent_args[:1]==['request']:
                request_parser=argparse.ArgumentParser(prog='codex-api team request')
                request_parser.add_argument('--group',required=True)
                request_parser.add_argument('--tokens',type=int,required=True)
                request=request_parser.parse_args(args.agent_args[1:])
                from team_client import RemoteBroker
                import uuid
                result=RemoteBroker(ROOT).request_more({'group':request.group,'amount':request.tokens,'request_id':uuid.uuid4().hex})
                print('Quota request '+result['request_id']+': '+result['state']+'. The owner can review it with codex-api team requests.')
            else:
                from shared import command
                command(ROOT,args.agent_args)
        elif args.command=='extensions':
            from extensions import command
            result=command(ROOT,args.agent_args)
            if isinstance(result,dict) and result.get('changed'):prepare()
        elif args.command=='protect':
            from maintenance import protect
            if protect(ROOT,args.agent_args):prepare()
        elif args.command=='upgrade':
            from releases import command
            result=command(ROOT,args.agent_args,announce_prepare=False)
            # Invoke the active generation in a new process, never keep executing
            # the previously imported code after a pointer switch.
            if isinstance(result,dict) and result.get('native_prepare_required'):
                print('Code selected. Preparing and checking the dedicated API sandbox.',flush=True)
                wrapper=ROOT/'bin/codex-api'
                completed=subprocess.run([str(wrapper),'prepare'],env=clean_env())
                if completed.returncode:
                    print('Sandbox preparation failed. Requests remain blocked. Run codex-api prepare to retry.',file=sys.stderr,flush=True)
                else:print('API sandbox ready. Run codex-api to continue.',flush=True)
                return completed.returncode
        elif args.command=='policy':
            from configuration import command
            if command(ROOT,args.agent_args):
                configured=json.loads((ROOT/'verification.json').read_text()).get('openai',{}).get('account_configured')
                if configured or (ROOT/'sandbox-created.json').exists():prepare()
                else:print('Policy selected. Continue account configuration or coordinator setup before preparing a client sandbox.')
        elif args.command=='billing':
            from onboarding import billing
            billing(ROOT,args.agent_args)
        elif args.command=='help':print('Start: codex-api [Codex arguments or subcommand]\nExamples: codex-api -m gpt-6.1-sol; codex-api resume --last\nDaily usage: codex-api usage (also available as !codex-api usage inside the CLI)\nDiagnostics: codex-api doctor; codex-api explain CODE; codex-api explain permissions\nUsage recovery: codex-api reconcile (read-only by default)\nDetails: codex-api status\nExit: Ctrl+C when idle or /quit; cleanup is automatic\nBackup stop: codex-api stop (from another terminal or after the original terminal closes)')
        elif args.command == "pause": (ROOT / "paused").touch(mode=0o600, exist_ok=True); print("New requests are blocked. Usage from requests already sent will still be recorded.")
        elif args.command == "stop": stop(); print("Dedicated environment stopped.")
        elif args.command == "login": subprocess.run([str(SBX), "login"], env=clean_env(), check=True)
        elif args.command == "prepare":
            if args.agent_args not in ([],['--configure-sandbox-host']):parser.error('prepare accepts only --configure-sandbox-host')
            prepare(configure_host=bool(args.agent_args))
        elif args.command == "reset": reset()
        elif args.command == "retire": retire()
        elif args.command == "start": start(args.agent_args)
    except KeyboardInterrupt:
        print('API Codex exited.',file=sys.stderr);return 130
    except subprocess.CalledProcessError as error:
        print("API Codex: a sandbox operation failed (status "+str(error.returncode)+"). No provider fallback was used.", file=sys.stderr)
        return 1
    except Denied as error:
        print(('API Codex: ['+error.code+'] ' if error.code else '')+str(error), file=sys.stderr)
        return 1
    except PolicyError as error:
        print('API Codex policy: '+str(error)+' Run codex-api policy show or follow SETUP.md; no request was sent.',file=sys.stderr);return 1
    except (OSError, ValueError, KeyError, sqlite3.Error):
        print('API Codex: local state is unavailable. Run codex-api doctor; no usage was reset.',file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__": raise SystemExit(main())
