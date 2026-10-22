"""Build and verify one owned sandbox. Never reset global policy or other VMs."""
import datetime as dt
import fcntl
from email.utils import formatdate
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

from guard import Denied, Ledger, atomic_json, canonical
from settings import ROOT, WORKSPACE, SBX, NAME, PORT

PACKAGE_HOSTS={'registry.npmjs.org:443','pypi.org:443','files.pythonhosted.org:443'}
HOST_SETTINGS={'browser.enabled':False,'ssh.agentForwardingEnabled':False,'clipboard.imagePaste':False}


def call(args,*,capture=True,timeout=45,env=None,**kwargs):
    from controller import clean_env
    r=subprocess.run([str(SBX),*args],env=env or clean_env(),text=True,
                     capture_output=capture,timeout=timeout,**kwargs)
    if r.returncode:
        raise Denied('A Docker Sandboxes operation failed (status '+str(r.returncode)+'). Check Docker login and the preceding build output. No account or usage state was reset.')
    return r


def policy_issues(policy,name=NAME):
    """Reject broad inherited access; never assume a kit overrides global allows."""
    rules=policy.get('rules')
    if not isinstance(rules,list):return ['Network policy could not be inspected.']
    issues=[]
    if not any(r.get('id')=='default-deny-all' for r in rules):issues.append('Docker Sandboxes must use the Locked Down preset.')
    for r in rules:
        if r.get('resource_type') not in {'network','http'} or r.get('decision')!='allow' or r.get('status')=='inactive':continue
        scope=r.get('scope')
        if scope not in {'global','sandbox:'+name}:continue
        resources=set(r.get('resources',[]))
        if scope=='global':issues.append('A global network allowance would widen this sandbox. Existing rules were not modified.');continue
        if r.get('resource_type')=='network':
            if resources!={'localhost:'+str(PORT)}:issues.append('The sandbox has an unreviewed network allowance.')
        elif not resources or not resources<=PACKAGE_HOSTS or set(r.get('methods',[]))!={'GET','HEAD'}:
            issues.append('The sandbox has an unreviewed HTTP allowance.')
    if policy.get('governance') not in (None,False,'none','local','unmanaged',{}):
        issues.append('Organization-managed Docker policy requires separate review.')
    return sorted(set(issues))


def host_issues():
    issues=[]
    for name,expected in HOST_SETTINGS.items():
        value=call(['settings','get',name]).stdout.strip()
        if value!=str(expected).lower():issues.append('Docker host setting '+name+' must be '+str(expected).lower()+'.')
    catalog=json.loads(call(['mcp','ls','--json']).stdout)
    if catalog!=[]:issues.append('The shared Docker MCP catalog is not empty. Existing MCP registrations were left unchanged.')
    policy=json.loads(call(['policy','ls','--json']).stdout)
    issues+=policy_issues(policy)
    return issues


def configure_fresh_host():
    from controller import sandbox_inventory
    if sandbox_inventory():raise Denied('Other sandboxes exist. Global settings were left unchanged; review host isolation settings before proceeding.')
    policy=json.loads(call(['policy','ls','--json']).stdout)
    if any(r.get('scope')=='global' and not str(r.get('id','')).startswith('default-') for r in policy.get('rules',[])):
        raise Denied('Custom global policy exists. It was left unchanged; this is not a fresh sandbox host.')
    # Explicit opt-in only, and only before this daemon owns any sandbox.
    for key,value in HOST_SETTINGS.items():call(['settings','set',key,str(value).lower()])
    call(['policy','init','deny-all'])
    call(['daemon','restart'],timeout=90)


def acceptance():
    """Native filesystem, network, and real CLI replay with an offline fake model."""
    import gateway
    from controller import clean_env
    token=(ROOT/'gateway.token').read_text().strip()
    report={'real_provider_requests':0}
    with tempfile.TemporaryDirectory(prefix='.codex-api-check-',dir=WORKSPACE) as temporary:
        project=Path(temporary);(project/'.env').write_text('PUBLIC_TEST_SENTINEL_ONLY')
        (project/'.env.example').write_text('API_KEY=your_api_key\n')
        code='''import json,os,subprocess,sys;from pathlib import Path
p=Path(sys.argv[1]);out={}
try:(p/".env").read_bytes();out["sensitive_file_denied"]=False
except OSError:out["sensitive_file_denied"]=True
out["safe_template_readable"]="your_api_key" in (p/".env.example").read_text()
(p/"write-through.txt").write_text("PUBLIC_WRITE_TEST")
out["upstream_credentials_absent"]=not any(os.environ.get(k) for k in ("OPENAI_API_KEY","GH_TOKEN","GITHUB_TOKEN","SSH_AUTH_SOCK","TAVILY_API_KEY","EXA_API_KEY","BRAVE_SEARCH_API_KEY","DOCKER_PAT"))
out["subscription_not_mounted"]=not Path(sys.argv[2]).exists()
out["private_install_not_mounted"]=not Path(sys.argv[3]).exists()
out["codex_pinned"]="0.162.1" in subprocess.check_output(["codex","--version"],text=True)
out["playwright_pinned"]="0.1.22" in subprocess.check_output(["playwright-cli","--version"],text=True)
out["network"]={}
for url,method,expected in [("https://api.openai.com/v1/models","GET",False),("https://github.com","GET",False),("https://example.com","GET",False),("https://registry.npmjs.org/is-number","GET",True),("https://pypi.org/simple/idna/","GET",True),("https://registry.npmjs.org/-/npm/v1/security/audits/quick","POST",False)]:
 r=subprocess.run(["curl","-sS","--max-time","8","-o","/dev/null","-w","%{http_code}","-X",method,url],capture_output=True,text=True)
 allowed=r.returncode==0 and r.stdout.strip().startswith("2")
 blocked=r.returncode!=0 or r.stdout.strip() in {"000","403","407"}
 out["network"][method+" "+url]=allowed if expected else blocked
print(json.dumps(out))'''
        args=['exec',NAME,'/usr/local/bin/codex-api-entrypoint','sandbox','-P','codex_api_workspace',
              '--include-managed-config','-C',str(project),'--','python3','-I','-c',code,
              str(project),str(Path.home()/'.codex'),str(ROOT)]
        r=call(args,timeout=150);native=json.loads(r.stdout)
        native['direct_write_sync']=(project/'write-through.txt').read_text()=='PUBLIC_WRITE_TEST'
        if not all(v if isinstance(v,bool) else all(v.values()) for v in native.values()):
            raise Denied('Sandbox isolation acceptance failed. Providers remain disabled; no model request was made.')
        report['native']=native
    with tempfile.TemporaryDirectory(prefix='offline-check-',dir=ROOT) as temporary:
        root=Path(temporary);(root/'gateway.token').write_text(token);(root/'openai-key.env').write_text('OPENAI_API_KEY=fake-offline-key\n');(root/'openai-key.env').chmod(0o600)
        now=time.time()
        atomic_json(root/'verification.json',{'openai':{'enabled':True,'billing_policy':'metered','project_id':'fake-project','organization_id':'fake-org','quota_guard':True,'org_exclusive':True,'daily_token_limits':{'A':100000,'B':1000000},'output_token_cap':16384}})
        ledger=Ledger(root/'state',initialize=True);ledger.pause(False)
        calls=[];outputs=[]
        class Connection:
            def close(self):pass
        class Response(io.BytesIO):
            status=200
            def __init__(self,data,content_type):super().__init__(data);self.content_type=content_type
            def getheader(self,name,default=''):
                if name.lower()=='date':return formatdate(time.time(),usegmt=True)
                return self.content_type if name.lower()=='content-type' else default
        def transport(host,path,body,headers):
            calls.append(path)
            if path.endswith('input_tokens'):return Connection(),Response(b'{"input_tokens":100}','application/json')
            if path!='/v1/responses':raise RuntimeError('Unexpected offline test route')
            index=calls.count('/v1/responses')
            if index==1:
                command='python3 -c "print(42)"'
                script='text(await tools.exec_command('+json.dumps({'cmd':command,'workdir':str(WORKSPACE),'max_output_tokens':100})+'));'
                item={'type':'response.output_item.done','item':{'type':'custom_tool_call','name':'exec','namespace':'functions','call_id':'offline-public-check','input':script}}
            else:
                replay=[x.get('output') for x in body.get('input',[]) if x.get('type')=='custom_tool_call_output']
                outputs.append('42' in json.dumps(replay))
                item={'type':'response.output_item.done','item':{'id':'offline-message','type':'message','role':'assistant','content':[{'type':'output_text','text':'HARNESS_OFFLINE_PASS'}]}}
            events=[{'type':'response.created','response':{'id':'offline-response'}},item,{'type':'response.completed','response':{'id':'offline-response','usage':{'input_tokens':100,'output_tokens':10,'total_tokens':110}}}]
            return Connection(),Response(b''.join(b'data: '+json.dumps(e).encode()+b'\n\n' for e in events),'text/event-stream')
        server=gateway.make_server(root,ledger,port=PORT,transport=transport)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            r=call(['exec',NAME,'/usr/local/bin/codex-api-entrypoint','--no-daemon','-m','gpt-5.6-terra','exec','--ephemeral','--skip-git-repo-check','--json',
                    'Offline installation check. Use the provided local tool, then answer.'],timeout=100)
            report['offline_protocol']=r.returncode==0 and 'HARNESS_OFFLINE_PASS' in r.stdout and any(outputs) and ledger.status()['unresolved']==0
            if not report['offline_protocol']:raise Denied('Offline CLI protocol acceptance failed. No provider was called.')
        finally:server.shutdown();server.server_close();thread.join();ledger.close()
    report['passed']=True
    return report


def prepare(configure_host=False):
    from controller import clean_env, integrity, owned_sandbox, sandbox_inventory, workspace_check
    with (ROOT/'session.lock').open('a+b') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('Exit the API session before preparing its sandbox.')
        installation = integrity();workspace_check()
        from extensions import verify_build
        verify_build(ROOT)
        kit_digest=hashlib.sha256(canonical({path:digest for path,digest in installation['files'].items() if path.startswith('kit/')})).hexdigest()
        if not (ROOT/'paused').exists() or (ROOT/'gateway-process.json').exists():raise Denied('Stop the API environment before preparing it.')
        if configure_host:configure_fresh_host()
        issues=host_issues()
        if issues:raise Denied('Setup stopped:\n- '+'\n- '.join(issues)+'\nOn a fresh dedicated Docker Sandboxes installation, use codex-api prepare --configure-sandbox-host. This changes global Docker settings; existing sandboxes are never reset.')
        if (ROOT/'sandbox-created.json').exists():
            if owned_sandbox() is None:raise Denied('The owned sandbox is missing. Run codex-api reset before preparing again; usage is preserved.')
            marker=json.loads((ROOT/'sandbox-created.json').read_text())
            if marker.get('kit_digest')!=kit_digest:
                # Verify ownership before removing exactly this stopped VM.
                # Ledger/key/project live on the host and are never recreated.
                # An explicitly failed create never became a ready API guest;
                # its image may not contain Python at all. Keep any original
                # pending backup rather than trying to export that partial VM.
                # Missing legacy metadata still requires a full capture.
                if marker.get('build_completed') is not False:
                    from session_state import capture
                    capture(ROOT,SBX,NAME,marker['id'],env=clean_env())
                print('Applying reviewed policy changes to the owned sandbox. Private session history and preferences are preserved automatically.',flush=True)
                call(['rm',NAME,'--force'])
                (ROOT/'sandbox-created.json').unlink()
                ready=json.loads((ROOT/'readiness.json').read_text())
                for key in ('image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested'):ready[key]=False
                atomic_json(ROOT/'readiness.json',ready)
        if not (ROOT/'sandbox-created.json').exists():
            if any(r.get('name')==NAME for r in sandbox_inventory()):raise Denied('Sandbox name already exists without ownership proof. It was not changed.')
            token=(ROOT/'gateway.token').read_text().strip()
            env=clean_env();env.update(CODEX_GATEWAY_TOKEN=token,SBX_KIT_BUILDER='sandbox')
            args=['create','--name',NAME,'--skills','off','--cpus','4','--memory','6g','--env','CODEX_GATEWAY_TOKEN']
            for host in ('openai.com','**.openai.com','chatgpt.com','**.chatgpt.com','github.com','**.github.com','githubusercontent.com','**.githubusercontent.com','api.tavily.com','api.exa.ai','api.search.brave.com'):
                args+=['--deny-network',host]
            args+=[str(ROOT/'kit'),str(WORKSPACE)]
            print('Building the isolated environment. The first build downloads pinned tools; no model request is made.',flush=True)
            build_completed=False
            try:
                call(args,capture=False,timeout=3600,env=env)
                build_completed=True
            finally:
                rows=[r for r in sandbox_inventory() if r.get('name')==NAME]
                if len(rows)==1 and rows[0].get('id') and rows[0].get('workspaces')==[str(WORKSPACE)]:
                    atomic_json(ROOT/'sandbox-created.json',{'name':NAME,'id':rows[0]['id'],'workspace':str(WORKSPACE),'created':time.time(),
                                'kit_digest':kit_digest if build_completed else None,'build_completed':build_completed})
            if owned_sandbox() is None:raise Denied('Sandbox ownership could not be verified.')
        try:
            from session_state import restore, complete
            current=owned_sandbox()
            if current is None:raise Denied('Sandbox ownership could not be verified before restoring private history.')
            restore(ROOT,SBX,NAME,current['id'],env=clean_env())
            issues=host_issues()
            if issues:raise Denied('Runtime policy acceptance failed. '+' '.join(issues))
            report=acceptance()
            atomic_json(ROOT/'runtime-acceptance.json',report)
            ready=json.loads((ROOT/'readiness.json').read_text())
            for key in ('docker_authenticated','image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested'):ready[key]=True
            complete(ROOT,current['id'])
            atomic_json(ROOT/'readiness.json',ready)
            print('Sandbox ready. Isolation and local tools passed; no provider request was made. Start with codex-api.')
        finally:
            if owned_sandbox() is not None:call(['stop',NAME],capture=False)
