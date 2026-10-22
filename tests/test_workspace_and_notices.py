import contextlib,fnmatch,importlib.util,io,json,os,random,string,tempfile,threading,tomllib,unittest
from pathlib import Path
from unittest.mock import patch
import controller,gateway,workspace_policy as policy
import test_guard as fixtures
import test_http as http_fixtures
from guard import Denied,Ledger,atomic_json,read_quota
from test_preferences_and_recovery import DailyFixture
from test_preferences_and_recovery import preferences

class CliPolicyTests(unittest.TestCase):
 def setUp(self):
  from policy import legacy
  self.patcher=patch.object(preferences,'model_policy',return_value=legacy());self.patcher.start();self.addCleanup(self.patcher.stop)
 def test_protected_overrides_are_refused_before_native_cli(self):
  for args in (['--dangerously-bypass-approvals-and-sandbox'],['sandbox','-P',':danger-full-access'],['-c','sandbox_mode="danger-full-access"'],['--config=model_provider="openai"'],['--add-dir','/tmp'],['--search'],['--dangerously-bypass-hook-trust'],['-m','unapproved'],['-C','/home/agent']):
   with self.subTest(args=args),self.assertRaises(preferences.PolicyArgumentError):preferences.validate_cli_args(args)
 def test_normal_workflow_and_safe_preferences_remain_available(self):
  for args in ([],['resume','--last'],['exec','--json','public test'],['-m','gpt-6.1-sol'],['-c','model_reasoning_effort=high'],['--config=tui.animations=false'],['sandbox','-P','codex_api_workspace','--include-managed-config','--','python3','-c','print(1)']):preferences.validate_cli_args(args)
 def test_literal_command_arguments_after_separator_are_not_policy_flags(self):
  preferences.validate_cli_args(['sandbox','--','python3','-c','print("--search")'])

class NoticeHookTests(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('notice_hook',Path(__file__).parents[1]/'kit/quota-notice.py');self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
 def test_hook_only_sends_empty_request_and_returns_ui_message_without_context(self):
  message='API quota warning - Group B: 90%+ used or reserved; 10 tokens left. Resets 00:00 UTC.'
  class Response(io.BytesIO):
   def __enter__(inner):return inner
   def __exit__(inner,*args):inner.close()
  class Opener:
   request=None
   def open(inner,request,timeout):inner.request=request;return Response(json.dumps({'notices':[{'message':message}]}).encode())
  opener=Opener();stdin=type('Input',(),{'buffer':io.BytesIO(b'PRIVATE_HOOK_INPUT_NEVER_FORWARD')})()
  with patch.object(self.module.sys,'stdin',stdin),patch.dict(os.environ,{'CODEX_GATEWAY_TOKEN':'local-gateway-only','CODEX_API_INTERACTIVE':'1'}),patch.object(self.module.urllib.request,'build_opener',return_value=opener),contextlib.redirect_stdout(io.StringIO()) as out:
   self.assertEqual(self.module.main(),0)
  self.assertEqual(opener.request.data,b'{}');self.assertEqual(json.loads(out.getvalue()),{'systemMessage':message});self.assertNotIn('PRIVATE_HOOK_INPUT',out.getvalue())
 def test_noninteractive_hook_keeps_notice_pending_instead_of_hiding_it(self):
  stdin=type('Input',(),{'buffer':io.BytesIO(b'{}')})()
  with patch.object(self.module.sys,'stdin',stdin),patch.dict(os.environ,{'CODEX_GATEWAY_TOKEN':'local-only','CODEX_API_INTERACTIVE':'0'}),patch.object(self.module.urllib.request,'build_opener') as opener,contextlib.redirect_stdout(io.StringIO()) as out:
   self.assertEqual(self.module.main(),0);opener.assert_not_called();self.assertEqual(out.getvalue(),'')
 def test_notice_timeout_is_quiet_and_never_blocks_or_retries(self):
  stdin=type('Input',(),{'buffer':io.BytesIO(b'{}')})()
  with patch.object(self.module.sys,'stdin',stdin),patch.dict(os.environ,{'CODEX_GATEWAY_TOKEN':'local-only','CODEX_API_INTERACTIVE':'1'}),patch.object(self.module.urllib.request,'build_opener') as opener,contextlib.redirect_stdout(io.StringIO()) as out:
   opener.return_value.open.side_effect=TimeoutError();self.assertEqual(self.module.main(),0);self.assertEqual(opener.return_value.open.call_count,1);self.assertEqual(out.getvalue(),'')

class WorkspaceTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
 def tearDown(self):self.tmp.cleanup()
 def test_generated_native_patterns_cover_names_with_only_exact_template_exceptions(self):
  def matches(name):return any(fnmatch.fnmatchcase('nested/'+name,p) for p in policy.native_deny_globs())
  for name in ('.env','.ENV','.env.local','.env.EXAMPLE.secret','.env.exa','.env.examplex','.env.s','.env..','secret.PEM','id_rsa','.netrc','auth.json','.npmrc','cacert2.pem','evilcacert.pem','cacert.pem.pem'):
   with self.subTest(name=name):self.assertTrue(matches(name))
  for name in policy.TEMPLATES|{'.ENV.EXAMPLE','normal.ts','package.json','environment.py','cacert.pem','CA-BUNDLE.PEM'}:
   with self.subTest(name=name):self.assertFalse(matches(name))
  rng=random.Random(3)
  for _ in range(1000):
   suffix=''.join(rng.choice(string.ascii_lowercase+'.-_0123') for _ in range(rng.randint(0,25)))
   name='.env.'+suffix;self.assertEqual(matches(name),name not in policy.TEMPLATES)
 def test_only_empty_or_placeholder_templates_are_accepted(self):
  p=self.root/'.env.example';p.write_text('OPENAI_API_KEY=your_openai_api_key\nPORT=3000\nURL=http://localhost:3000\nEMPTY=\n')
  self.assertTrue(policy.safe_template(p));policy.check_workspace(self.root)
  for value in ('sk-proj-PRIVATE_SENTINEL','tvly-private-sentinel','real-looking-credential-123','$(cat private)','`cat private`','https://user:secret@example.com','https://example.com/?key=secret'):
   p.write_text('KEY='+value+'\n')
   with self.subTest(value=value),self.assertRaises(Denied) as error:policy.check_workspace(self.root)
   self.assertNotIn(value,str(error.exception))
 def test_sensitive_files_added_after_initial_check_are_detected(self):
  policy.check_workspace(self.root);p=self.root/'nested';p.mkdir();(p/'.env.local').write_text('PRIVATE_SENTINEL')
  with self.assertRaises(Denied) as error:policy.check_workspace(self.root)
  self.assertEqual(error.exception.code,'workspace_policy_failed');self.assertNotIn('PRIVATE_SENTINEL',str(error.exception))
 def test_external_links_and_hardlinks_remain_forbidden(self):
  target=self.root.parent/(self.root.name+'-outside');target.write_text('PUBLIC_SENTINEL')
  try:
   (self.root/'link').symlink_to(target)
   with self.assertRaises(Denied):policy.check_workspace(self.root)
   (self.root/'link').unlink();os.link(target,self.root/'hardlink')
   with self.assertRaises(Denied):policy.check_workspace(self.root)
  finally:target.unlink()
 def test_standard_guest_venv_links_do_not_grant_host_private_paths(self):
  v=self.root/'.venv';(v/'bin').mkdir(parents=True);(v/'pyvenv.cfg').write_text('home=/usr/local/bin\n')
  link=v/'bin/python3';link.symlink_to('/usr/local/bin/python3.14');(v/'bin/python').symlink_to('python3')
  (v/'bin/𝜋thon').symlink_to('python3')
  policy.check_workspace(self.root)
  link.unlink();link.symlink_to('/host-private/.ssh/id_ed25519')
  with self.assertRaises(Denied):policy.check_workspace(self.root)
 def test_empty_native_sandbox_anchor_is_allowed_but_credentials_are_not(self):
  folder=self.root/'.aws';folder.mkdir();policy.check_workspace(self.root)
  (folder/'credentials').write_text('PUBLIC_SAFETY_TEST')
  with self.assertRaises(Denied):policy.check_workspace(self.root)
 def test_public_ca_bundle_exception_cannot_hide_a_private_key(self):
  source=Path('/etc/ssl/cert.pem')
  if not source.is_file():source=Path('/etc/ssl/certs/ca-certificates.crt')
  if not source.is_file():self.skipTest('No public system CA bundle fixture')
  data=source.read_text();start=data.index('-----BEGIN CERTIFICATE-----');end=data.index('-----END CERTIFICATE-----',start)+len('-----END CERTIFICATE-----')
  bundle=self.root/'cacert.pem';bundle.write_text(data[start:end]+'\n');self.assertTrue(policy.public_ca_bundle(bundle));policy.check_workspace(self.root)
  bundle.write_text('-----BEGIN '+'PRIVATE KEY-----\nPUBLIC_TEST_SENTINEL\n-----END '+'PRIVATE KEY-----')
  self.assertFalse(policy.public_ca_bundle(bundle))
  with self.assertRaises(Denied):policy.check_workspace(self.root)
 def test_managed_profile_hooks_and_download_configuration_are_narrow(self):
  req=tomllib.loads(policy.managed_requirements());self.assertTrue(req['allow_managed_hooks_only'])
  self.assertEqual(req['allowed_permission_profiles'],{'codex_api_workspace':True})
  for groups in req['hooks'].values():
   if isinstance(groups,list):
    for group in groups:
     for hook in group['hooks']:self.assertEqual(hook['command'],'python3 -I /etc/codex-api/quota-notice.py')
  config=tomllib.loads((Path(__file__).parents[1]/'kit/config.toml').read_text());self.assertNotIn('sandbox_mode',config)
  self.assertFalse(config['features']['plugin_hooks']);self.assertFalse(config['features']['plugins'])

class DispatchPreflightTests(DailyFixture):
 def test_added_secret_blocks_even_counting(self):
  self.daily();p=self.root/'project';p.mkdir();self.broker.workspace_guard=lambda:policy.check_workspace(p)
  (p/'.env').write_text('PRIVATE_SENTINEL')
  with self.assertRaises(Denied) as error:self.request()
  self.assertEqual(error.exception.code,'workspace_policy_failed');self.assertEqual(self.calls,[])
 def test_secret_arriving_during_count_never_reaches_inference(self):
  self.daily();p=self.root/'project';p.mkdir();self.broker.workspace_guard=lambda:policy.check_workspace(p)
  original=self.broker.transport
  def transport(*args,**kwargs):
   result=original(*args,**kwargs);(p/'.env.local').write_text('PRIVATE_SENTINEL');return result
  self.broker.transport=transport
  with self.assertRaises(Denied):self.request()
  self.assertEqual(len(self.calls),1);self.assertTrue(self.calls[0][1].endswith('input_tokens'))
  self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)

class NoticeTests(DailyFixture):
 def limits(self):return {'A':100,'B':100}
 def debit(self,group,amount):
  r=self.ledger.reserve_daily(group,100,amount,{});self.ledger.dispatch_daily(r);self.ledger.settle(r,amount);return r
 def test_exact_ninety_percent_boundary_and_one_per_group(self):
  self.daily();self.debit('A',89);head=self.ledger._head()
  self.assertEqual(self.ledger.claim_daily_notices(self.limits()),[]);self.assertEqual(self.ledger._head(),head)
  self.debit('A',1);first=self.ledger.claim_daily_notices(self.limits());self.assertEqual([n['group'] for n in first],['A'])
  self.debit('A',5);self.assertEqual(self.ledger.claim_daily_notices(self.limits()),[])
  self.debit('B',90);self.assertEqual([n['group'] for n in self.ledger.claim_daily_notices(self.limits())],['B'])
 def test_restart_keeps_dedup_and_day_rollover_is_independent(self):
  self.daily();self.debit('B',90);self.assertEqual(len(self.ledger.claim_daily_notices(self.limits())),1)
  self.ledger.close();self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW)
  self.assertEqual(self.ledger.claim_daily_notices(self.limits()),[])
  self.ledger.close();self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW+86400)
  self.debit('B',90);self.assertEqual(len(self.ledger.claim_daily_notices(self.limits())),1)
 def test_concurrent_claims_warn_once_without_changing_accounting(self):
  self.daily();self.debit('B',90)
  before=self.ledger.db.execute('SELECT * FROM requests').fetchall();budgets=self.ledger.db.execute('SELECT * FROM budgets').fetchall()
  out=[]
  threads=[threading.Thread(target=lambda:out.extend(self.ledger.claim_daily_notices(self.limits()))) for _ in range(12)]
  for t in threads:t.start()
  for t in threads:t.join()
  self.assertEqual(len(out),1);self.assertEqual(self.ledger.db.execute('SELECT * FROM requests').fetchall(),before);self.assertEqual(self.ledger.db.execute('SELECT * FROM budgets').fetchall(),budgets)
 def test_unknown_reservations_warn_conservatively_without_becoming_actual(self):
  self.daily();r=self.ledger.reserve_daily('B',100,90,{});self.ledger.dispatch_daily(r)
  notice=self.ledger.claim_daily_notices(self.limits())[0];self.assertIn('used or reserved',notice['message']);self.assertEqual(notice['remaining'],10)
  self.assertIsNone(self.ledger.db.execute('SELECT actual FROM requests WHERE id=?',(r,)).fetchone()[0])
 def test_read_only_usage_does_not_claim_or_add_lines(self):
  self.daily();self.debit('B',90)
  with patch.object(controller,'ROOT',self.root),contextlib.redirect_stdout(io.StringIO()) as out:controller.status(usage_only=True)
  self.assertEqual(len(out.getvalue().splitlines()),2);self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM quota_notices').fetchone()[0],0)
  self.assertEqual(len(self.ledger.claim_daily_notices(self.limits())),1)
 def test_bad_witness_never_consumes_notice_or_resets_usage(self):
  self.daily();self.debit('B',90);atomic_json(self.root/'state/ledger-witness.json',{'identity':'wrong','sequence':0})
  with self.assertRaises(Denied):self.ledger.claim_daily_notices(self.limits())
  self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM quota_notices').fetchone()[0],0)
 def test_unknown_carry_can_warn_again_on_a_new_utc_day_without_refund(self):
  self.daily();rid=self.ledger.reserve_daily('B',100,90,{});self.ledger.dispatch_daily(rid)
  self.assertEqual(len(self.ledger.claim_daily_notices(self.limits())),1)
  self.ledger.close();self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW+86400)
  notice=self.ledger.claim_daily_notices(self.limits())[0];self.assertEqual(notice['remaining'],10)
  self.assertEqual(self.ledger.db.execute('SELECT phase,actual FROM requests WHERE id=?',(rid,)).fetchone(),('unknown',None))

class NoticeHTTPTests(unittest.TestCase):
 setUp=http_fixtures.HTTPTests.setUp
 tearDown=http_fixtures.HTTPTests.tearDown
 call=http_fixtures.HTTPTests.call
 def test_local_authenticated_notice_claim_never_calls_provider(self):
  data=json.loads((self.root/'verification.json').read_text());data['openai'].update(quota_guard=True,daily_token_limits={'A':100,'B':100});atomic_json(self.root/'verification.json',data)
  r=self.ledger.reserve_daily('B',100,90,{});self.ledger.dispatch_daily(r)
  self.assertEqual(self.call('/v1/notices/claim',{},method='POST',token=False)[0],403)
  status,result=self.call('/v1/notices/claim',{},method='POST');self.assertEqual(status,200);self.assertEqual(result['notices'][0]['group'],'B')
  self.assertEqual(self.call('/v1/notices/claim',{},method='POST')[1]['notices'],[]);self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()
