"""Clean-machine setup and account boundaries. No real credentials or providers."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from guard import Denied, Ledger, DAILY_LIMITS
import onboarding
import provision

spec=importlib.util.spec_from_file_location('harness_setup',Path(__file__).parents[1]/'setup.py')
setup=importlib.util.module_from_spec(spec);spec.loader.exec_module(setup)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name).resolve()
        self.home=self.base/'home';self.home.mkdir();self.root=self.base/'private installation'
        self.project=self.base/"project with spaces and 'quotes'";self.launcher=self.base/'bin/codex-api'
        self.sbx=self.base/'sbx'
        self.sbx.write_text('#!'+sys.executable+'\nprint("sbx version v0.49.1 test")\n');self.sbx.chmod(0o700)
        self.home_patch=patch.object(Path,'home',return_value=self.home);self.home_patch.start()
    def tearDown(self):self.home_patch.stop();self.tmp.cleanup()
    def install(self):return setup.install(self.root,self.project,self.sbx,port=49321,launcher=self.launcher)
    def configure(self,extra=()):
        (self.root/'openai-key.env').write_text('OPENAI_API_KEY=fake-public-test-key\n');(self.root/'openai-key.env').chmod(0o600)
        onboarding.configure(self.root,['--organization','org-FAKE1','--project','proj_FAKE1','--exclusive-organization','--baseline-a','7','--baseline-b','9',*extra])

    def test_fresh_install_uses_only_owner_private_state_and_leaves_subscription(self):
        subscription=self.home/'.codex/config.toml';subscription.parent.mkdir();subscription.write_text('model="subscription-only"\n')
        before=subscription.read_bytes();result=self.install()
        self.assertEqual(result['provider_requests'],0);self.assertFalse(result['resumed']);self.assertEqual(subscription.read_bytes(),before)
        self.assertFalse((self.root/'openai-key.env').stat().st_mode&0o077)
        self.assertFalse((self.root/'gateway.token').stat().st_mode&0o077)
        v=json.loads((self.root/'verification.json').read_text());self.assertFalse(v['openai']['enabled']);self.assertEqual(v['openai']['billing_policy'],'free_only')
        self.assertEqual(v['openai']['daily_token_limits'],DAILY_LIMITS)
        self.assertNotIn(str(self.home), (setup.SOURCE/'kit/config.toml').read_text())

    def test_rendered_paths_ports_and_quoting_are_valid(self):
        import tomllib
        self.install();config=tomllib.loads((self.root/'kit/config.toml').read_text())
        self.assertIn(str(self.project),config['projects']);self.assertIn(':49321/',config['model_providers']['quota_gateway']['base_url'])
        self.assertEqual((self.root/'kit/workspace').read_text().strip(),str(self.project))
        self.assertNotIn('__WORKSPACE',(self.root/'kit/entrypoint.sh').read_text())
        self.assertEqual(subprocess.run(['/bin/sh','-n',str(self.root/'kit/entrypoint.sh')],capture_output=True).returncode,0)
        self.assertIn(str(self.project),tomllib.loads((self.root/'kit/requirements.toml').read_text())['permissions']['filesystem']['deny_read'][0])

    def test_usage_after_install_is_two_english_lines_and_needs_no_key_or_sandbox(self):
        self.install();before=(self.root/'state/usage.sqlite3').read_bytes()
        r=subprocess.run([str(self.launcher),'usage'],capture_output=True,text=True,check=True)
        lines=r.stdout.splitlines();self.assertEqual(len(lines),2);self.assertTrue(r.stdout.isascii());self.assertTrue(lines[0].startswith('A ('));self.assertTrue(lines[1].startswith('B ('))
        self.assertEqual(before,(self.root/'state/usage.sqlite3').read_bytes())

    def test_resume_never_replaces_credentials_or_ledger(self):
        self.install();self.configure();before={name:(self.root/name).read_bytes() for name in ('verification.json','openai-key.env','gateway.token','state/usage.sqlite3')}
        self.assertTrue(self.install()['resumed'])
        self.assertEqual(before,{name:(self.root/name).read_bytes() for name in before})

    def test_other_launcher_is_not_overwritten(self):
        self.launcher.parent.mkdir();self.launcher.write_text('OTHER COMMAND')
        with self.assertRaises(ValueError):self.install()
        self.assertEqual(self.launcher.read_text(),'OTHER COMMAND');self.assertFalse(self.root.exists())

    def test_install_cannot_share_private_root_or_whole_home(self):
        for folder in (self.root,self.base,self.home):
            with self.subTest(folder=folder),self.assertRaises(ValueError):setup.install(self.root,folder,self.sbx,launcher=self.launcher)

    def test_symlink_and_credential_workspace_are_rejected_before_install(self):
        target=self.base/'target';target.mkdir();self.project.symlink_to(target)
        with self.assertRaises(ValueError):self.install()
        self.project.unlink();self.project.mkdir();(self.project/'.env').write_text('PUBLIC_SENTINEL')
        with self.assertRaises(Denied):self.install()
        self.assertFalse(self.root.exists())

    def test_changed_owned_file_stops_resuming_without_resetting_state(self):
        self.install();before=(self.root/'state/usage.sqlite3').read_bytes();(self.root/'app/guard.py').chmod(0o600);(self.root/'app/guard.py').write_text('CHANGED')
        with self.assertRaises(ValueError):self.install()
        self.assertEqual(before,(self.root/'state/usage.sqlite3').read_bytes())

    def test_other_release_does_not_silently_reuse_or_overwrite_existing_install(self):
        self.install();before=(self.root/'state/usage.sqlite3').read_bytes()
        with patch.object(setup,'VERSION','99.0.0'):
            with self.assertRaises(ValueError):self.install()
        self.assertEqual(before,(self.root/'state/usage.sqlite3').read_bytes())

    def test_free_only_configuration_does_not_claim_free_eligibility(self):
        self.install();self.configure();v=json.loads((self.root/'verification.json').read_text())['openai']
        self.assertEqual(v['billing_policy'],'free_only');self.assertFalse(v['verified']);self.assertFalse(v['count_endpoint_free_confirmed']);self.assertTrue(v['org_exclusive'])
        ledger=Ledger(self.root/'state')
        try:self.assertEqual(ledger.daily_remaining('A',DAILY_LIMITS['A'])['remaining'],DAILY_LIMITS['A']-7)
        finally:ledger.close()

    def test_billing_opt_in_preserves_all_existing_usage_and_account_binding(self):
        self.install();self.configure();before=(self.root/'state/usage.sqlite3').read_bytes()
        onboarding.billing(self.root,['--allow-api-charges']);v=json.loads((self.root/'verification.json').read_text())['openai']
        self.assertEqual(v['billing_policy'],'metered');self.assertTrue(v['quota_guard']);self.assertEqual(v['project_id'],'proj_FAKE1')
        self.assertEqual(before,(self.root/'state/usage.sqlite3').read_bytes())
        onboarding.billing(self.root,['--free-only']);self.assertEqual(before,(self.root/'state/usage.sqlite3').read_bytes())

    def test_account_cannot_be_rebound_or_baseline_reset(self):
        self.install();self.configure();before=(self.root/'verification.json').read_bytes()
        with self.assertRaises(Denied):self.configure(['--allow-api-charges'])
        self.assertEqual(before,(self.root/'verification.json').read_bytes())

    def test_billing_change_refuses_active_session(self):
        import fcntl
        self.install();self.configure()
        with (self.root/'session.lock').open('a+b') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(Denied):onboarding.billing(self.root,['--allow-api-charges'])

    def test_environment_inventory_never_reads_secret_files_or_env_values(self):
        with patch.object(setup,'default_sbx',return_value=None),patch.object(Path,'read_text',side_effect=AssertionError('Content read is forbidden')),patch.dict(os.environ,{'OPENAI_API_KEY':'PRIVATE_CONTEXT_SENTINEL'}):
            result=setup.inspect_context()
        self.assertFalse(result['secret_contents_read']);self.assertNotIn('PRIVATE_CONTEXT_SENTINEL',json.dumps(result))

    def test_interrupted_initial_configuration_resumes_without_replacing_baseline(self):
        import datetime as dt
        self.install();day=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
        ledger=Ledger(self.root/'state')
        try:ledger.configure_budget('openai:A',day,DAILY_LIMITS['A'],baseline=7)
        finally:ledger.close()
        self.configure()
        ledger=Ledger(self.root/'state')
        try:self.assertEqual(ledger.daily_remaining('A',DAILY_LIMITS['A'])['remaining'],DAILY_LIMITS['A']-7)
        finally:ledger.close()

    def test_invalid_download_is_rejected_before_signature_check_or_execution(self):
        stage=self.base/'download';stage.mkdir()
        with patch.object(setup.urllib.request,'urlopen',return_value=io.BytesIO(b'CORRUPT_PUBLIC_TEST_ARCHIVE')),patch.object(setup.subprocess,'run') as run:
            with self.assertRaises(ValueError):setup.bootstrap_sbx(stage)
            run.assert_not_called()

    def test_public_catalog_uses_authored_instructions_without_account_model_exports(self):
        models=json.loads((setup.SOURCE/'kit/models.json').read_text())['models']
        self.assertEqual(len(models),5)
        for model in models:
            self.assertNotIn('model_messages',model)
            self.assertTrue(model['base_instructions'].startswith('You are Codex, a coding assistant'))
            self.assertLess(len(model['base_instructions']),2000)


class HostPolicyTests(unittest.TestCase):
    def base(self):return {'rules':[{'id':'default-deny-all','resource_type':'network','decision':'deny','resources':['**'],'scope':'global'}]}
    def test_locked_down_without_unreviewed_allow_is_accepted(self):self.assertEqual(provision.policy_issues(self.base()),[])
    def test_global_allow_and_wrong_runtime_hosts_are_rejected(self):
        for scope,kind,resource in [('global','network','**'),('sandbox:'+provision.NAME,'network','github.com'),('sandbox:'+provision.NAME,'http','registry.npmjs.org:443')]:
            p=self.base();p['rules'].append({'scope':scope,'resource_type':kind,'decision':'allow','resources':[resource],'methods':['POST']})
            with self.subTest(scope=scope,kind=kind):self.assertTrue(provision.policy_issues(p))
    def test_only_pinned_package_get_head_and_local_gateway_are_accepted(self):
        p=self.base();scope='sandbox:'+provision.NAME
        p['rules'].append({'scope':scope,'resource_type':'network','decision':'allow','resources':['localhost:'+str(provision.PORT)]})
        for host in provision.PACKAGE_HOSTS:p['rules'].append({'scope':scope,'resource_type':'http','decision':'allow','resources':[host],'methods':['GET','HEAD']})
        self.assertEqual(provision.policy_issues(p),[])
    def test_global_changes_are_refused_when_other_sandboxes_exist(self):
        import controller
        with patch.object(controller,'sandbox_inventory',return_value=[{'name':'existing-project'}]),patch.object(provision,'call') as call:
            with self.assertRaises(Denied):provision.configure_fresh_host()
            call.assert_not_called()
