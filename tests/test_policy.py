"""Generalized owner policy: real accounting, fake providers, private fixture files."""
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import configuration
import onboarding
import policy
from guard import Denied, Ledger, atomic_json, normalize, read_quota
from gateway import Broker
from shared import Team, MemberLedger, MemberBroker
import test_guard
import test_install


def profile(tier='default',groups=('Daily',)):
    p=policy.recommended();template=next(iter(p['models'].values()))
    p['pools']={g:{'label':g+' models','daily_tokens':100000} for g in groups}
    p['models']={('gpt-6.1-sol' if i==0 else 'owner-reviewed-model-'+str(i)):{**copy.deepcopy(template),'pool':g} for i,g in enumerate(groups)}
    p['defaults']['service_tier']=tier
    p['defaults']['request_deadline_seconds']=900 if tier=='flex' else 600
    return policy.validate(p)


class SchemaTests(unittest.TestCase):
    def test_shared_amount_errors_name_tokens_instead_of_account_baselines(self):
        p=profile()
        for items in (['Unknown=1'],[],['Daily=95001']):
            with self.subTest(items=items),self.assertRaises(Denied) as error:configuration.baselines(items,p,flag='--tokens')
            self.assertNotIn('prior usage',str(error.exception).lower())
            self.assertNotIn('--baseline',str(error.exception))

    def test_shared_init_rejects_mixed_baseline_flags_before_state_creation(self):
        import shared
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Denied):shared.command(Path(tmp),['init','--organization','org-fixture','--baseline','Daily=0','--baseline-a','100','--all-traffic-coordinated'])
            self.assertFalse((Path(tmp)/'team').exists())

    def test_legacy_efforts_match_conservative_api_subset_without_mutating_receipt(self):
        receipt={'daily_token_limits':{'A':12345,'B':23456},'output_token_cap':1000}
        before=copy.deepcopy(receipt)
        p=policy.from_receipt(receipt)
        self.assertEqual(receipt,before)
        self.assertEqual(policy.limits(p),receipt['daily_token_limits'])
        for model in p['models']:
            with self.subTest(model=model):
                self.assertEqual(p['models'][model]['reasoning_efforts'],['low','medium','high','xhigh','max'])
                with self.assertRaises(Denied):normalize({'model':model,'input':'x','reasoning':{'effort':'ultra'}},policy=p)

    def test_pool_labels_reject_all_ascii_controls_including_delete(self):
        for value in [*range(32),127]:
            p=profile();p['pools']['Daily']['label']='Daily'+chr(value)
            with self.subTest(value=value),self.assertRaises(policy.PolicyError):policy.validate(p)

    def test_recommendations_are_unconfigured_until_owner_choice(self):
        self.assertEqual(policy.empty()['models'],{});self.assertEqual(policy.empty()['pools'],{})
        self.assertEqual(policy.validate(policy.empty(),allow_empty=True),policy.empty())
        with self.assertRaises(policy.PolicyError):policy.validate(policy.empty())

    def test_one_and_three_pools_not_bound_to_original_models_or_limits(self):
        for groups in [('Daily',),('Small','Large','Research')]:
            p=profile(groups=groups);p['pools'][groups[0]]['daily_tokens']=5000000
            self.assertEqual(policy.limits(p)[groups[0]],4750000)
            self.assertEqual(set(policy.model_pools(p).values()),set(groups))

    def test_every_tier_is_explicit_and_priority_canonicalizes(self):
        for tier in ['default','fast','flex','ultrafast']:
            p=profile(tier);result=normalize({'model':'gpt-6.1-sol','input':'test'},policy=p)
            self.assertEqual(result['service_tier'],tier)
        p=profile('fast');p['defaults']['service_tier']='priority'
        self.assertEqual(policy.validate(p)['defaults']['service_tier'],'fast')

    def test_unknown_auto_and_incompatible_tiers_fail(self):
        for invalid in ['auto','future','',None,[],True]:
            p=profile();p['defaults']['service_tier']=invalid
            with self.subTest(invalid=invalid),self.assertRaises(policy.PolicyError):policy.validate(p)
        p=profile('fast');p['models']['gpt-6.1-sol']['service_tiers']=['default']
        with self.assertRaises(policy.PolicyError):policy.validate(p)

    def test_schema_types_bounds_unknown_fields_and_other_reset_cycles_fail(self):
        mutations=[lambda p:p.update(unknown=True),lambda p:p.update(reset='monthly'),lambda p:p.update(safety_margin_percent=True),lambda p:p.update(warning_percent=100),lambda p:p['pools']['Daily'].update(daily_tokens=0),lambda p:p['pools']['Daily'].update(daily_tokens=1.5),lambda p:p['pools']['Daily'].update(label='inject\ntext'),lambda p:p['models']['gpt-6.1-sol'].update(pool=[]),lambda p:p['models']['gpt-6.1-sol'].update(reference='https://evil.example/model'),lambda p:p['defaults'].update(model=[]),lambda p:p['defaults'].update(output_token_cap=200000),lambda p:p['defaults'].update(request_deadline_seconds=901),lambda p:p['models']['gpt-6.1-sol'].update(reasoning_efforts=['medium','medium']),lambda p:p['models']['gpt-6.1-sol'].update(service_tiers=['fast','priority'])]
        for mutate in mutations:
            p=profile();mutate(p)
            with self.subTest(p=p),self.assertRaises(policy.PolicyError):policy.validate(p)

    def test_model_effort_tier_and_output_enforced_before_provider(self):
        p=profile()
        for payload in [{'model':'unapproved','input':'x'},{'model':'gpt-6.1-sol','input':'x','reasoning':{'effort':'ultra'}},{'model':'gpt-6.1-sol','input':'x','service_tier':'fast'},{'model':'gpt-6.1-sol','input':'x','max_output_tokens':16385}]:
            with self.subTest(payload=payload),self.assertRaises(Denied):normalize(payload,16384,policy=p)

    def test_hosted_tools_remain_denied_for_all_tiers(self):
        for tier in policy.TIERS:
            p=profile(tier)
            for tool in ['web_search','file_search','code_interpreter','mcp','image_generation']:
                with self.subTest(tier=tier,tool=tool),self.assertRaises(Denied):normalize({'model':'gpt-6.1-sol','input':'x','tools':[{'type':tool}]},policy=p)

    def test_duplicate_json_nonfinite_symlinks_and_public_input_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'draft';path.write_text('{"version":1,"version":1}');path.chmod(0o600)
            with self.assertRaises(policy.PolicyError):policy.read_json(path,private=True)
            path.write_text('{"value":NaN}')
            with self.assertRaises(policy.PolicyError):policy.read_json(path,private=True)
            path.write_text('{}');path.chmod(0o644)
            with self.assertRaises(policy.PolicyError):policy.read_json(path,private=True)
            link=Path(tmp)/'link';link.symlink_to(path)
            with self.assertRaises(OSError):policy.read_json(link)


class PolicyInstallTests(unittest.TestCase):
    setUp=test_install.InstallTests.setUp
    tearDown=test_install.InstallTests.tearDown
    install=test_install.InstallTests.install
    def initialize(self,p=None):
        self.install();p=p or profile();self.draft=self.root/'review.json';atomic_json(self.draft,p)
        (self.root/'openai-key.env').write_text('OPENAI_API_KEY=fake-fixture-key\n');(self.root/'openai-key.env').chmod(0o600)
        args=['--organization','org-fixture','--project','proj_fixture','--exclusive-organization','--allow-api-charges','--policy',str(self.draft),'--reviewed-policy-digest',policy.digest(p)]
        for g in p['pools']:args+=['--baseline',g+'=0']
        with contextlib.redirect_stdout(io.StringIO()):onboarding.configure(self.root,args)
        return p
    def ledger_rows(self):
        ledger=Ledger(self.root/'state')
        try:return ledger._head()['identity'],ledger.db.execute('SELECT * FROM requests ORDER BY id').fetchall()
        finally:ledger.close()
    def apply(self,p,**kw):
        with contextlib.redirect_stdout(io.StringIO()):return configuration.apply(self.root,p,**kw)

    def test_fresh_install_has_no_implied_models_or_usage_allowance(self):
        self.install();p=policy.load(self.root,allow_empty=True)
        self.assertEqual(p['models'],{})
        result=subprocess.run([str(self.launcher),'usage'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('237,500',result.stdout)

    def test_private_account_specific_configuration_drives_every_guest_file(self):
        p=self.initialize(profile('flex',('Daily','Research','Build')))
        self.assertEqual(policy.verify_guest(self.root),p)
        import tomllib
        config=tomllib.loads((self.root/'kit/config.toml').read_text())
        self.assertEqual(config['service_tier'],'flex')
        self.assertEqual(set(m['slug'] for m in json.loads((self.root/'kit/models.json').read_text())['models']),set(p['models']))
        result=subprocess.run([str(self.launcher),'usage'],capture_output=True,text=True,check=True)
        self.assertEqual(len(result.stdout.splitlines()),3);self.assertTrue(result.stdout.isascii())

    def test_guest_capability_drift_is_rejected(self):
        p=self.initialize();catalog=json.loads((self.root/'kit/models.json').read_text())
        catalog['models'][0]['context_window']+=1
        atomic_json(self.root/'kit/models.json',catalog)
        with self.assertRaises(policy.PolicyError):policy.verify_guest(self.root)

    def test_policy_digest_review_and_each_baseline_are_required(self):
        self.install();p=profile();path=self.root/'review.json';atomic_json(path,p)
        with self.assertRaises(Denied):configuration.candidate(path,'0'*64)
        with self.assertRaises(Denied):configuration.baselines([],p)
        with self.assertRaises(Denied):configuration.baselines(['Daily=0','Daily=1'],p)
        with self.assertRaises(Denied):configuration.baselines(['Other=0'],p)

    def test_adjusting_limit_preserves_keys_account_sessions_spent_and_identity(self):
        p=self.initialize();history=self.root/'guest-state/sentinel';history.parent.mkdir();history.write_text('KEEP_SESSION')
        ledger=Ledger(self.root/'state');ledger.pause(False)
        request=ledger.reserve_daily('Daily',95000,20,{})
        ledger.dispatch_daily(request);ledger.settle(request,9);ledger.close()
        identity,rows=self.ledger_rows();key=(self.root/'openai-key.env').read_bytes()
        p['pools']['Daily']['daily_tokens']=200000;self.apply(p)
        self.assertEqual(self.ledger_rows(),(identity,rows));self.assertEqual((self.root/'openai-key.env').read_bytes(),key)
        self.assertEqual(history.read_text(),'KEEP_SESSION')
        account=json.loads((self.root/'verification.json').read_text())['openai']
        self.assertEqual(account['organization_id'],'org-fixture');self.assertEqual(account['billing_policy'],'metered')
        self.assertEqual(read_quota(self.root/'state',policy.limits(p),policy=p)['daily_pools']['Daily']['remaining'],190000-9)

    def test_crash_after_budget_commit_resumes_without_refund_or_baseline_reset(self):
        p=self.initialize();p['pools']['Daily']['daily_tokens']=200000
        real=configuration.atomic_json
        def crash(path,value):
            if Path(path)==self.root/'verification.json':raise SystemExit('synthetic crash')
            return real(path,value)
        with patch.object(configuration,'atomic_json',side_effect=crash),self.assertRaises(SystemExit):self.apply(p)
        with self.assertRaises(policy.PolicyError):policy.load(self.root)
        self.apply(p);self.assertEqual(policy.limits(policy.load(self.root)),{'Daily':190000})
        ledger=Ledger(self.root/'state')
        try:self.assertEqual(ledger.db.execute('SELECT ceiling,baseline FROM budgets WHERE scope=?',('openai:Daily',)).fetchone(),(190000,0))
        finally:ledger.close()
        self.assertFalse((self.root/'policy-pending.json').exists())

    def test_interrupted_partial_guest_render_can_replay_exact_bytes(self):
        p=self.initialize();p['defaults']['reasoning_effort']='high'
        real=configuration.os.replace
        def crash(src,dst):
            if Path(dst)==(self.root/'kit/config.toml').resolve():raise SystemExit('synthetic guest render crash')
            return real(src,dst)
        with patch.object(configuration.os,'replace',side_effect=crash),self.assertRaises(SystemExit):self.apply(p)
        self.assertTrue((self.root/'policy-render-pending.json').exists())
        self.apply(p);self.assertEqual(policy.verify_guest(self.root),p)
        self.assertFalse((self.root/'policy-render-pending.json').exists())

    def test_unknown_requests_pool_removal_and_model_reassignment_are_not_refunded(self):
        p=self.initialize(profile(groups=('Daily','Research')))
        ledger=Ledger(self.root/'state');ledger.pause(False)
        request=ledger.reserve_daily('Daily',95000,20,{})
        ledger.dispatch_daily(request);ledger.close()
        with self.assertRaises(Denied):self.apply(p)
        ledger=Ledger(self.root/'state');ledger.settle(request,9);ledger.close()
        changed=copy.deepcopy(p);changed['models']['gpt-6.1-sol']['pool']='Research';changed['models']['new-reviewed-model']=copy.deepcopy(p['models']['gpt-6.1-sol'])
        with self.assertRaises(Denied):self.apply(changed)
        self.assertEqual(self.ledger_rows()[1][0][5],9)

    def test_new_pool_requires_today_baseline_and_existing_baseline_cannot_reset(self):
        p=self.initialize();new=profile(groups=('Daily','Research'))
        with self.assertRaises(Denied):self.apply(new)
        with self.assertRaises(Denied):self.apply(new,baseline={'Daily':0,'Research':0})
        self.apply(new,baseline={'Research':7})
        view=read_quota(self.root/'state',policy.limits(new),policy=new)
        self.assertEqual(view['daily_pools']['Research']['remaining'],95000-7)

    def test_active_session_and_malformed_guest_policy_fail_closed(self):
        p=self.initialize()
        with (self.root/'session.lock').open('a+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(Denied):self.apply(p)
        atomic_json(self.root/'kit/runtime-policy.json',profile('fast'))
        with self.assertRaises(policy.PolicyError):policy.verify_guest(self.root)

    def test_warning_once_per_day_per_pool_even_when_threshold_changes(self):
        p=self.initialize();ledger=Ledger(self.root/'state')
        try:
            day=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
            with ledger.transaction():ledger.db.execute('UPDATE budgets SET baseline=90000 WHERE scope=? AND period=?',('openai:Daily',day))
            self.assertEqual(len(ledger.claim_daily_notices({'Daily':95000},warning_percent=90)),1)
            self.assertEqual(ledger.claim_daily_notices({'Daily':95000},warning_percent=80),[])
        finally:ledger.close()

    def test_legacy_launcher_dispatches_new_owner_policy_without_replacing_it(self):
        self.initialize();text=test_install.setup.launcher_text(self.root).replace('|policy|','|')
        self.launcher.write_text(text)
        result=subprocess.run([str(self.launcher),'policy','show'],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(result.stdout)['effective_daily_limits'],{'Daily':95000})

    def test_old_code_cannot_ignore_generalized_policy_on_rollback(self):
        import releases
        self.initialize()
        with self.assertRaises(Denied):releases._state_compatible(self.root,{'harness_version':'0.2.0'})
        releases._state_compatible(self.root,{'harness_version':'0.3.0'})

    def test_reconciliation_reads_dynamic_pool_and_retains_request(self):
        import recovery
        p=self.initialize(profile('flex'));ledger=Ledger(self.root/'state');ledger.pause(False)
        request=ledger.reserve_daily('Daily',95000,20,{})
        ledger.dispatch_daily(request);ledger.close()
        result=recovery.inspect(self.root)
        self.assertTrue(result['verified']);self.assertEqual(result['requests'][0]['id'],request)

    def test_removed_model_cannot_return_in_another_pool_after_recorded_use(self):
        p=self.initialize(profile(groups=('Daily','Research')));ledger=Ledger(self.root/'state');ledger.pause(False)
        request=ledger.reserve_daily('Daily',95000,20,{})
        ledger.dispatch_daily(request);ledger.settle(request,9);ledger.close()
        q=copy.deepcopy(p);old=q['models'].pop('gpt-6.1-sol')
        q['models']['replacement-model']=copy.deepcopy(old);q['defaults']['model']='replacement-model'
        self.apply(q)
        q['models']['gpt-6.1-sol']={**old,'pool':'Research'}
        with self.assertRaises(Denied):self.apply(q)

    def test_switching_models_adapts_saved_effort_but_rejects_explicit_mismatch(self):
        from test_preferences_and_recovery import preferences
        p=profile(groups=('Daily','Research'))
        p['models']['owner-reviewed-model-1']['reasoning_efforts']=['none']
        self.initialize(p)
        home=self.base/'guest';home.mkdir()
        (home/'preferences.json').write_text(json.dumps({'model':'gpt-6.1-sol','model_reasoning_effort':'high'}))
        with patch.object(preferences,'model_policy',return_value=p):
            overrides=preferences.validate_cli_args(['-m','owner-reviewed-model-1'])
            _,saved=preferences.prepare(home,self.root/'kit/config.toml',self.root/'kit/extensions',return_policy=True)
            original=(home/'preferences.json').read_bytes()
            config=preferences.cli_policy(saved,overrides)
            self.assertEqual(config['model'],'owner-reviewed-model-1');self.assertEqual(config['model_reasoning_effort'],'none')
            self.assertEqual((home/'preferences.json').read_bytes(),original)
            with self.assertRaises(preferences.PolicyArgumentError):preferences.cli_policy(config,{'model_reasoning_effort':'high'})


class TierTransportTests(unittest.TestCase):
    setUp=test_guard.GuardTests.setUp
    tearDown=test_guard.GuardTests.tearDown
    def test_selected_tier_and_custom_pool_reach_fake_transport(self):
        for tier in sorted(policy.TIERS):
            p=profile(tier);p['defaults']['output_token_cap']=10
            atomic_json(self.root/'verification.json',{'openai':{'enabled':True,'billing_policy':'metered','organization_id':'fake-org','project_id':'fake-project','quota_guard':True,'org_exclusive':True,'policy':p}})
            self.response=test_guard.Response({'usage':{'input_tokens':5,'output_tokens':4}})
            self.broker.openai({'model':'gpt-6.1-sol','input':'fixture'},lambda _:None,lambda _:None)
            body=self.calls[-1][2];self.assertEqual(body['service_tier'],tier)
            self.assertEqual(self.ledger.overlap_seconds,p['defaults']['request_deadline_seconds']+15)
        self.assertEqual(self.ledger.db.execute('SELECT DISTINCT scope FROM requests').fetchall(),[('openai:Daily',)])


class SharedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'team'
        self.policy=profile('flex',('Small','Large','Research'))
        atomic_json(self.root.parent/'verification.json',{'openai':{'policy':self.policy}})
        self.team=Team.initialize(self.root,'org-fixture',{'Small':0,'Large':0,'Research':0},all_traffic=True,clock=lambda:test_guard.NOW)
    def tearDown(self):self.team.close();self.tmp.cleanup()
    def test_organization_project_member_limits_share_same_dynamic_pools(self):
        self.team.add_member('alice','proj_fixture',{'Small':100,'Large':200,'Research':300})
        q=self.team.quota('alice');self.assertEqual(len(q['usage_lines']),3)
        ledger=MemberLedger(self.team,'alice');r=ledger.reserve_daily('Research',95000,20,{})
        ledger.dispatch_daily(r);ledger.settle(r,9)
        self.assertEqual(self.team.quota('alice')['daily_pools']['Research']['remaining'],291)
        self.team.defaults('alice',{'Small':101,'Large':202,'Research':303},operation='fixture-defaults')
        self.assertEqual(self.team.status()['members'][0]['defaults']['Research'],303)
        self.assertEqual(self.team.ledger.overlap_seconds,915)
        invite=json.loads((self.root/'invites/alice.json').read_text())
        self.assertEqual(invite['policy_digest'],policy.digest(self.policy))
    def test_transfer_and_requests_work_for_nonlegacy_pool(self):
        values={'Small':100,'Large':200,'Research':300}
        self.team.add_member('alice','proj_fixture',values);self.team.add_member('bob','proj_other',values)
        self.team.transfer('alice','bob',{'Small':0,'Large':0,'Research':20},operation='fixture-transfer')
        self.assertEqual(self.team.quota('bob')['daily_pools']['Research']['limit'],320)
        result=self.team.request_more('bob',{'group':'Research','amount':10,'request_id':'fixture-quota-request'})
        self.team.approve(result['request_id'],'alice')
        self.assertEqual(self.team.quota('bob')['daily_pools']['Research']['limit'],330)
    def test_free_only_rejects_requests_without_counting(self):
        self.team.add_member('alice','proj_fixture',{'Small':100,'Large':200,'Research':300})
        calls=[];broker=MemberBroker(self.team,'alice',transport=lambda *a:calls.append(a))
        with self.assertRaises(Denied):broker.openai({'model':'gpt-6.1-sol','input':'fixture'},lambda _:None,lambda _:None)
        self.assertEqual(calls,[])
