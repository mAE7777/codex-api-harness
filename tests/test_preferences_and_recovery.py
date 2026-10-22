import contextlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

import controller
import gateway
import recovery
import test_guard as fixtures
import test_http as http_fixtures
from guard import Denied, Ledger, atomic_json, read_quota, readonly_database
from transport_control import RequestControl

spec = importlib.util.spec_from_file_location('guest_preferences', Path(__file__).parents[1]/'kit/preferences.py')
preferences = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preferences)


class PreferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)/'private'; self.home.mkdir()
        self.base = Path(__file__).parents[1]/'kit/config.toml'
    def tearDown(self): self.temp.cleanup()

    def test_model_effort_and_ui_survive_restart_without_importing_policy(self):
        (self.home/'config.toml').write_text('model="gpt-6.1-sol"\nmodel_reasoning_effort="high"\nmodel_provider="evil"\n[features]\nimage_generation=true\n[tui]\ntheme="nord"\nstatus_line=["model-with-reasoning","context-remaining"]\nstatus_line_use_colors=false\n')
        preferences.prepare(self.home,self.base)
        preferences.save(self.home)
        preferences.prepare(self.home,self.base)
        result=preferences.read_config(self.home/'config.toml')
        self.assertEqual(result['model'],'gpt-6.1-sol');self.assertEqual(result['model_reasoning_effort'],'high')
        self.assertEqual(result['tui']['theme'],'nord')
        self.assertFalse(result['tui']['status_line_use_colors'])
        self.assertEqual(result['model_provider'],'quota_gateway');self.assertFalse(result['features']['image_generation'])
        self.assertNotIn('evil',(self.home/'preferences.json').read_text())

    def test_corrupt_native_config_recovers_only_saved_preferences(self):
        (self.home/'preferences.json').write_text(json.dumps({'model':'gpt-5.6-luna','model_reasoning_effort':'high','notify':['steal']}))
        (self.home/'config.toml').write_text('not valid toml = [')
        preferences.prepare(self.home,self.base)
        result=preferences.read_config(self.home/'config.toml')
        self.assertEqual(result['model'],'gpt-5.6-luna');self.assertNotIn('notify',result)

    def test_unknown_model_path_theme_and_command_status_items_are_not_kept(self):
        result=preferences.select_preferences({'model':'unapproved','model_reasoning_effort':'bad','tui':{'theme':'../../private','status_line':['$(cat key)']},'mcp_servers':{'x':{}}})
        self.assertEqual(result,{})

    def test_symlinked_config_never_overwrites_target(self):
        target=Path(self.temp.name)/'subscription.toml';target.write_text('preserve')
        (self.home/'config.toml').symlink_to(target)
        with self.assertRaises(ValueError):preferences.prepare(self.home,self.base)
        self.assertEqual(target.read_text(),'preserve')

    def test_private_saved_file_contains_no_policy_or_auth(self):
        (self.home/'config.toml').write_text(self.base.read_text())
        preferences.save(self.home)
        self.assertFalse((self.home/'preferences.json').stat().st_mode & 0o077)
        self.assertNotIn('model_providers',(self.home/'preferences.json').read_text())


class DailyFixture(unittest.TestCase):
    setUp=fixtures.GuardTests.setUp
    tearDown=fixtures.GuardTests.tearDown
    request=fixtures.GuardTests.request
    def daily(self):
        data=json.loads((self.root/'verification.json').read_text())
        data['openai'].update(billing_policy='metered',quota_guard=True,org_exclusive=True,daily_token_limits={'A':100,'B':100},output_token_cap=10)
        atomic_json(self.root/'verification.json',data)
    def pending(self):
        self.daily()
        request=self.ledger.reserve_daily('B',100,20,{})
        self.ledger.dispatch_daily(request)
        return request
    def receipt(self,request,action='record_actual',actual=9):
        return {'version':1,'resolution_id':uuid.uuid4().hex,'request_id':request,'expected_phase':'unknown','expected_reserved_tokens':20,
                'action':action,'actual_tokens':actual,
                'evidence':{'kind':{'record_actual':'operator_verified_provider_usage','confirm_unused':'operator_verified_no_usage','confirm_consumed':'operator_verified_completed'}[action],
                            'reference':'verified-export-2026-10-21-item-1','request_finished':True}}


class QuotaViewTests(DailyFixture):
    def test_stopped_query_creates_no_sqlite_sidecars_or_accounting_writes(self):
        self.daily();self.ledger.close()
        state=self.root/'state';before={p.name:p.read_bytes() for p in state.iterdir() if p.is_file()}
        try:
            result=read_quota(state,{'A':100,'B':100},now=fixtures.NOW)
            self.assertEqual(len(result['usage_lines']),2)
            self.assertEqual(before,{p.name:p.read_bytes() for p in state.iterdir() if p.is_file()})
        finally:self.ledger=Ledger(state,clock=lambda:fixtures.NOW)

    def test_live_wal_is_read_and_never_opened_immutable(self):
        import sqlite3
        self.daily();self.pending()
        with patch('guard.sqlite3.connect',wraps=sqlite3.connect) as connect:
            result=read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW)
        self.assertEqual(result['daily_pools']['B']['remaining'],80)
        self.assertNotIn('immutable',connect.call_args.args[0])

    def test_symlinked_ledger_is_not_followed(self):
        self.ledger.close()
        path=self.root/'state/usage.sqlite3'; moved=path.with_name('other.sqlite3');path.rename(moved);path.symlink_to(moved)
        try:
            with self.assertRaises(Denied) as error:read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW)
            self.assertEqual(error.exception.code,'quota_state_unavailable')
        finally:path.unlink();moved.rename(path);self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW)

    def test_snapshot_matches_admission_including_baseline_and_does_not_write(self):
        self.daily()
        with self.ledger.transaction():self.ledger.db.execute("UPDATE budgets SET baseline=7 WHERE scope='openai:B'")
        request=self.pending()
        self.ledger.settle(request,9)
        head=self.ledger._head()
        view=read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW)
        self.assertEqual(view['daily_pools']['B']['remaining'],84)
        self.assertEqual(view['daily_pools']['B']['used_or_reserved'],16)
        self.assertEqual(view['daily_pools']['B']['remaining'],self.ledger.daily_remaining('B',100)['remaining'])
        # Admission above may update its witness; repeated view calls must not.
        head=self.ledger._head()
        for _ in range(3):read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW)
        self.assertEqual(self.ledger._head(),head)

    def test_host_usage_does_not_read_credentials_scan_workspace_or_check_subscription(self):
        self.daily()
        with patch.object(controller,'ROOT',self.root),patch.object(controller,'blockers',side_effect=AssertionError('heavy check')),patch.object(controller,'credentials',side_effect=AssertionError('credential read')),patch.object(controller,'subscription_unchanged',side_effect=AssertionError('subscription read')),contextlib.redirect_stdout(io.StringIO()) as out:
            controller.status(usage_only=True)
        lines=out.getvalue().splitlines()
        self.assertEqual(len(lines),2);self.assertTrue(lines[0].startswith('A ('));self.assertTrue(lines[1].startswith('B ('))
        self.assertTrue(out.getvalue().isascii())

    def test_witness_mismatch_has_no_guessed_balance_or_reset(self):
        self.daily();head=self.ledger._head()
        atomic_json(self.root/'state/ledger-witness.json',{'identity':'wrong','sequence':0})
        with self.assertRaises(Denied) as e:read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW)
        self.assertEqual(e.exception.code,'quota_reconciliation_required');self.assertEqual(self.ledger._head(),head)

    def test_prior_unknown_carries_into_read_only_next_day_view(self):
        self.pending()
        view=read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW+86400)
        self.assertEqual(view['daily_pools']['B']['remaining'],80)
        self.assertFalse(self.ledger.db.execute('SELECT 1 FROM budgets WHERE period=?',('2026-10-22',)).fetchone())


class QuotaHTTPTests(unittest.TestCase):
    setUp=http_fixtures.HTTPTests.setUp
    tearDown=http_fixtures.HTTPTests.tearDown
    call=http_fixtures.HTTPTests.call
    def test_authenticated_quota_is_local_read_only_even_while_paused(self):
        data=json.loads((self.root/'verification.json').read_text());data['openai']['daily_token_limits']={'A':100,'B':100}
        atomic_json(self.root/'verification.json',data);(self.root/'paused').touch()
        before=self.ledger._head()
        status,result=self.call('/v1/quota',method='GET')
        self.assertEqual(status,200);self.assertEqual(len(result['usage_lines']),2)
        self.assertEqual(self.calls,[]);self.assertEqual(self.ledger._head(),before)
    def test_quota_requires_gateway_authentication(self):
        self.assertEqual(self.call('/v1/quota',method='GET',token=False)[0],403)
        self.assertEqual(self.calls,[])


class RecoveryTests(DailyFixture):
    def test_active_session_cannot_apply_even_with_paused_marker(self):
        import fcntl
        request=self.pending();path=recovery.template(self.root,request)
        path.write_text(json.dumps(self.receipt(request)));(self.root/'paused').touch()
        with (self.root/'session.lock').open('a+b') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(Denied,'active API Codex session'):recovery.apply(self.root,path)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)

    def test_read_only_inspection_does_not_modify_pending_or_witness(self):
        request=self.pending();before=self.ledger._head()
        result=recovery.inspect(self.root)
        self.assertTrue(result['verified']);self.assertEqual(result['requests'][0]['id'],request)
        self.assertEqual(self.ledger._head(),before);self.assertEqual(self.calls,[])

    def test_actual_usage_is_recorded_once_and_conflicting_replay_is_denied(self):
        request=self.pending();receipt=self.receipt(request)
        self.assertTrue(self.ledger.reconcile(receipt)['applied'])
        self.assertFalse(self.ledger.reconcile(receipt)['applied'])
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)
        with self.assertRaises(Denied):self.ledger.reconcile({**receipt,'actual_tokens':0})
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)

    def test_no_refund_without_completed_request_and_reviewed_evidence(self):
        request=self.pending();receipt=self.receipt(request,'confirm_unused',None)
        receipt['evidence']['request_finished']=False
        with self.assertRaises(Denied):self.ledger.reconcile(receipt)
        receipt['evidence']['request_finished']=True;receipt['evidence']['reference']='REPLACE_WITH_EVIDENCE'
        with self.assertRaises(Denied):self.ledger.reconcile(receipt)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)

    def test_unknown_finished_consumption_keeps_full_charge_without_inventing_actual(self):
        request=self.pending();receipt=self.receipt(request,'confirm_consumed',None)
        self.ledger.close();self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW+86400)
        self.ledger.reconcile(receipt)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)
        self.assertIsNone(self.ledger.db.execute('SELECT actual FROM requests WHERE id=?',(request,)).fetchone()[0])
        view=read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW+2*86400)
        self.assertEqual(view['daily_pools']['B']['remaining'],100)

    def test_changed_request_state_cannot_be_overwritten_by_old_receipt(self):
        request=self.pending();receipt=self.receipt(request);self.ledger.settle(request,9)
        with self.assertRaises(Denied):self.ledger.reconcile(receipt)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)

    def test_correcting_under_reservation_records_usage_but_keeps_safety_stop(self):
        request=self.pending();receipt=self.receipt(request,actual=21)
        self.ledger.reconcile(receipt)
        self.assertTrue((self.root/'state/safety-stop.json').exists())
        self.assertEqual(read_quota(self.root/'state',{'A':100,'B':100},now=fixtures.NOW)['daily_pools']['B']['remaining'],79)
        with self.assertRaises(Denied):self.ledger.daily_remaining('B',100)

    def test_private_template_is_unapproved_and_apply_requires_stopped_session(self):
        request=self.pending();path=recovery.template(self.root,request)
        receipt=json.loads(path.read_text())
        self.assertFalse(receipt['evidence']['request_finished']);self.assertFalse(path.stat().st_mode & 0o077)
        path.write_text(json.dumps(self.receipt(request)))
        with self.assertRaises(Denied):recovery.apply(self.root,path)
        self.ledger.close();(self.root/'paused').touch()
        try:
            result=recovery.apply(self.root,path)
            self.assertTrue(result['applied'])
        finally:self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)

    def test_receipt_from_shared_or_external_directory_is_rejected(self):
        request=self.pending();path=self.root/'shared-plan.json';path.write_text(json.dumps(self.receipt(request)));path.chmod(0o600)
        with self.assertRaises(Denied):recovery.apply(self.root,path)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)


class DiagnosticTests(DailyFixture):
    def test_doctor_is_redacted_and_unknown_free_eligibility_is_only_a_warning(self):
        self.daily()
        data=json.loads((self.root/'verification.json').read_text());data['openai']['count_endpoint_free_confirmed']=False
        atomic_json(self.root/'verification.json',data)
        atomic_json(self.root/'readiness.json',{k:True for k in ('filesystem_tested','network_tested','host_integrations_absent')})
        with patch.object(controller,'ROOT',self.root),patch.object(controller,'integrity'),patch.object(controller,'workspace_check'),patch.object(controller,'runtime_state',return_value='stopped'),patch.object(controller,'subscription_unchanged',return_value=True),contextlib.redirect_stdout(io.StringIO()):
            result=controller.doctor(bundle=True)
        self.assertTrue(result['passed']);self.assertEqual(self.calls,[])
        self.assertTrue(any(c['status']=='WARN' for c in result['checks']))
        saved=next((self.root/'diagnostics').glob('*.json')).read_text()
        self.assertNotIn('fake-test-only-key',saved);self.assertNotIn(str(self.root),saved)

    def test_explain_is_local_and_permission_summary_has_no_key(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            result=controller.explain('daily_token_limit')
        self.assertIn('00:00:15 UTC',result['next_step']);self.assertTrue(out.getvalue().isascii());self.assertEqual(self.calls,[])

    def test_stale_gateway_marker_is_not_reported_as_running(self):
        atomic_json(self.root/'gateway-process.json',{'pid':12345,'identity':'old gateway'})
        with patch.object(controller,'ROOT',self.root),patch.object(controller,'process_identity',return_value=None):
            self.assertEqual(controller.runtime_state(),'stale')


class PhaseCancellationTests(DailyFixture):
    def test_cancel_during_count_body_has_no_model_dispatch(self):
        self.daily();entered=threading.Event();release=threading.Event();cancel=threading.Event()
        original=self.broker.transport
        class Response(fixtures.Response):
            def read(inner,*args):entered.set();release.wait(2);return super().read(*args)
        def transport(host,path,body,headers,method='POST'):
            if path.endswith('input_tokens'):
                self.calls.append((host,path,body,headers,method))
                return fixtures.Connection(),Response({'input_tokens':5})
            return original(host,path,body,headers,method)
        self.broker.transport=transport
        def cancel_after_read():entered.wait(1);cancel.set()
        worker=threading.Thread(target=cancel_after_read);worker.start()
        try:
            with self.assertRaises(Denied) as error:self.broker.openai(self.payload,lambda _:None,lambda _:None,cancelled=cancel.is_set)
            self.assertEqual(error.exception.code,'client_cancelled');self.assertEqual(self.ledger.status()['requests'],0);self.assertEqual(len(self.calls),1)
        finally:release.set();worker.join()

    def test_socket_timeout_has_specific_phase_without_retry(self):
        class TimedConnection:
            def __init__(inner,*args,**kwargs):pass
            def request(inner,*args,**kwargs):raise TimeoutError()
            def close(inner):pass
        with patch.object(gateway.http.client,'HTTPSConnection',TimedConnection):
            with self.assertRaises(Denied) as error:gateway.upstream('api.openai.com','/v1/responses',{}, {}, phase='response_headers')
        self.assertEqual(error.exception.code,'api_timeout');self.assertEqual(error.exception.details['phase'],'response_headers')

    def delayed_transport(self, delayed_path):
        entered=threading.Event();release=threading.Event();closed=threading.Event()
        original=self.broker.transport
        class Connection:
            def close(inner):closed.set()
        def transport(host,path,body,headers,method='POST'):
            if path==delayed_path:
                self.calls.append((host,path,body,headers,method));entered.set();release.wait(3)
                value={'input_tokens':5} if path.endswith('input_tokens') else {'usage':{'input_tokens':5,'output_tokens':4}}
                return Connection(),fixtures.Response(value)
            return original(host,path,body,headers,method)
        self.broker.transport=transport
        return entered,release,closed

    def check_cancel(self,path,expected_requests):
        self.daily();entered,release,closed=self.delayed_transport(path);cancel=threading.Event()
        def cancel_after_entry():
            entered.wait(1);cancel.set()
        worker=threading.Thread(target=cancel_after_entry);worker.start();started=time.monotonic()
        try:
            with self.assertRaises(Denied) as error:self.broker.openai(self.payload,lambda _:None,lambda _:None,cancelled=cancel.is_set)
            self.assertEqual(error.exception.code,'client_cancelled');self.assertLess(time.monotonic()-started,1)
            self.assertEqual(self.ledger.status()['requests'],expected_requests)
        finally:release.set();worker.join()
        self.assertTrue(closed.wait(1))
        return error.exception

    def test_cancel_during_count_never_dispatches_or_reserves_model(self):
        error=self.check_cancel('/v1/responses/input_tokens',0)
        self.assertEqual(error.details['phase'],'input_count');self.assertEqual(len(self.calls),1)

    def test_cancel_before_headers_returns_promptly_and_preserves_uncertain_usage(self):
        error=self.check_cancel('/v1/responses',1)
        self.assertEqual(error.details['phase'],'response_headers')
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],85)

    def test_header_timeout_has_specific_phase_and_never_retries(self):
        self.daily();entered,release,closed=self.delayed_transport('/v1/responses')
        class FastControl(RequestControl):
            def begin(inner,phase,timeout):super(FastControl,inner).begin(phase,.12 if phase=='response_headers' else timeout)
        try:
            with patch.object(gateway,'RequestControl',FastControl),self.assertRaises(Denied) as error:
                self.request()
            self.assertEqual(error.exception.code,'api_timeout');self.assertEqual(error.exception.details['phase'],'response_headers')
            self.assertEqual(len(self.calls),2);self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],85)
        finally:release.set()
        self.assertTrue(closed.wait(1))

    def test_stop_during_header_wait_cancels_without_waiting_for_transport_timeout(self):
        self.daily();entered,release,closed=self.delayed_transport('/v1/responses')
        def stop_after_entry():entered.wait(1);(self.root/'paused').touch()
        worker=threading.Thread(target=stop_after_entry);worker.start()
        try:
            started=time.monotonic()
            with self.assertRaises(Denied) as error:self.request()
            self.assertEqual(error.exception.code,'client_cancelled');self.assertLess(time.monotonic()-started,1)
            self.assertEqual(self.ledger.status()['unresolved'],1)
        finally:release.set();worker.join()
        self.assertTrue(closed.wait(1))

    def test_total_deadline_is_not_extended_by_phase_changes(self):
        with RequestControl(lambda:False,lambda:False,total=.09) as control:
            control.begin('response_stream',1)
            while time.monotonic()<control.total_deadline:time.sleep(.01)
            with self.assertRaises(Denied) as error:control.touch()
            self.assertEqual(error.exception.code,'api_response_deadline')


if __name__=='__main__':unittest.main()
