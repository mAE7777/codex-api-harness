"""UTC overlap, clock proof, and conservative reconciliation without real APIs."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from gateway import verify_provider_clock
from guard import Denied, Ledger, DAILY_LIMITS, UTC_OVERLAP_SECONDS, atomic_json, read_quota, utc_admission
from shared import Team, MemberLedger
import test_guard as fixtures

DAY='2026-10-21'
NEXT='2026-10-22'
MIDNIGHT=dt.datetime(2026,10,22,tzinfo=dt.timezone.utc).timestamp()


class TerminalOverlapTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.now=fixtures.NOW
        self.ledger=Ledger(self.root/'state',initialize=True,clock=lambda:self.now)
        for group in ('A','B'):self.ledger.configure_budget('openai:'+group,DAY,100)
        self.ledger.pause(False)

    def tearDown(self):self.ledger.close();self.temp.cleanup()

    def at(self,instant):
        self.ledger.last_wall+=instant-self.now;self.now=instant

    def request(self,seconds=30):
        self.at(MIDNIGHT-seconds)
        identity=self.ledger.reserve_daily('B',100,20,{})
        self.ledger.dispatch_daily(identity)
        return identity

    def receipt(self,identity,action='record_actual',actual=9):
        return {'version':1,'resolution_id':uuid.uuid4().hex,'request_id':identity,
                'expected_phase':'unknown','expected_reserved_tokens':20,'action':action,
                'actual_tokens':actual if action=='record_actual' else None,
                'evidence':{'kind':{'record_actual':'operator_verified_provider_usage','confirm_consumed':'operator_verified_completed','confirm_unused':'operator_verified_no_usage'}[action],
                            'reference':'synthetic-verified-completed-request','request_finished':True}}

    def test_same_local_day_terminal_is_also_shadowed_into_next_day(self):
        identity=self.request();self.ledger.settle(identity,9)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)
        self.assertEqual(self.ledger.db.execute('SELECT period,scope,amount FROM carryovers').fetchall(),[(NEXT,'openai:B',9)])
        self.at(MIDNIGHT+20);self.ledger.close()
        self.ledger=Ledger(self.root/'state',clock=lambda:self.now)
        head=self.ledger._head()
        view=read_quota(self.root/'state',{'A':100,'B':100},now=self.now)
        self.assertEqual(view['daily_pools']['B']['remaining'],91)
        self.assertEqual(self.ledger._head(),head)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)

    def test_early_request_has_no_future_day_shadow(self):
        identity=self.request(UTC_OVERLAP_SECONDS+0.1);self.ledger.settle(identity,9)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM carryovers').fetchone()[0],0)
        self.at(MIDNIGHT+20)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)

    def test_overlap_includes_the_exact_deadline_boundary(self):
        identity=self.request(UTC_OVERLAP_SECONDS);self.ledger.settle(identity,9)
        self.assertEqual(self.ledger.db.execute('SELECT amount FROM carryovers WHERE period=?',(NEXT,)).fetchone(),(9,))

    def test_real_next_day_terminal_is_counted_once_not_twice(self):
        identity=self.request();self.at(MIDNIGHT+20)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)
        self.ledger.settle(identity,9);self.ledger.settle(identity,9)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*),SUM(amount) FROM carryovers WHERE period=?',(NEXT,)).fetchone(),(1,9))

    def test_late_rejection_keeps_full_overlap_across_restart_and_duplicate_rejection(self):
        identity=self.request(1);self.ledger.reject(identity);self.ledger.reject(identity)
        self.assertEqual(self.ledger.status()['unresolved'],0)
        self.at(MIDNIGHT+16);self.ledger.close()
        self.ledger=Ledger(self.root/'state',clock=lambda:self.now)
        self.ledger.reject(identity)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)
        self.assertEqual(read_quota(self.root/'state',{'A':100,'B':100},now=self.now)['daily_pools']['B']['remaining'],80)
        self.assertEqual(self.ledger.db.execute('SELECT period,amount FROM carryovers').fetchall(),[(NEXT,20)])

    def test_next_day_rejection_retains_the_existing_unknown_hold_once(self):
        identity=self.request(1);self.at(MIDNIGHT+16)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)
        self.ledger.reject(identity);self.ledger.reject(identity)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*),SUM(amount) FROM carryovers').fetchone(),(1,20))

    def test_early_rejection_does_not_shadow_an_unambiguous_day(self):
        identity=self.request(UTC_OVERLAP_SECONDS+1);self.ledger.reject(identity)
        self.at(MIDNIGHT+16)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM carryovers').fetchone()[0],0)

    def test_actual_reconciliation_applies_same_shadow_and_replays_idempotently(self):
        identity=self.request();receipt=self.receipt(identity)
        self.assertTrue(self.ledger.reconcile(receipt)['applied'])
        self.assertFalse(self.ledger.reconcile(receipt)['applied'])
        self.at(MIDNIGHT+20)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*),SUM(amount) FROM carryovers WHERE period=?',(NEXT,)).fetchone(),(1,9))

    def test_confirmed_consumption_keeps_full_shadow_instead_of_refunding_new_day(self):
        identity=self.request();receipt=self.receipt(identity,'confirm_consumed')
        self.ledger.reconcile(receipt);self.at(MIDNIGHT+20)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],80)
        self.assertFalse(self.ledger.reconcile(receipt)['applied'])

    def test_confirmed_no_usage_never_creates_a_positive_shadow(self):
        identity=self.request();self.ledger.reconcile(self.receipt(identity,'confirm_unused'))
        self.at(MIDNIGHT+20)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)

    def test_search_monthly_settlement_does_not_gain_an_openai_shadow(self):
        self.ledger.configure_budget('tavily','2026-10',100)
        identity=self.ledger.reserve('tavily','2026-10',20,{})
        self.ledger.dispatch(identity);self.at(MIDNIGHT-1);self.ledger.settle(identity,9)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM carryovers').fetchone()[0],0)

    def test_operator_baseline_does_not_invent_request_timestamps(self):
        with self.ledger.transaction():self.ledger.db.execute("UPDATE budgets SET baseline=7 WHERE scope='openai:B'")
        self.at(MIDNIGHT-1)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],93)
        self.at(MIDNIGHT+20)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM carryovers').fetchone()[0],0)


class SharedOverlapTests(unittest.TestCase):
    def test_member_project_and_organization_see_the_same_durable_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            now=[MIDNIGHT-30];root=Path(temporary)/'team'
            team=Team.initialize(root,'org-overlaptest',0,0,all_traffic=True,clock=lambda:now[0])
            try:
                team.add_member('alice','proj_sharedexample',100,100)
                team.add_member('bob','proj_sharedexample',100,100)
                team.project_limits('proj_sharedexample',100,100,operation='project-ceiling')
                alice=MemberLedger(team,'alice')
                request=alice.reserve_daily('B',DAILY_LIMITS['B'],20,{})
                alice.dispatch_daily(request);alice.settle(request,9)
                delta=MIDNIGHT+20-now[0];now[0]+=delta;team.ledger.last_wall+=delta
                self.assertEqual(team.quota('alice')['daily_pools']['B']['remaining'],91)
                self.assertEqual(team.quota('bob')['daily_pools']['B']['remaining'],91)
                self.assertEqual(team.status()['organization_pools']['B']['remaining'],DAILY_LIMITS['B']-9)
            finally:team.close()
            team=Team(root,clock=lambda:now[0])
            try:
                self.assertEqual(team.quota('alice')['daily_pools']['B']['remaining'],91)
                self.assertEqual(team.quota('bob')['daily_pools']['B']['project_remaining'],91)
            finally:team.close()

    def test_late_rejection_preserves_member_project_and_org_full_debits(self):
        with tempfile.TemporaryDirectory() as temporary:
            now=[MIDNIGHT-1];root=Path(temporary)/'team'
            team=Team.initialize(root,'org-rejecttest',0,0,all_traffic=True,clock=lambda:now[0])
            try:
                team.add_member('alice','proj_sharedexample',100,100)
                team.add_member('bob','proj_sharedexample',100,100)
                team.project_limits('proj_sharedexample',100,100,operation='project-ceiling')
                alice=MemberLedger(team,'alice')
                request=alice.reserve_daily('B',DAILY_LIMITS['B'],20,{})
                alice.dispatch_daily(request);alice.reject(request);alice.reject(request)
                delta=MIDNIGHT+16-now[0];now[0]+=delta;team.ledger.last_wall+=delta
                self.assertEqual(team.quota('alice')['daily_pools']['B']['remaining'],80)
                self.assertEqual(team.quota('bob')['daily_pools']['B']['project_remaining'],80)
                self.assertEqual(team.status()['organization_pools']['B']['remaining'],DAILY_LIMITS['B']-20)
            finally:team.close()
            team=Team(root,clock=lambda:now[0])
            try:
                self.assertEqual(team.quota('alice')['daily_pools']['B']['remaining'],80)
                self.assertEqual(team.quota('bob')['daily_pools']['B']['project_remaining'],80)
            finally:team.close()


class ClockProofTests(unittest.TestCase):
    setUp=fixtures.GuardTests.setUp
    tearDown=fixtures.GuardTests.tearDown

    def daily(self):
        profile=json.loads((self.root/'verification.json').read_text())
        profile['openai'].update(billing_policy='metered',quota_guard=True,org_exclusive=True,
                                 daily_token_limits={'A':100,'B':100},output_token_cap=10)
        atomic_json(self.root/'verification.json',profile)

    def at(self,instant):
        self.now=instant
        self.ledger.clock=lambda:self.now;self.ledger.last_wall=self.now;self.ledger.last_mono=time.monotonic()
        self.broker.clock=lambda:self.now

    def request(self):return self.broker.openai(self.payload,lambda _:None,lambda _:None)

    def test_first_fifteen_seconds_are_explicitly_guarded_without_a_pre_midnight_blackout(self):
        for instant in (MIDNIGHT,MIDNIGHT+1,MIDNIGHT+14.999):
            with self.subTest(instant=instant),self.assertRaises(Denied) as error:utc_admission(instant)
            self.assertEqual(error.exception.code,'utc_day_transition')
            self.assertGreaterEqual(error.exception.details['retry_after_seconds'],1)
        utc_admission(MIDNIGHT-1);utc_admission(MIDNIGHT+15)

    def test_utc_guard_stops_even_counting_and_preserves_a_new_operation_key(self):
        self.daily();self.at(MIDNIGHT+1)
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'utc_day_transition');self.assertEqual(self.calls,[])
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)

    def test_utc_guard_is_checked_again_after_count_and_voids_the_unsent_permit(self):
        self.daily();self.at(MIDNIGHT-1)
        def transport(host,path,body,headers):
            self.calls.append(path)
            if path.endswith('/input_tokens'):
                self.now=MIDNIGHT+2
                return fixtures.Connection(),fixtures.Response({'input_tokens':5},date=self.now)
            raise AssertionError('Generation must not be dispatched during the UTC guard')
        self.broker.transport=transport
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'utc_day_transition')
        self.assertEqual(self.calls,['/v1/responses/input_tokens'])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(0,0,'not_sent'))

    def test_valid_late_request_is_dispatched_normally_and_shadowed(self):
        self.daily();self.at(MIDNIGHT-1)
        def transport(host,path,body,headers):
            self.calls.append(path)
            data={'input_tokens':5} if path.endswith('/input_tokens') else {'usage':{'input_tokens':5,'output_tokens':4}}
            return fixtures.Connection(),fixtures.Response(data,date=self.now)
        self.broker.transport=transport;self.request()
        self.assertEqual(self.calls,['/v1/responses/input_tokens','/v1/responses'])
        self.assertEqual(self.ledger.db.execute('SELECT period,amount FROM carryovers').fetchall(),[(NEXT,9)])

    def test_valid_request_resumes_at_fifteen_seconds(self):
        self.daily();self.at(MIDNIGHT+15)
        def transport(host,path,body,headers):
            self.calls.append(path)
            data={'input_tokens':5} if path.endswith('/input_tokens') else {'usage':{'input_tokens':5,'output_tokens':4}}
            return fixtures.Connection(),fixtures.Response(data,date=self.now)
        self.broker.transport=transport;self.request()
        self.assertEqual(self.calls,['/v1/responses/input_tokens','/v1/responses'])

    def test_missing_invalid_old_and_future_dates_stop_before_generation(self):
        self.daily()
        examples=[(None,'provider_clock_unverified'),('invalid','provider_clock_unverified'),
                  ('Wed, 21 Oct 2026 12:00:00 +0000','provider_clock_unverified'),
                  ('Thu, 21 Oct 2026 12:00:00 GMT','provider_clock_unverified'),
                  (fixtures.NOW-7,'provider_clock_mismatch'),(fixtures.NOW+7,'provider_clock_mismatch')]
        for date,code in examples:
            with self.subTest(date=date):
                before=len(self.calls)
                def transport(host,path,body,headers):
                    self.calls.append(path)
                    if path!='/v1/responses/input_tokens':raise AssertionError('Unverified clock dispatched a model')
                    return fixtures.Connection(),fixtures.Response({'input_tokens':5},date=date)
                self.broker.transport=transport
                with self.assertRaises(Denied) as error:self.request()
                self.assertEqual(error.exception.code,code)
                self.assertEqual(self.calls[before:],['/v1/responses/input_tokens'])
        self.assertEqual(self.ledger.status()['requests'],0)

    def test_initial_absolute_os_clock_error_is_detected_even_with_stable_monotonic_clock(self):
        self.daily();self.broker.clock=lambda:fixtures.NOW+86400
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'provider_clock_mismatch')
        self.assertEqual([row[1] for row in self.calls],['/v1/responses/input_tokens'])

    def test_five_second_tolerance_plus_date_precision_is_explicit(self):
        for offset in (-6,0,6):verify_provider_clock(fixtures.Response({},date=fixtures.NOW+offset),fixtures.NOW)
        for offset in (-7,7):
            with self.assertRaises(Denied):verify_provider_clock(fixtures.Response({},date=fixtures.NOW+offset),fixtures.NOW)
