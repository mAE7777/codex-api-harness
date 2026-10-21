import datetime as dt
import json
import signal
import subprocess
from unittest.mock import patch

import unittest
import test_guard as fixtures
NOW,DAY,Response,Connection=fixtures.NOW,fixtures.DAY,fixtures.Response,fixtures.Connection
from guard import Denied, Ledger, atomic_json
from gateway import provider_error, public_error


class UXTests(unittest.TestCase):
    setUp=fixtures.GuardTests.setUp
    tearDown=fixtures.GuardTests.tearDown
    request=fixtures.GuardTests.request
    metered=fixtures.GuardTests.metered
    def daily(self):
        self.metered()
        v=json.loads((self.root/'verification.json').read_text())
        v['openai'].update(quota_guard=True,org_exclusive=True,daily_token_limits={'A':100,'B':100},output_token_cap=10)
        atomic_json(self.root/'verification.json',v)

    def test_quota_preflight_stops_before_model_when_whole_request_does_not_fit(self):
        self.daily()
        request=self.ledger.reserve('openai:B',DAY,90,{})
        self.ledger.dispatch(request);self.ledger.settle(request,90)
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'daily_token_limit')
        self.assertEqual(error.exception.details['remaining'],10)
        self.assertEqual([c[1] for c in self.calls],['/v1/responses/input_tokens'])

    def test_fully_exhausted_pool_stops_even_count_but_other_group_works(self):
        self.daily()
        request=self.ledger.reserve('openai:B',DAY,100,{})
        self.ledger.dispatch(request);self.ledger.settle(request,100)
        with self.assertRaises(Denied):self.request()
        self.assertEqual(self.calls,[])
        self.request({**self.payload,'model':'gpt-6-astra'})
        self.assertEqual(self.ledger.daily_remaining('A',100)['remaining'],91)

    def test_new_day_creates_budget_automatically_without_resetting_history(self):
        self.daily();self.request();self.ledger.close()
        self.ledger=Ledger(self.root/'state',clock=lambda:NOW+86400)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)
        self.assertEqual(self.ledger.status()['requests'],1)

    def test_five_percent_limits_accept_requests_but_reject_higher_limits(self):
        self.daily()
        limits={'A':237500,'B':2375000}
        receipt=json.loads((self.root/'verification.json').read_text())
        receipt['openai']['daily_token_limits']=limits.copy()
        atomic_json(self.root/'verification.json',receipt)
        with self.ledger.transaction():
            for group,limit in limits.items():
                self.ledger.db.execute('UPDATE budgets SET ceiling=? WHERE scope=? AND period=?',(limit,'openai:'+group,DAY))
        for group,model in [('A','gpt-6-astra'),('B','gpt-5.6-terra')]:
            with self.subTest(group=group):
                self.response=Response({'usage':{'input_tokens':5,'output_tokens':4}})
                self.request({**self.payload,'model':model})
                self.assertEqual(self.ledger.daily_remaining(group,limits[group])['remaining'],limits[group]-9)
                invalid=json.loads(json.dumps(receipt))
                invalid['openai']['daily_token_limits'][group]+=1
                atomic_json(self.root/'verification.json',invalid)
                self.calls.clear()
                with self.assertRaisesRegex(Denied,'Invalid configured daily limit'):
                    self.request({**self.payload,'model':model})
                self.assertEqual(self.calls,[])
                atomic_json(self.root/'verification.json',receipt)

    def test_prior_unclassified_usage_is_conservatively_charged_to_both_pools(self):
        self.metered();self.request();self.daily()
        # Rebuild only the synthetic empty budgets, never production budgets.
        self.ledger.db.execute('DELETE FROM budgets')
        self.assertEqual(self.ledger.daily_remaining('A',100)['remaining'],91)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)

    def test_cancel_closes_upstream_keeps_reservation_and_allows_further_safe_use(self):
        self.daily()
        self.response=Response(raw=b'data: {"type":"response.created"}\n\n',content_type='text/event-stream')
        class TrackedConnection:
            closed=False
            def close(inner):inner.closed=True
        connection=TrackedConnection()
        original=self.broker.transport
        def transport(host,path,body,headers,method='POST'):
            conn,response=original(host,path,body,headers,method)
            return (connection,response) if path=='/v1/responses' else (conn,response)
        self.broker.transport=transport
        def disconnect(_):raise BrokenPipeError()
        with self.assertRaises(Denied) as e:self.broker.openai({**self.payload,'stream':True},lambda _:None,disconnect)
        self.assertEqual(e.exception.code,'client_cancelled')
        self.assertTrue(connection.closed)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],85)
        self.response=Response({'usage':{'input_tokens':5,'output_tokens':4}})
        self.request()
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],76)

    def test_unresolved_carry_and_late_settlement_do_not_erase_next_day_usage(self):
        self.daily()
        request=self.ledger.reserve_daily('B',100,15,{})
        self.ledger.dispatch_daily(request);self.ledger.close()
        self.ledger=Ledger(self.root/'state',clock=lambda:NOW+86400)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],85)
        self.ledger.settle(request,9)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)
        self.ledger.close();self.ledger=Ledger(self.root/'state',clock=lambda:NOW+86400)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],91)

    def test_concurrent_daily_reservations_cannot_oversubscribe(self):
        import threading
        self.daily(); results=[]
        def take():
            try:results.append(self.ledger.reserve_daily('B',100,60,{}))
            except Denied:pass
        threads=[threading.Thread(target=take) for _ in range(10)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(len(results),1)

    def test_provider_errors_are_specific_and_do_not_echo_secrets(self):
        for status,code in [(401,'invalid_api_key'),(429,'credit_balance_exhausted'),(429,'project_spend_limit_exceeded'),(429,'organization_spend_limit_exceeded'),(429,'rate_limit_error'),(400,'invalid_request_error')]:
            r=Response({'error':{'code':code,'message':'FAKE_SECRET_AND_PRIVATE_PROMPT','param':'model'}},status=status)
            e=provider_error(r)
            self.assertEqual(e.status,status);self.assertEqual(e.code,code)
            body=public_error(e)
            self.assertNotIn('FAKE_SECRET',json.dumps(body))
            self.assertEqual(body['param'],'model')

    def test_provider_rejection_is_not_unknown_and_does_not_permanently_freeze(self):
        self.daily();self.response=Response({'error':{'code':'rate_limit_error'}},status=429)
        with self.assertRaises(Denied):self.request()
        self.assertEqual(self.ledger.status()['unresolved'],0)
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],85)

    def test_count_endpoint_failure_never_sends_inference(self):
        self.daily()
        def transport(*args,**kwargs):
            self.calls.append(args[1]);return Connection(),Response({'error':{'code':'invalid_api_key'}},status=401)
        self.broker.transport=transport
        with self.assertRaises(Denied) as e:self.request()
        self.assertEqual(e.exception.status,401)
        self.assertEqual(self.calls,['/v1/responses/input_tokens'])

    def test_cancel_before_dispatch_does_not_leave_a_phantom_debit(self):
        self.daily();original=self.broker.transport
        def transport(host,path,body,headers,method='POST'):
            result=original(host,path,body,headers,method)
            if path.endswith('input_tokens'):(self.root/'paused').touch()
            return result
        self.broker.transport=transport
        with self.assertRaises(Denied):self.request()
        self.assertEqual([c[1] for c in self.calls],['/v1/responses/input_tokens'])
        self.assertEqual(self.ledger.daily_remaining('B',100)['remaining'],100)
        self.assertEqual(self.ledger.status()['unresolved'],0)

    def test_streamed_provider_failure_keeps_specific_code_and_hides_raw_message(self):
        self.daily()
        event={'type':'response.failed','response':{'error':{'code':'credit_balance_exhausted','message':'PRIVATE_TEXT'},'usage':None}}
        self.response=Response(raw=b'data: '+json.dumps(event).encode()+b'\n\n',content_type='text/event-stream')
        chunks=[]
        with self.assertRaises(Denied) as e:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(e.exception.code,'credit_balance_exhausted')
        self.assertEqual(chunks,[])

    def test_cancel_while_upstream_is_silent_does_not_wait_for_next_token(self):
        import threading,time
        self.daily();closed=threading.Event();cancel=threading.Event()
        class SilentResponse:
            status=200
            def getheader(inner,*_):return 'text/event-stream'
            def readline(inner,*_):
                if not closed.wait(2):raise AssertionError('Cancellation did not close the upstream')
                return b''
        class CancelConnection:
            def close(inner):closed.set()
        original=self.broker.transport
        def transport(host,path,body,headers,method='POST'):
            if path=='/v1/responses':return CancelConnection(),SilentResponse()
            return original(host,path,body,headers,method)
        self.broker.transport=transport
        timer=threading.Timer(0.2,cancel.set);timer.start();started=time.monotonic()
        try:
            with self.assertRaises(Denied) as e:self.broker.openai({**self.payload,'stream':True},lambda _:None,lambda _:None,cancelled=cancel.is_set)
            self.assertEqual(e.exception.code,'client_cancelled')
            self.assertLess(time.monotonic()-started,1.5)
        finally:timer.cancel()
