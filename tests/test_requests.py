"""Synthetic protocol/accounting checks; never contacts a real provider."""
import hashlib
import http.client
import json
from pathlib import Path
import threading
import unittest
import uuid
from unittest.mock import patch

import gateway
from guard import Denied, Ledger, canonical, normalize
import test_guard as fixtures
import test_http as http_fixtures
import test_shared as shared_fixtures


class TerminalUsageTests(unittest.TestCase):
    setUp = fixtures.GuardTests.setUp
    tearDown = fixtures.GuardTests.tearDown

    def test_coordinator_owner_cannot_also_dispatch_from_an_independent_personal_ledger(self):
        (self.root/'team').mkdir()
        with self.assertRaises(Denied) as error:
            self.broker.openai(self.payload,lambda _:None,lambda _:None)
        self.assertEqual(error.exception.code,'team_client_required')
        self.assertEqual(self.calls,[])

    def test_invalid_json_usage_is_rejected_before_success_and_keeps_reservation(self):
        invalid = [False, [], {}, {'input_tokens':True,'output_tokens':4},
                   {'input_tokens':5,'output_tokens':-1}, {'input_tokens':'5','output_tokens':4},
                   {'input_tokens':5,'output_tokens':None},
                   {'input_tokens':2**63,'output_tokens':4},
                   {'input_tokens':2**53-1,'output_tokens':1},
                   {'input_tokens':5,'output_tokens':4,'total_tokens':True},
                   {'input_tokens':5,'output_tokens':4,'total_tokens':8}]
        for usage in invalid:
            with self.subTest(usage=usage):
                fixture=fixtures.GuardTests();fixture.setUp()
                try:
                    fixture.response = fixtures.Response({'usage':usage})
                    headers, chunks = [], []
                    with self.assertRaises(Denied) as error:
                        fixture.broker.openai(fixture.payload,headers.append,chunks.append)
                    self.assertEqual(error.exception.code,'terminal_usage_invalid')
                    self.assertEqual(headers,[]);self.assertEqual(chunks,[])
                    row=fixture.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone()
                    self.assertEqual(row,(15,None,'unknown'))
                finally:fixture.tearDown()

    def test_missing_json_usage_does_not_forward_a_success(self):
        self.response=fixtures.Response({'output':[]})
        headers,chunks=[],[]
        with self.assertRaises(Denied) as error:self.broker.openai(self.payload,headers.append,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_missing')
        self.assertEqual(headers,[]);self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.status()['unresolved'],1)

    def test_invalid_sse_terminal_event_is_not_forwarded(self):
        event={'type':'response.completed','response':{'usage':{'input_tokens':False,'output_tokens':4}}}
        self.response=fixtures.Response(raw=b'data: '+canonical(event)+b'\n\n',content_type='text/event-stream')
        chunks=[]
        with self.assertRaises(Denied) as error:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_invalid')
        self.assertEqual(chunks,[]);self.assertEqual(self.ledger.status()['unresolved'],1)

    def test_json_is_settled_before_success_is_forwarded(self):
        phases=[]
        self.broker.openai(self.payload,lambda _:None,lambda _:phases.append(self.ledger.db.execute('SELECT phase,actual FROM requests').fetchone()))
        self.assertEqual(phases,[('settled',9)])

    def stream(self,usages,*,suffix=b''):
        events=[{'type':'response.completed','response':{'usage':usage}} for usage in usages]
        return fixtures.Response(raw=b''.join(b'data: '+canonical(e)+b'\n\n' for e in events)+suffix,content_type='text/event-stream')

    def conflict(self):
        self.response=self.stream([{'input_tokens':5,'output_tokens':4},{'input_tokens':5,'output_tokens':9}])
        chunks=[]
        with self.assertRaises(Denied) as error:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_conflict')
        self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))
        self.assertTrue((self.ledger.root/'safety-stop.json').exists())
        return self.ledger.db.execute('SELECT id FROM requests').fetchone()[0]

    def receipt(self,identity,actual=14,reserved=15):
        return {'version':1,'resolution_id':uuid.uuid4().hex,'request_id':identity,'expected_phase':'unknown',
                'expected_reserved_tokens':reserved,'action':'record_actual','actual_tokens':actual,
                'evidence':{'kind':'operator_verified_provider_usage','reference':'synthetic verified completed usage','request_finished':True}}

    def test_conflicting_terminal_record_retains_full_hold_and_stops_before_another_count(self):
        self.conflict();calls=len(self.calls)
        with self.assertRaises(Denied) as error:self.broker.openai(self.payload,lambda _:None,lambda _:None)
        self.assertEqual(error.exception.code,'quota_reconciliation_required');self.assertEqual(len(self.calls),calls)

    def test_later_lower_usage_is_still_a_conflict_without_an_early_refund(self):
        self.response=self.stream([{'input_tokens':5,'output_tokens':4},{'input_tokens':5,'output_tokens':3}])
        chunks=[]
        with self.assertRaises(Denied) as error:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_conflict')
        self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT actual,phase FROM requests').fetchone(),(None,'unknown'))

    def test_invalid_or_missing_later_terminal_usage_cannot_confirm_an_earlier_value(self):
        for later in (None,{'input_tokens':5,'output_tokens':-1}):
            with self.subTest(later=later):
                fixture=TerminalUsageTests();fixture.setUp()
                try:
                    fixture.response=fixture.stream([{'input_tokens':5,'output_tokens':4},later]);chunks=[]
                    with self.assertRaises(Denied):fixture.broker.openai({**fixture.payload,'stream':True},lambda _:None,chunks.append)
                    self.assertEqual(chunks,[])
                    self.assertEqual(fixture.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))
                    self.assertTrue((fixture.ledger.root/'safety-stop.json').exists())
                finally:fixture.tearDown()

    def test_identical_duplicate_terminal_events_settle_only_after_clean_eof(self):
        usage={'input_tokens':5,'output_tokens':4};self.response=self.stream([usage,usage],suffix=b'data: [DONE]\n\n')
        eof=[False];readline=self.response.readline;phases=[]
        def read(size):
            line=readline(size)
            if not line:
                self.assertEqual(self.ledger.db.execute('SELECT actual,phase FROM requests').fetchone(),(None,'unknown'))
                eof[0]=True
            return line
        self.response.readline=read
        self.broker.openai({**self.payload,'stream':True},lambda _:None,lambda _:phases.append((eof[0],self.ledger.db.execute('SELECT actual,phase FROM requests').fetchone())))
        self.assertEqual(phases,[(True,(9,'settled'))]*3)

    def test_failed_event_with_missing_usage_and_error_cannot_confirm_earlier_success(self):
        failure={'type':'response.failed','response':{'usage':None,'error':None}}
        self.response=self.stream([{'input_tokens':5,'output_tokens':4}],suffix=b'data: '+canonical(failure)+b'\n\n')
        chunks=[]
        with self.assertRaises(Denied) as error:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_missing');self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))
        self.assertTrue((self.ledger.root/'safety-stop.json').exists())

    def test_initial_failed_event_with_missing_usage_and_error_retains_full_hold(self):
        failure={'type':'response.failed','response':{'usage':None,'error':None}}
        self.response=fixtures.Response(raw=b'data: '+canonical(failure)+b'\n\n',content_type='text/event-stream');chunks=[]
        with self.assertRaises(Denied) as error:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_missing');self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))

    def test_failed_event_cannot_become_success_even_with_identical_valid_usage(self):
        usage={'input_tokens':5,'output_tokens':4}
        failure={'type':'response.failed','response':{'usage':usage,'error':None}}
        self.response=self.stream([usage],suffix=b'data: '+canonical(failure)+b'\n\n');chunks=[]
        with self.assertRaises(Denied) as error:self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'upstream_response_failed');self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))
        self.assertTrue((self.ledger.root/'safety-stop.json').exists())

    def test_truncated_event_after_terminal_keeps_full_reservation(self):
        self.response=self.stream([{'input_tokens':5,'output_tokens':4}],suffix=b'data: {"type":"response.completed"')
        chunks=[]
        with self.assertRaises(Denied):self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))

    def test_cancellation_after_terminal_before_eof_keeps_full_reservation(self):
        self.response=self.stream([{'input_tokens':5,'output_tokens':4}]);readline=self.response.readline;cancelled=[False]
        def read(size):
            line=readline(size)
            if not line:cancelled[0]=True
            return line
        self.response.readline=read;chunks=[]
        with self.assertRaises(Denied):self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append,cancelled=lambda:cancelled[0])
        self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))

    def test_socket_close_before_terminal_completion_keeps_full_reservation(self):
        self.response=self.stream([{'input_tokens':5,'output_tokens':4}]);readline=self.response.readline
        def read(size):
            line=readline(size)
            if not line:raise ConnectionResetError('synthetic socket close')
            return line
        self.response.readline=read;chunks=[]
        with self.assertRaises(ConnectionResetError):self.broker.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(chunks,[])
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))

    def test_conflict_stop_clears_after_completed_usage_is_reviewed(self):
        identity=self.conflict();receipt=self.receipt(identity)
        result=self.ledger.reconcile(receipt)
        self.assertTrue(result['applied']);self.assertFalse(result['safety_stop_preserved'])
        self.assertFalse(self.ledger.reconcile(receipt)['applied'])
        self.assertEqual(self.ledger.db.execute('SELECT actual,phase FROM requests').fetchone(),(14,'settled'))

    def test_receipt_replay_can_finish_an_interrupted_safety_stop_clear(self):
        identity=self.conflict();receipt=self.receipt(identity);unlink=Path.unlink;stop=self.ledger.root/'safety-stop.json'
        def fail(path,*args,**kwargs):
            if path==stop:raise OSError('synthetic interruption before clear')
            return unlink(path,*args,**kwargs)
        with patch.object(Path,'unlink',autospec=True,side_effect=fail):
            with self.assertRaises(OSError):self.ledger.reconcile(receipt)
        self.assertTrue(stop.exists());self.assertFalse(self.ledger.reconcile(receipt)['applied']);self.assertFalse(stop.exists())

    def test_conflict_stop_is_retained_until_every_unknown_request_is_reviewed(self):
        identity=self.ledger.reserve_daily('B',100,15,{})
        self.ledger.dispatch_daily(identity)
        other=self.ledger.reserve_daily('B',100,5,{})
        self.ledger.dispatch_daily(other);self.ledger.note_usage_conflict(identity)
        self.assertTrue(self.ledger.reconcile(self.receipt(identity))['safety_stop_preserved'])
        self.assertFalse(self.ledger.reconcile(self.receipt(other,actual=3,reserved=5))['safety_stop_preserved'])

    def test_above_reservation_receipt_upgrades_conflict_stop_and_never_auto_clears_it(self):
        identity=self.conflict();result=self.ledger.reconcile(self.receipt(identity,actual=16))
        self.assertTrue(result['safety_stop_preserved'])
        self.assertEqual(json.loads((self.ledger.root/'safety-stop.json').read_text())['reason'],'usage_above_reservation')


class SharedConflictTests(unittest.TestCase):
    setUp=shared_fixtures.SharedTests.setUp
    tearDown=shared_fixtures.SharedTests.tearDown
    enable_fake=shared_fixtures.SharedTests.enable_fake

    def test_conflict_keeps_shared_full_debit_and_stops_other_members(self):
        from shared import MemberBroker
        for member in ('alice','bob'):self.enable_fake(member)
        events=[{'type':'response.completed','response':{'usage':{'input_tokens':5,'output_tokens':n}}} for n in (4,9)]
        calls=[]
        def transport(host,path,*args):
            calls.append(path)
            if path.endswith('input_tokens'):return fixtures.Connection(),fixtures.Response({'input_tokens':5})
            return fixtures.Connection(),fixtures.Response(raw=b''.join(b'data: '+canonical(e)+b'\n\n' for e in events),content_type='text/event-stream')
        alice=MemberBroker(self.team,'alice',transport=transport);chunks=[]
        with self.assertRaises(Denied) as error:alice.openai({**self.payload,'stream':True},lambda _:None,chunks.append)
        self.assertEqual(error.exception.code,'terminal_usage_conflict');self.assertEqual(chunks,[])
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],85)
        with self.assertRaises(Denied) as error:MemberBroker(self.team,'bob',transport=transport).openai(self.payload,lambda _:None,lambda _:None)
        self.assertEqual(error.exception.code,'quota_reconciliation_required');self.assertEqual(len(calls),2)


class OperationTests(unittest.TestCase):
    setUp=fixtures.GuardTests.setUp
    tearDown=fixtures.GuardTests.tearDown

    def request(self, key='operation-example-001', payload=None, namespace='local'):
        return self.broker.openai(payload or self.payload,lambda _:None,lambda _:None,operation_id=key,operation_namespace=namespace)

    def restart(self):
        self.ledger.close()
        self.ledger=Ledger(self.root/'state',clock=lambda:fixtures.NOW)
        self.broker.ledger=self.ledger

    def test_explicit_duplicate_never_recounts_or_dispatches_again(self):
        self.request();calls=len(self.calls)
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'duplicate_operation');self.assertEqual(error.exception.status,409)
        self.assertEqual(len(self.calls),calls)
        self.assertEqual(error.exception.details['operation_phase'],'completed')
        self.assertRegex(error.exception.details['correlation_id'],r'^[a-f0-9]{32}$')
        self.assertEqual(self.ledger.status()['requests'],1)

    def test_body_conflict_is_distinguished_and_original_body_is_not_stored(self):
        self.request()
        with self.assertRaises(Denied) as error:self.request(payload={**self.payload,'input':'different PRIVATE_PROMPT_SENTINEL'})
        self.assertEqual(error.exception.code,'operation_id_conflict')
        self.assertEqual(len(self.calls),2)
        row=self.ledger.db.execute('SELECT operation_hash,payload_hash FROM operations').fetchone()
        self.assertEqual(row[0],hashlib.sha256(b'operation-example-001').hexdigest())
        self.assertEqual(row[1],hashlib.sha256(canonical(normalize(self.payload))).hexdigest())
        self.assertNotIn('PRIVATE_PROMPT_SENTINEL',json.dumps(error.exception.details))

    def test_identical_intentional_requests_without_explicit_key_are_independent(self):
        for _ in range(2):
            self.response=fixtures.Response({'usage':{'input_tokens':5,'output_tokens':4}})
            self.broker.openai(self.payload,lambda _:None,lambda _:None)
        self.assertEqual(self.ledger.status()['requests'],2)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],2)

    def test_member_namespaces_do_not_collide(self):
        for namespace in ('member:one','member:two'):
            self.response=fixtures.Response({'usage':{'input_tokens':5,'output_tokens':4}})
            self.request(namespace=namespace)
        self.assertEqual(self.ledger.status()['requests'],2)

    def test_concurrent_operation_claims_have_only_one_winner(self):
        normalized=normalize(self.payload);barrier=threading.Barrier(8);out=[]
        def claim():
            barrier.wait()
            try:out.append(self.ledger.begin_operation(normalized,'concurrent-example'))
            except Denied as error:out.append(error.code)
        threads=[threading.Thread(target=claim) for _ in range(8)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(out.count('duplicate_operation'),7)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],1)
        self.assertEqual(self.calls,[])

    def assert_replay_blocked_after_restart(self, expected_calls, phase):
        self.restart()
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'duplicate_operation')
        self.assertEqual(error.exception.details['operation_phase'],phase)
        self.assertEqual(len(self.calls),expected_calls)

    def test_crash_before_count_is_not_silently_retried_after_restart(self):
        with patch.object(gateway,'credentials',side_effect=SystemExit('synthetic crash')):
            with self.assertRaises(SystemExit):self.request()
        self.assert_replay_blocked_after_restart(0,'admitted')

    def test_crash_during_count_is_not_silently_retried_after_restart(self):
        def crash(*args):
            self.calls.append(args)
            raise SystemExit('synthetic crash')
        original=self.broker.transport;self.broker.transport=crash
        with self.assertRaises(SystemExit):self.request()
        self.broker.transport=original
        self.assert_replay_blocked_after_restart(1,'counting')

    def test_crash_after_count_and_reservation_keeps_one_permit(self):
        mark=self.ledger.mark_operation
        def crash(correlation,phase,**options):
            result=mark(correlation,phase,**options)
            if phase=='reserved':raise SystemExit('synthetic crash')
            return result
        with patch.object(self.ledger,'mark_operation',side_effect=crash):
            with self.assertRaises(SystemExit):self.request()
        self.assert_replay_blocked_after_restart(1,'reserved')
        self.assertEqual(self.ledger.db.execute('SELECT reserved,phase FROM requests').fetchone(),(15,'reserved'))

    def test_crash_after_dispatch_keeps_unknown_usage_and_never_resends(self):
        original=self.broker.transport
        def crash(host,path,*args):
            if path=='/v1/responses':
                self.calls.append((host,path,*args));raise SystemExit('synthetic crash')
            return original(host,path,*args)
        self.broker.transport=crash
        with self.assertRaises(SystemExit):self.request()
        self.broker.transport=original
        self.assert_replay_blocked_after_restart(2,'dispatched')
        self.assertEqual(self.ledger.db.execute('SELECT reserved,actual,phase FROM requests').fetchone(),(15,None,'unknown'))

    def test_completed_operations_remain_deduplicated_after_restart(self):
        self.request();self.assert_replay_blocked_after_restart(2,'completed')

    def test_count_failure_is_durable_and_requires_an_intentional_new_operation(self):
        original=self.broker.transport
        def unavailable(*args):return fixtures.Connection(),fixtures.Response({'error':{'code':'invalid_api_key'}},status=401)
        self.broker.transport=unavailable
        with self.assertRaises(Denied) as error:self.request()
        self.assertIn('correlation_id',error.exception.details)
        self.broker.transport=original
        with self.assertRaises(Denied) as error:self.request()
        self.assertEqual(error.exception.code,'duplicate_operation')
        self.request(key='intentional-new-operation')
        self.assertEqual(self.ledger.status()['requests'],1)

    def test_invalid_operation_identifiers_fail_before_provider_calls(self):
        for key in ('short','a'*129,'private\nheader',True,{},'bad key has spaces'):
            with self.subTest(key=key),self.assertRaises(Denied) as error:self.request(key=key)
            self.assertEqual(error.exception.code,'invalid_operation_id')
        self.assertEqual(self.calls,[])

    def test_provider_correlation_is_sanitized_and_bound_to_one_attempt(self):
        self.response.getheader=lambda name,default=None:'req_public-example-123' if name.lower()=='x-request-id' else default
        self.request()
        row=self.ledger.db.execute('SELECT request_id,provider_request_id,phase FROM operations').fetchone()
        self.assertRegex(row[0],r'^[0-9a-f]{32}$');self.assertEqual(row[1: ],('req_public-example-123','completed'))
        correlation=self.ledger.db.execute('SELECT correlation_id FROM operations').fetchone()[0]
        with self.assertRaises(Denied):self.ledger.mark_operation(correlation,'completed',request_id='0'*32)


class OperationHTTPTests(unittest.TestCase):
    setUp=http_fixtures.HTTPTests.setUp
    tearDown=http_fixtures.HTTPTests.tearDown
    call=http_fixtures.HTTPTests.call

    def test_explicit_header_deduplicates_with_actionable_error(self):
        status,_=self.call('/v1/responses',self.payload,extra={'Idempotency-Key':'http-operation-example'})
        self.assertEqual(status,200)
        status,result=self.call('/v1/responses',self.payload,extra={'Idempotency-Key':'http-operation-example'})
        self.assertEqual(status,409);self.assertEqual(result['error']['code'],'duplicate_operation')
        self.assertIn('correlation_id',result['error']);self.assertEqual(len(self.calls),2)

    def test_repeated_idempotency_headers_are_rejected(self):
        client=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        data=json.dumps(self.payload)
        client.putrequest('POST','/v1/responses')
        client.putheader('Authorization','Bearer fake-guest-token-'+'0'*48)
        client.putheader('Content-Length',str(len(data)))
        client.putheader('Idempotency-Key','http-operation-example')
        client.putheader('Idempotency-Key','http-operation-example')
        client.endheaders(data.encode())
        response=client.getresponse();body=json.loads(response.read());client.close()
        self.assertEqual(response.status,403);self.assertEqual(body['error']['code'],'invalid_operation_id')
        self.assertEqual(self.calls,[])
