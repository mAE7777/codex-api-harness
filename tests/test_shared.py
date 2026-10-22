import concurrent.futures
import datetime as dt
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import time
import unittest

from guard import Denied, DAILY_LIMITS, atomic_json
from shared import Team, MemberLedger, MemberBroker, make_server, _owner_call
from test_guard import NOW, Connection, Response


class SharedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'team';self.now=NOW
        self.team=Team.initialize(self.root,'org-exampleteam',0,0,all_traffic=True,clock=lambda:self.now)
        self.team.add_member('alice','proj_exampleone',100,100)
        self.team.add_member('bob','proj_exampletwo',100,100)
        self.alice=MemberLedger(self.team,'alice');self.bob=MemberLedger(self.team,'bob')
        self.payload={'model':'gpt-5.6-terra','input':'hello','max_output_tokens':10}

    def tearDown(self):
        if self.team:self.team.close()
        self.temp.cleanup()

    def advance(self,seconds):
        self.now+=seconds;self.team.ledger.last_wall+=seconds

    def reserve(self,adapter,amount=20,group='B'):
        return adapter.reserve_daily(group,DAILY_LIMITS[group],amount,self.payload)

    def member_token(self,member):
        return json.loads((self.root/'invites'/(member+'.json')).read_text())['token']

    def enable_fake(self,member):
        directory=self.root/'members'/member
        key_path=self.root/'projects'/self.team._member(member)[0]/'openai-key.env'
        key_path.write_text('OPENAI_API_KEY=fake-test-only-key\n')
        key_path.chmod(0o600)
        data=json.loads((directory/'verification.json').read_text());data['openai']['billing_policy']='metered'
        atomic_json(directory/'verification.json',data)

    def test_initialization_requires_complete_traffic_and_never_resets(self):
        with self.assertRaises(Denied):Team.initialize(Path(self.temp.name)/'other','org-exampleteam',0,0)
        with self.assertRaises(Denied):Team.initialize(self.root,'org-exampleteam',0,0,all_traffic=True)
        self.assertEqual(len(self.team.status()['members']),2)

    def test_initialization_requires_stopped_personal_session_and_gateway(self):
        parent=Path(self.temp.name)/'other-installation';parent.mkdir(mode=0o700)
        target=parent/'team'
        with (parent/'session.lock').open('a+b') as active:
            fcntl.flock(active,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(Denied):Team.initialize(target,'org-exampleother',0,0,all_traffic=True)
        self.assertFalse(target.exists())
        atomic_json(parent/'gateway-process.json',{'pid':123})
        with self.assertRaises(Denied):Team.initialize(target,'org-exampleother',0,0,all_traffic=True)
        self.assertFalse(target.exists())

    def test_tokens_are_distinct_hashed_and_invites_are_private(self):
        alice=self.member_token('alice');bob=self.member_token('bob')
        self.assertNotEqual(alice,bob)
        hashes=[r[0] for r in self.team.ledger.db.execute('SELECT token_hash FROM team_members')]
        self.assertIn(hashlib.sha256(alice.encode()).hexdigest(),hashes)
        self.assertNotIn(alice,str(hashes))
        for file in (self.root/'invites/alice.json',self.root/'projects/proj_exampleone/openai-key.env'):
            self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
        self.assertEqual(self.team.authenticate('Bearer '+alice),'alice')
        with self.assertRaises(Denied):self.team.authenticate('Bearer '+alice+'x')

    def test_quota_is_two_english_lines_and_read_only(self):
        head=self.team.ledger._head()
        result=self.team.quota('alice')
        self.assertEqual(len(result['usage_lines']),2)
        self.assertTrue(result['usage_lines'][0].startswith('A ('))
        self.assertIn('100 / 100 tokens remaining',result['usage_lines'][1])
        self.assertEqual(head,self.team.ledger._head())

    def test_member_usage_is_isolated_but_parent_usage_is_shared(self):
        identity=self.reserve(self.alice,20);self.alice.dispatch_daily(identity);self.alice.settle(identity,9)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],91)
        self.assertEqual(self.team.quota('bob')['daily_pools']['B']['remaining'],100)
        self.assertEqual(self.team.status()['organization_pools']['B']['remaining'],DAILY_LIMITS['B']-9)
        with self.assertRaises(Denied):self.bob.settle(identity,9)

    def test_concurrent_reservations_cannot_spend_the_last_global_tokens_twice(self):
        day=self.team.day()
        with self.team.ledger.transaction():
            self.team.ledger.db.execute('UPDATE budgets SET baseline=? WHERE scope=? AND period=?',(DAILY_LIMITS['B']-30,'openai:B',day))
        barrier=threading.Barrier(2)
        def reserve(adapter):
            barrier.wait()
            try:return self.reserve(adapter,20)
            except Denied:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            results=list(workers.map(reserve,(self.alice,self.bob)))
        self.assertEqual(sum(value is not None for value in results),1)
        self.assertEqual(self.team.status()['organization_pools']['B']['remaining'],10)

    def test_same_project_members_also_share_a_project_limit(self):
        self.team.add_member('carol','proj_exampleone',100,100)
        self.team.project_limits('proj_exampleone',100,30,operation='project-30')
        self.reserve(self.alice,20)
        carol=MemberLedger(self.team,'carol')
        with self.assertRaises(Denied):self.reserve(carol,20)
        self.assertEqual(self.team.quota('carol')['daily_pools']['B']['remaining'],10)
        self.assertEqual(self.team.quota('bob')['daily_pools']['B']['remaining'],100)

    def test_cannot_reduce_project_limit_below_used_or_reserved(self):
        self.reserve(self.alice,20)
        with self.assertRaises(Denied):self.team.project_limits('proj_exampleone',100,19,operation='bad-project-reduction')
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],80)

    def test_transfer_is_atomic_idempotent_and_does_not_move_held_tokens(self):
        self.reserve(self.alice,80)
        before=self.team.status()['members']
        with self.assertRaises(Denied):self.team.transfer('alice','bob',10,21,operation='bad-transfer')
        self.assertEqual(before,self.team.status()['members'])
        result=self.team.transfer('alice','bob',10,20,operation='valid-transfer')
        self.assertEqual(result['tokens'],{'A':10,'B':20})
        self.assertTrue(self.team.transfer('alice','bob',10,20,operation='valid-transfer')['replayed'])
        self.assertEqual(self.team.quota('bob')['daily_pools']['B']['limit'],120)
        with self.assertRaises(Denied):self.team.transfer('alice','bob',10,19,operation='valid-transfer')

    def test_transfer_revision_conflict_preserves_allocations(self):
        revision=self.team.status()['revision']
        self.team.transfer('alice','bob',0,1,operation='first-change',revision=revision)
        with self.assertRaises(Denied) as error:self.team.transfer('alice','bob',0,1,operation='stale-change',revision=revision)
        self.assertEqual(error.exception.code,'team_revision_conflict')

    def test_concurrent_transfers_do_not_duplicate_unused_capacity(self):
        barrier=threading.Barrier(2)
        def transfer(index):
            barrier.wait()
            try:return self.team.transfer('alice','bob',0,60,operation='race-'+str(index))
            except Denied:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:results=list(workers.map(transfer,(1,2)))
        self.assertEqual(sum(value is not None for value in results),1)
        pools=[m['today']['B']['limit'] for m in self.team.status()['members']]
        self.assertEqual(sorted(pools),[40,160])

    def test_defaults_apply_next_day_while_temporary_transfers_expire(self):
        self.team.transfer('alice','bob',0,20,operation='temporary')
        self.team.defaults('alice',50,50,operation='tomorrow-alice')
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['limit'],80)
        self.advance(86400)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['limit'],50)
        self.assertEqual(self.team.quota('bob')['daily_pools']['B']['limit'],100)
        self.reserve(self.alice,10)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['limit'],50)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],40)

    def test_unknown_reservation_survives_restart_and_multiple_utc_days(self):
        identity=self.reserve(self.alice,80);self.alice.dispatch_daily(identity)
        self.team.close();self.team=Team(self.root,clock=lambda:self.now);self.alice=MemberLedger(self.team,'alice')
        self.advance(86400)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],20)
        self.advance(86400)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],20)
        self.alice.settle(identity,10)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],90)
        self.advance(86400)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],100)

    def test_day_change_before_dispatch_can_only_void_unsent_reservation(self):
        identity=self.reserve(self.alice,20);self.advance(86400)
        with self.assertRaises(Denied):self.alice.dispatch_daily(identity)
        self.alice.void_unsent(identity)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],100)

    def test_revoke_does_not_refund_and_prevents_pending_dispatch(self):
        identity=self.reserve(self.alice,20);token=self.member_token('alice')
        self.team.revoke('alice')
        with self.assertRaises(Denied):self.team.authenticate('Bearer '+token)
        with self.assertRaises(Denied):self.alice.dispatch_daily(identity)
        self.assertEqual(self.team.status()['organization_pools']['B']['remaining'],DAILY_LIMITS['B']-20)
        self.alice.void_unsent(identity)
        self.assertEqual(self.team.status()['organization_pools']['B']['remaining'],DAILY_LIMITS['B'])

    def test_rotating_a_member_token_does_not_change_other_member_or_usage(self):
        self.reserve(self.alice,20);old=self.member_token('alice');bob=self.member_token('bob')
        self.team.rotate('alice')
        with self.assertRaises(Denied):self.team.authenticate('Bearer '+old)
        self.assertEqual(self.team.authenticate('Bearer '+self.member_token('alice')),'alice')
        self.assertEqual(self.team.authenticate('Bearer '+bob),'bob')
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],80)

    def test_duplicate_approval_transfers_only_once(self):
        request={'request_id':'example-request-0001','group':'B','amount':20}
        self.team.request_more('bob',request)
        self.assertTrue(self.team.request_more('bob',request)['replayed'])
        self.team.approve(request['request_id'],'alice')
        self.assertTrue(self.team.approve(request['request_id'],'alice')['replayed'])
        self.assertEqual(self.team.quota('bob')['daily_pools']['B']['limit'],120)
        with self.assertRaises(Denied):self.team.approve(request['request_id'],'bob')

    def test_only_one_pending_request_per_member_group_day(self):
        first=self.team.request_more('alice',{'request_id':'example-request-0002','group':'A','amount':20})
        second=self.team.request_more('alice',{'request_id':'example-request-0003','group':'A','amount':30})
        self.assertEqual(first['request_id'],second['request_id'])
        self.advance(86400)
        with self.assertRaises(Denied):self.team.approve(first['request_id'],'bob')

    def test_ninety_percent_notice_is_once_per_member_group_day(self):
        identity=self.reserve(self.alice,90);self.alice.dispatch_daily(identity);self.alice.settle(identity,90)
        self.assertEqual(len(self.team.notices('alice')),1)
        self.assertEqual(self.team.notices('alice'),[])
        self.assertEqual(self.team.notices('bob'),[])
        self.team.close();self.team=Team(self.root,clock=lambda:self.now)
        self.assertEqual(self.team.notices('alice'),[])

    def test_above_reservation_usage_stops_every_member(self):
        identity=self.reserve(self.alice,10);self.alice.dispatch_daily(identity)
        with self.assertRaises(Denied):self.alice.settle(identity,11)
        with self.assertRaises(Denied):self.bob.daily_remaining('B',DAILY_LIMITS['B'])

    def test_no_free_assertion_or_binding_inheritance(self):
        calls=[]
        def transport(*args,**kwargs):calls.append(args);raise AssertionError('No provider request permitted')
        broker=MemberBroker(self.team,'alice',transport)
        with self.assertRaises(Denied) as error:broker.openai(self.payload,lambda _:None,lambda _:None,operation_id='unverified-free')
        self.assertEqual(error.exception.code,'free_eligibility_unconfirmed')
        self.assertEqual(calls,[])
        self.enable_fake('alice')
        path=self.root/'members/alice/verification.json';data=json.loads(path.read_text());data['openai']['project_id']='proj_examplewrong';atomic_json(path,data)
        with self.assertRaises(Denied) as error:broker.openai(self.payload,lambda _:None,lambda _:None,operation_id='wrong-project')
        self.assertEqual(error.exception.code,'team_account_binding_invalid');self.assertEqual(calls,[])

    def test_default_overallocation_is_rejected(self):
        with self.assertRaises(Denied):self.team.add_member('carol','proj_exampleone',DAILY_LIMITS['A'],0)
        with self.assertRaises(Denied):self.team.defaults('alice',DAILY_LIMITS['A'],0,operation='too-many-defaults')
        self.assertEqual(len(self.team.status()['members']),2)

    def test_project_key_is_shared_once_and_never_overwritten(self):
        self.enable_fake('alice')
        path=self.root/'projects/proj_exampleone/openai-key.env';before=path.read_bytes()
        result=self.team.add_member('carol','proj_exampleone',100,100)
        self.assertEqual(result['key_file'],str(path));self.assertEqual(before,path.read_bytes())
        self.assertFalse((self.root/'members/carol/openai-key.env').exists())

    def test_unused_revoked_member_allocation_can_be_explicitly_reclaimed(self):
        self.reserve(self.alice,20);self.team.revoke('alice')
        self.team.transfer('alice','bob',0,80,operation='reclaim-unused')
        self.assertEqual(self.team.quota('bob')['daily_pools']['B']['limit'],180)
        with self.assertRaises(Denied):self.team.transfer('alice','bob',0,1,operation='steal-held')

    def test_token_rotation_blocks_an_old_credential_before_dispatch(self):
        digest=hashlib.sha256(self.member_token('alice').encode()).hexdigest()
        adapter=MemberLedger(self.team,'alice',credential_hash=digest)
        identity=self.reserve(adapter,20);self.team.rotate('alice')
        with self.assertRaises(Denied) as error:adapter.dispatch_daily(identity)
        self.assertEqual(error.exception.code,'team_auth_failed')
        adapter.void_unsent(identity)
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],100)

    def test_clock_discontinuity_stops_admission(self):
        self.now+=20
        with self.assertRaises(Denied):self.reserve(self.alice,20)
        self.assertEqual(self.team.ledger.db.execute('SELECT COUNT(*) FROM requests').fetchone()[0],0)

    def test_shared_reconciliation_needs_specific_finished_evidence_and_is_idempotent(self):
        identity=self.reserve(self.alice,20);self.alice.dispatch_daily(identity)
        self.assertEqual(self.team.reconcile()['requests'][0]['member_id'],'alice')
        path=Path(self.team.reconcile(template=identity)['review_file']);plan=json.loads(path.read_text())
        with self.assertRaises(Denied):self.team.reconcile(apply=str(path))
        plan['actual_tokens']=9;plan['evidence'].update(reference='example-provider-receipt',request_finished=True)
        atomic_json(path,plan)
        self.assertTrue(self.team.reconcile(apply=str(path))['applied'])
        self.assertFalse(self.team.reconcile(apply=str(path))['applied'])
        self.assertEqual(self.team.quota('alice')['daily_pools']['B']['remaining'],91)

    def test_coordinator_state_symlink_and_world_readable_directory_are_rejected(self):
        self.team.close();self.team=None
        self.root.chmod(0o755)
        with self.assertRaises(Denied):Team(self.root)
        self.root.chmod(0o700)
        link=Path(self.temp.name)/'team-link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(Denied):Team(link)


class SharedHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'team'
        team=Team.initialize(self.root,'org-examplehttp',0,0,all_traffic=True)
        team.add_member('alice','proj_examplehttp',100,100)
        self.token=json.loads((self.root/'invites/alice.json').read_text())['token']
        self.coordinator=team.coordinator_id
        team.billing('alice',charges=True)
        (self.root/'projects/proj_examplehttp/openai-key.env').write_text('OPENAI_API_KEY=fake-test-only-key\n')
        (self.root/'projects/proj_examplehttp/openai-key.env').chmod(0o600)
        team.close();self.calls=[]
        def transport(host,path,body,headers,method='POST'):
            self.calls.append((path,headers))
            if path.endswith('input_tokens'):return Connection(),Response({'input_tokens':5},date=time.time())
            if body.get('stream'):
                raw=b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_example","status":"completed","usage":{"input_tokens":5,"output_tokens":4}}}\n\n'
                return Connection(),Response(raw=raw,content_type='text/event-stream')
            return Connection(),Response({'usage':{'input_tokens':5,'output_tokens':4},'output':[]})
        self.server=make_server(self.root,port=0,transport=transport)
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
        self.payload={'model':'gpt-5.6-terra','input':'hello','max_output_tokens':10}

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.server.close_shared();self.temp.cleanup()

    def call(self,path,body=None,*,method='POST',token=True,operation='example-http-operation',headers=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        extra={}
        if token:extra['Authorization']='Bearer '+self.token
        if operation:extra['Idempotency-Key']=operation
        extra.update(headers or {})
        connection.request(method,path,None if body is None else json.dumps(body),extra)
        response=connection.getresponse();raw=response.read();connection.close()
        return response.status,raw

    def test_identity_and_usage_are_authenticated_and_member_scoped(self):
        status,raw=self.call('/identity',method='GET');data=json.loads(raw)
        self.assertEqual(status,200);self.assertEqual(data['coordinator_id'],self.coordinator)
        self.assertEqual(data['member_id'],'alice');self.assertNotIn(self.token,raw.decode())
        self.assertEqual(self.call('/identity',method='GET',token=False)[0],401)
        data=json.loads(self.call('/v1/quota',method='GET')[1]);self.assertEqual(len(data['usage_lines']),2)
        self.assertEqual(len(json.loads(self.call('/v1/models',method='GET')[1])['data']),5)

    def test_no_admin_or_settlement_http_surface(self):
        for path in ('/admin','/v1/settle','/v1/transfer','/v1/images/generations','/v1/chat/completions'):
            self.assertEqual(self.call(path,{})[0],403)
        self.assertEqual(self.call('/identity',method='GET',headers={'Host':'other.example'})[0],403)
        self.assertEqual(self.calls,[])

    def test_missing_operation_id_and_duplicate_attempt_never_resend(self):
        self.assertEqual(self.call('/v1/responses',self.payload,operation=None)[0],403)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.call('/v1/responses',self.payload)[0],200)
        self.assertEqual(len(self.calls),2)
        status,body=self.call('/v1/responses',self.payload)
        self.assertEqual(status,409);self.assertEqual(json.loads(body)['error']['code'],'duplicate_operation')
        self.assertEqual(len(self.calls),2)
        self.assertEqual(self.server.team.quota('alice')['daily_pools']['B']['remaining'],91)

    def test_streaming_is_forwarded_and_accounted(self):
        status,raw=self.call('/v1/responses',dict(self.payload,stream=True))
        self.assertEqual(status,200);self.assertIn(b'event: response.completed',raw)
        self.assertEqual(self.server.team.quota('alice')['daily_pools']['B']['remaining'],91)

    def test_disabled_hosted_tool_is_specific_and_never_calls_provider(self):
        status,raw=self.call('/v1/responses',dict(self.payload,tools=[{'type':'web_search'}],stream=True))
        self.assertEqual(status,200);self.assertIn(b'[tool_disabled]',raw);self.assertEqual(self.calls,[])

    def test_owner_changes_live_over_unix_socket_but_member_http_cannot(self):
        self.server.start_admin()
        result=_owner_call(self.root,'add_member',{'member':'bob','project':'proj_examplebob','a':100,'b':100})
        self.assertEqual(result['member_id'],'bob')
        result=_owner_call(self.root,'transfer',{'donor':'alice','recipient':'bob','a':0,'b':20,'operation':'owner-live'})
        self.assertEqual(result['tokens']['B'],20)
        self.assertEqual(self.server.team.quota('alice')['daily_pools']['B']['limit'],80)
        self.assertEqual(stat.S_IMODE((self.root/'admin.sock').stat().st_mode),0o600)

    def test_remote_quota_request_is_deduplicated_and_approval_is_owner_only(self):
        payload={'request_id':'example-http-request01','group':'B','amount':10}
        self.assertEqual(self.call('/v1/quota/request',payload)[0],200)
        self.assertTrue(json.loads(self.call('/v1/quota/request',payload)[1])['replayed'])
        self.assertEqual(self.call('/v1/quota/approve',payload)[0],403)

    def test_duplicate_headers_and_get_bodies_are_rejected(self):
        for name,value in [('Host','localhost:'+str(self.server.server_port)),('Authorization','Bearer '+self.token),('Idempotency-Key','other-operation'),('Content-Length','2')]:
            connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
            connection.putrequest('POST','/v1/responses')
            connection.putheader('Authorization','Bearer '+self.token)
            connection.putheader('Idempotency-Key','first-operation')
            connection.putheader('Content-Length','2')
            connection.putheader(name,value);connection.endheaders(b'{}')
            response=connection.getresponse();response.read();connection.close()
            self.assertEqual(response.status,403)
        self.assertEqual(self.call('/identity',{},method='GET')[0],403)
        self.assertEqual(self.calls,[])

    def test_shared_reconciliation_apply_requires_stopped_coordinator(self):
        self.call('/v1/responses',self.payload)
        self.server.start_admin()
        with self.assertRaises(Denied) as error:_owner_call(self.root,'reconcile',{'apply':'not-a-real-file'})
        self.assertEqual(error.exception.code,'team_stop_required')

    def test_quota_counts_are_member_scoped(self):
        self.call('/v1/responses',self.payload)
        self.server.team.add_member('bob','proj_examplebob',100,100)
        self.assertEqual(self.server.team.quota('alice')['recorded_requests'],1)
        self.assertEqual(self.server.team.quota('bob')['recorded_requests'],0)
