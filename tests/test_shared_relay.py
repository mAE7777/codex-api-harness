"""Two real HTTP hops with an authoritative fake-provider coordinator."""
import http.client
import json
from pathlib import Path
import secrets
import tempfile
import threading
import unittest

import gateway
from guard import Ledger, atomic_json, canonical
from shared import Team, make_server as coordinator_server, _owner_call
from test_guard import NOW, Connection, Response


class EndToEndRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='relay-')
        self.root=Path(self.temp.name);self.team_root=self.root/'team'
        team=Team.initialize(self.team_root,'org-exampleteam',0,0,all_traffic=True,clock=lambda:NOW)
        team.add_member('member-one','proj_exampleone',100,100)
        team.add_member('member-two','proj_exampletwo',100,100)
        team.billing('member-one',charges=True);team.billing('member-two',charges=True)
        for project in ('proj_exampleone','proj_exampletwo'):
            key=team.root/'projects'/project/'openai-key.env';key.write_text('OPENAI_API_KEY=fake-test-only-key\n');key.chmod(0o600)
        team.close();self.calls=[]
        def transport(host,path,body,headers):
            self.calls.append((host,path,body,headers))
            if path.endswith('/input_tokens'):return Connection(),Response({'input_tokens':10})
            if body.get('stream'):
                event={'type':'response.completed','response':{'id':'response_fixture','usage':{'input_tokens':10,'output_tokens':5,'total_tokens':15}}}
                return Connection(),Response(raw=b'data: '+canonical(event)+b'\n\n',content_type='text/event-stream')
            return Connection(),Response({'id':'response_fixture','usage':{'input_tokens':10,'output_tokens':5}})
        self.coordinator=coordinator_server(self.team_root,port=0,transport=transport,clock=lambda:NOW)
        self.coordinator.start_admin();self.threads=[]
        self.start(self.coordinator)
        self.local=self.root/'client';self.local.mkdir(mode=0o700)
        config=json.loads((self.team_root/'invites/member-one.json').read_text())
        config['endpoint']='http://127.0.0.1:'+str(self.coordinator.server_port)
        atomic_json(self.local/'team-client.json',config)
        self.local_token=secrets.token_urlsafe(48);(self.local/'gateway.token').write_text(self.local_token)
        self.ledger=Ledger(self.local/'state',initialize=True);self.ledger.pause(False)
        self.relay=gateway.make_server(self.local,self.ledger,port=0)
        self.start(self.relay)
        self.payload={'model':'gpt-5.6-terra','input':'Synthetic shared relay check','max_output_tokens':10}
    def start(self,server):
        thread=threading.Thread(target=server.serve_forever);thread.start();self.threads.append(thread)
    def tearDown(self):
        self.relay.shutdown();self.relay.server_close();self.ledger.close()
        self.coordinator.shutdown();self.coordinator.server_close();self.coordinator.close_shared()
        for thread in self.threads:thread.join()
        self.temp.cleanup()
    def request(self,method,path,payload=None,key=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.relay.server_port,timeout=5)
        headers={'Authorization':'Bearer '+self.local_token}
        if key:headers['Idempotency-Key']=key
        connection.request(method,path,None if payload is None else canonical(payload),headers)
        response=connection.getresponse();raw=response.read();connection.close()
        return response.status,raw
    def test_real_two_hop_model_request_only_debits_coordinator_and_bound_project(self):
        status,raw=self.request('POST','/v1/responses',self.payload)
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)['id'],'response_fixture')
        quota=self.coordinator.team.quota('member-one')
        self.assertEqual(quota['daily_pools']['B']['remaining'],85)
        self.assertEqual(self.coordinator.team.quota('member-two')['daily_pools']['B']['remaining'],100)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM requests').fetchone()[0],0)
        self.assertEqual([call[1] for call in self.calls],['/v1/responses/input_tokens','/v1/responses'])
        self.assertTrue(all(call[3]['OpenAI-Project']=='proj_exampleone' for call in self.calls))
        self.assertTrue(all('Bearer fake-test-only-key'==call[3]['Authorization'] for call in self.calls))
    def test_streaming_and_durable_hop_dedup(self):
        status,raw=self.request('POST','/v1/responses',{**self.payload,'stream':True},key='operation-relay-fixture')
        self.assertEqual(status,200);self.assertIn(b'response.completed',raw)
        _,replay=self.request('POST','/v1/responses',{**self.payload,'stream':True},key='operation-relay-fixture')
        self.assertIn(b'duplicate_operation',replay)
        self.assertEqual(len(self.calls),2)
    def test_free_only_does_not_count_or_generate(self):
        self.coordinator.team.billing('member-one',charges=False)
        status,raw=self.request('POST','/v1/responses',self.payload)
        self.assertEqual(status,403);self.assertEqual(json.loads(raw)['error']['code'],'free_eligibility_unconfirmed')
        self.assertEqual(self.calls,[])
    def test_owner_live_transfer_and_member_request_do_not_reset_usage(self):
        self.request('POST','/v1/responses',self.payload)
        status,raw=self.request('POST','/v1/quota/request',{'request_id':'fixture_quota_request_id','group':'B','amount':20})
        self.assertEqual(status,200)
        request_id=json.loads(raw)['request_id']
        _owner_call(self.team_root,'approve',{'request_id':request_id,'donor':'member-two'})
        _owner_call(self.team_root,'approve',{'request_id':request_id,'donor':'member-two'})
        _,raw=self.request('GET','/v1/quota')
        quota=json.loads(raw)
        self.assertEqual(quota['daily_pools']['B']['limit'],120)
        self.assertEqual(quota['daily_pools']['B']['remaining'],105)
        self.assertEqual(len(quota['usage_lines']),2)
        self.assertEqual(len(self.calls),2)
    def test_revocation_blocks_at_identity_before_any_provider_request(self):
        _owner_call(self.team_root,'revoke',{'member':'member-one'})
        status,raw=self.request('POST','/v1/responses',self.payload)
        self.assertEqual(status,401);self.assertIn(b'team_auth_failed',raw)
        self.assertEqual(self.calls,[])
    def test_hosted_tools_and_member_admin_routes_unreachable(self):
        for payload in ({**self.payload,'tools':[{'type':'web_search'}]},{**self.payload,'service_tier':'priority'},{**self.payload,'project_id':'proj_exampletwo'}):
            status,_=self.request('POST','/v1/responses',payload)
            self.assertEqual(status,403)
        status,_=self.request('POST','/admin/transfer',{})
        self.assertEqual(status,403);self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
