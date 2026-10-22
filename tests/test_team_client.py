import contextlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest import mock

from guard import DAILY_LIMITS, Denied, atomic_json, canonical
from team_client import Connection, RemoteBroker, command, private_json, validate


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.renderer=mock.patch('configuration.refresh_guest',return_value=False);self.renderer.start();self.addCleanup(self.renderer.stop)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.token=secrets.token_urlsafe(48);self.requests=[];self.identity='coordinator_fixture'
        test=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):self.respond()
            def do_POST(self):self.respond()
            def respond(self):
                length=int(self.headers.get('Content-Length','0'))
                body=self.rfile.read(length) if length else b''
                test.requests.append((self.path,self.headers.get('Authorization'),self.headers.get('Idempotency-Key'),body))
                if self.headers.get('Authorization')!='Bearer '+test.token:status,data=401,{'error':{'code':'member_revoked','message':'This membership is revoked.'}}
                elif self.path=='/identity':status,data=200,{'service':'codex-api-team','version':1,'coordinator_id':test.identity,'member_id':'member_fixture','project_id':'example_project'}
                elif self.path=='/v1/quota':status,data=200,{'daily_pools':{g:{'remaining':v//2,'limit':v} for g,v in DAILY_LIMITS.items()},'quota_guard':True,'unresolved_requests':0,'safety_stop':False}
                elif self.path=='/v1/notices/claim':status,data=200,{'notices':[]}
                elif self.path=='/v1/responses':status,data=200,{'id':'example_response','usage':{'input_tokens':10,'output_tokens':3}}
                else:status,data=404,{}
                raw=canonical(data)
                self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
        self.config={'version':1,'coordinator_id':self.identity,'member_id':'member_fixture','endpoint':'http://127.0.0.1:'+str(self.server.server_port),'token':self.token}
        atomic_json(self.root/'team-client.json',self.config)
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def test_identity_pinned_before_model_request(self):
        self.identity='another_coordinator'
        with self.assertRaises(Denied) as error:RemoteBroker(self.root).openai({'model':'gpt-5.6-terra','input':'example'},lambda _:None,lambda _:None)
        self.assertEqual(error.exception.code,'team_identity_changed')
        self.assertEqual([r[0] for r in self.requests],['/identity'])
    def test_host_relay_normalizes_and_attaches_explicit_operation(self):
        chunks=[];formats=[]
        RemoteBroker(self.root).openai({'model':'gpt-5.6-terra','input':'example','max_output_tokens':100},formats.append,chunks.append)
        self.assertEqual(formats,['application/json'])
        self.assertEqual(json.loads(b''.join(chunks))['usage']['input_tokens'],10)
        path,auth,operation,body=self.requests[-1]
        self.assertEqual(path,'/v1/responses');self.assertEqual(auth,'Bearer '+self.token)
        self.assertRegex(operation,r'^[a-f0-9]{32}$')
        self.assertFalse(json.loads(body)['store'])
        self.assertNotIn('OPENAI_API_KEY',body.decode())
    def test_tools_blocked_before_coordinator_contact(self):
        with self.assertRaises(Denied):RemoteBroker(self.root).openai({'model':'gpt-5.6-terra','input':'example','tools':[{'type':'web_search'}]},lambda _:None,lambda _:None)
        self.assertEqual(self.requests,[])
    def test_quota_exactly_two_english_lines(self):
        quota=RemoteBroker(self.root).quota()
        self.assertEqual(len(quota['usage_lines']),2)
        self.assertTrue(all(x.isascii() and '\n' not in x for x in quota['usage_lines']))
        self.assertTrue(quota['usage_lines'][0].startswith('A ('))
        self.assertTrue(quota['usage_lines'][1].startswith('B ('))
    def test_member_revocation_no_fallback(self):
        self.token=secrets.token_urlsafe(48)
        with self.assertRaises(Denied) as error:RemoteBroker(self.root).quota()
        self.assertEqual(error.exception.code,'member_revoked')
        self.assertEqual([r[0] for r in self.requests],['/identity'])
    def test_shared_search_stays_off(self):
        with self.assertRaises(Denied):RemoteBroker(self.root).search({'query':'example'})
        self.assertEqual(self.requests,[])
    def test_no_model_dispatch_when_paused(self):
        (self.root/'paused').touch()
        with self.assertRaises(Denied):RemoteBroker(self.root).openai({'model':'gpt-5.6-terra','input':'example'},lambda _:None,lambda _:None)
        self.assertFalse(any(r[0]=='/v1/responses' for r in self.requests))
    def test_join_fresh_install_no_openai_key_needed(self):
        (self.root/'team-client.json').unlink()
        invite=self.root/'invite.json';atomic_json(invite,self.config)
        atomic_json(self.root/'verification.json',{'openai':{'account_configured':False}})
        with contextlib.redirect_stdout(io.StringIO()):command(self.root,['--invite',str(invite)])
        self.assertEqual(private_json(self.root/'team-client.json')['coordinator_id'],self.identity)
        self.assertFalse((self.root/'openai-key.env').exists())
    def test_join_cannot_convert_existing_personal_binding(self):
        (self.root/'team-client.json').unlink()
        invite=self.root/'invite.json';atomic_json(invite,self.config)
        atomic_json(self.root/'verification.json',{'openai':{'account_configured':True}})
        with self.assertRaises(Denied):command(self.root,['--invite',str(invite)])
        self.assertFalse((self.root/'team-client.json').exists())
    def test_unavailable_coordinator_specific_failure(self):
        with mock.patch('http.client.HTTPConnection.request',side_effect=ConnectionRefusedError()):
            with self.assertRaises(Denied) as error:RemoteBroker(self.root).quota()
        self.assertEqual(error.exception.code,'team_unavailable')
    def test_no_remote_or_ambiguous_plaintext_endpoints(self):
        for endpoint in ('http://example.com:49200','http://localhost:49200','http://127.1:49200','https://127.0.0.1:49200','http://127.0.0.1:49200/path','http://127.0.0.1:22'):
            with self.subTest(endpoint=endpoint),self.assertRaises(Denied):validate({**self.config,'endpoint':endpoint})
    def test_connection_files_must_be_private_and_not_links(self):
        (self.root/'team-client.json').chmod(0o644)
        with self.assertRaises(Denied):RemoteBroker(self.root)
        (self.root/'link.json').symlink_to(self.root/'team-client.json')
        with self.assertRaises(Denied):private_json(self.root/'link.json')
    def test_ssh_destination_options_and_shell_fragments_denied(self):
        for ssh in ('-oProxyCommand=example','user@host;example','$(example)@host','user@host/path','host'):
            with self.subTest(ssh=ssh),self.assertRaises(Denied):validate({**self.config,'ssh':ssh,'remote_port':49200})


if __name__=='__main__':unittest.main()
