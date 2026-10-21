import http.client
import json
import threading
import unittest
import test_guard as fixtures
NOW=fixtures.NOW
from gateway import make_server


class HTTPTests(unittest.TestCase):
    def setUp(self):
        fixtures.GuardTests.setUp(self)
        (self.root / "gateway.token").write_text("fake-guest-token-" + "0"*48)
        try: self.server = make_server(self.root, self.ledger, port=0, transport=self.broker.transport)
        except Exception:
            fixtures.GuardTests.tearDown(self)
            raise
        self.server.broker.clock=lambda:NOW
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        fixtures.GuardTests.tearDown(self)

    def call(self, path, payload=None, method="POST", token=True, extra=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type":"application/json"}
        if token: headers["Authorization"] = "Bearer fake-guest-token-" + "0"*48
        if extra: headers.update(extra)
        client.request(method, path, None if payload is None else json.dumps(payload), headers)
        response = client.getresponse()
        status, body = response.status, json.loads(response.read())
        client.close()
        return status, body

    def test_http_authentication_blocks_request(self):
        self.assertEqual(self.call("/v1/responses", self.payload, token=False)[0],403)
        self.assertEqual(self.calls,[])

    def test_http_endpoint_allowlist(self):
        for route in ("/v1/chat/completions", "/v1/images/generations", "/v1/videos", "/v1/audio/transcriptions", "/v1/audio/speech", "/v1/responses/compact", "/v1/files", "/v1/vector_stores", "/v1/responses?upstream=evil"):
            with self.subTest(route=route): self.assertEqual(self.call(route, self.payload)[0],403)
        self.assertEqual(self.calls,[])

    def test_http_models_are_local_and_exact(self):
        status, body = self.call("/v1/models", method="GET")
        self.assertEqual(status,200)
        self.assertEqual(len(body["data"]),5)
        self.assertEqual(self.calls,[])

    def test_http_untrusted_host_denied(self):
        self.assertEqual(self.call("/v1/responses", self.payload, extra={"Host":"attacker.example"})[0],403)
        self.assertEqual(self.calls,[])

    def test_http_unknown_eligibility_prevents_even_count(self):
        (self.root / "paused").touch()
        self.assertEqual(self.call("/v1/responses", self.payload)[0],403)
        self.assertEqual(self.calls,[])

    def test_unverified_free_only_has_an_actionable_error_before_any_provider_call(self):
        data=json.loads((self.root/'verification.json').read_text());data['openai']['verified']=False
        (self.root/'verification.json').write_text(json.dumps(data))
        status,body=self.call('/v1/responses',self.payload)
        self.assertEqual(status,403);self.assertEqual(body['error']['code'],'free_eligibility_unconfirmed')
        self.assertIn('No counting or generation',body['error']['message']);self.assertEqual(self.calls,[])

    def test_http_hosted_tool_is_blocked_before_upstream(self):
        self.assertEqual(self.call("/v1/responses", {**self.payload,"tools":[{"type":"web_search"}]})[0],403)
        self.assertEqual(self.calls,[])

    def test_provider_status_code_and_safe_reason_reach_client(self):
        from test_guard import Response
        for status,code in [(401,'invalid_api_key'),(429,'credit_balance_exhausted'),(429,'project_spend_limit_exceeded'),(400,'invalid_request_error')]:
            self.response=Response({'error':{'code':code,'message':'PRIVATE_PROMPT_OR_KEY'}},status=status)
            result,body=self.call('/v1/responses',self.payload)
            self.assertEqual(result,status)
            self.assertEqual(body['error']['code'],code)
            self.assertNotIn('PRIVATE_PROMPT_OR_KEY',json.dumps(body))

    def test_disabled_tool_has_specific_code_and_saved_diagnostic(self):
        status,body=self.call('/v1/responses',{**self.payload,'tools':[{'type':'image_generation'}]})
        self.assertEqual(status,403)
        self.assertEqual(body['error']['code'],'tool_disabled')
        saved=json.loads((self.root/'last-error.json').read_text())
        self.assertEqual(saved['code'],'tool_disabled')
        self.assertNotIn('fake-test-only-key',json.dumps(saved))

    def test_streaming_rejection_is_a_terminal_failure_not_a_success_or_broken_stream(self):
        client=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        payload={**self.payload,'stream':True,'tools':[{'type':'image_generation'}]}
        client.request('POST','/v1/responses',json.dumps(payload),{'Authorization':'Bearer fake-guest-token-'+'0'*48,'Content-Type':'application/json'})
        response=client.getresponse();raw=response.read().decode();client.close()
        self.assertEqual(response.status,200)
        self.assertIn('event: response.failed',raw)
        event=json.loads(raw.split('data: ',1)[1])
        self.assertEqual(event['type'],'response.failed')
        self.assertIn('[tool_disabled]',event['response']['error']['message'])
        self.assertNotIn('response.completed',raw)
        self.assertEqual(self.calls,[])


if __name__ == "__main__": unittest.main(verbosity=2)
