import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

from guard import Denied, Ledger, atomic_json, normalize
from gateway import Broker, decode_json

NOW = dt.datetime(2026, 10, 21, 12, tzinfo=dt.timezone.utc).timestamp()
DAY = "2026-10-21"


class Response(io.BytesIO):
    def __init__(self, value=None, raw=None, status=200, content_type="application/json"):
        super().__init__(raw if raw is not None else json.dumps(value).encode())
        self.status, self.content_type = status, content_type
    def getheader(self, name, default=None):
        return self.content_type if name.lower() == "content-type" else default


class Connection:
    def close(self): pass


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ledger = Ledger(self.root / "state", initialize=True, clock=lambda: NOW)
        for group in "AB": self.ledger.configure_budget("openai:" + group, DAY, 100)
        self.ledger.pause(False)
        self.payload = {"model": "gpt-5.6-terra", "input": "hello", "max_output_tokens": 10}
        receipt = {"enabled": True, "verified": True, "verified_at": NOW-1, "valid_until": NOW+100,
            "sharing_enabled": True, "org_traffic_accounted": True,
            "count_endpoint_free_confirmed": True, "local_tool_inference_free_confirmed": True,
            "tier": "build", "project_id": "fake-project", "organization_id": "fake-org"}
        atomic_json(self.root / "verification.json", {"openai": receipt})
        (self.root / "openai-key.env").write_text("OPENAI_API_KEY=fake-test-only-key\n")
        (self.root / "openai-key.env").chmod(0o600)
        self.calls = []
        self.response = Response({"usage": {"input_tokens": 5, "output_tokens": 4}})
        def transport(host, path, body, headers, method="POST"):
            self.calls.append((host, path, body, headers, method))
            if path.endswith("input_tokens"): return Connection(), Response({"input_tokens": 5})
            return Connection(), self.response
        self.broker = Broker(self.root, self.ledger, transport, clock=lambda: NOW)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def request(self, payload=None):
        self.broker.openai(payload or self.payload, lambda _: None, lambda _: None)

    def test_five_models_only(self):
        from guard import MODELS
        for model in MODELS: self.assertEqual(normalize({**self.payload, "model": model})["model"], model)
        with self.assertRaises(Denied): normalize({**self.payload, "model": "unapproved-model"})

    def test_local_code_mode_is_not_a_hosted_tool(self):
        tools = [{"type":"namespace","name":"functions","tools":[
            {"type":"custom","name":"exec","format":{"type":"grammar","syntax":"lark","definition":"SOURCE: /.+/"}},
            {"type":"function","name":"wait","parameters":{"type":"object"}},
        ]}]
        self.assertEqual(normalize({**self.payload,"tools":tools})['tools'],tools)
        with self.assertRaises(Denied): normalize({**self.payload,'tools':[{'type':'code_interpreter'}]})

    def test_client_telemetry_is_removed(self):
        self.assertNotIn('client_metadata',normalize({**self.payload,'client_metadata':{'x-codex-turn-metadata':'{}'}}))

    def test_client_tool_declarations_are_checked_then_lifted(self):
        tool={'type':'custom','name':'exec','description':'Local code-mode runtime'}
        item={'type':'additional_tools','role':'developer','id':'local-tools','tools':[tool]}
        payload={**self.payload,'input':[item,{'role':'user','content':'hello'}]}
        result=normalize(payload)
        self.assertEqual(result['tools'],[tool])
        self.assertEqual(len(result['input']),1)
        item['tools']=[{'type':'web_search'}]
        with self.assertRaises(Denied): normalize(payload)

    def test_unknown_nested_input_options_are_blocked(self):
        for item in [
            {'role':'user','content':'hello','unreviewed_future_option':True},
            {'role':'user','content':[{'type':'input_text','text':'hello','file_id':'hidden-file'}]},
            {'type':'custom_tool_call','name':'exec','namespace':'unreviewed','call_id':'test','input':'text(1)'},
        ]:
            with self.subTest(item=item),self.assertRaises(Denied): normalize({**self.payload,'input':[item]})

    def test_local_clock_and_async_question_are_allowed(self):
        tools=[{'type':'namespace','name':'clock','tools':[{'type':'function','name':'sleep','parameters':{'type':'object'}}]},
               {'type':'function','name':'request_user_input_async','parameters':{'type':'object'}}]
        self.assertEqual(normalize({**self.payload,'tools':tools})['tools'],tools)
        tools[0]['tools']=[{'type':'function','name':'exec_command'}]
        with self.assertRaises(Denied): normalize({**self.payload,'tools':tools})

    def test_all_hosted_tool_types_denied(self):
        for kind in ("web_search", "web_search_preview", "file_search", "code_interpreter", "shell", "computer", "image_generation", "mcp", "future_unknown_tool"):
            with self.subTest(kind=kind), self.assertRaises(Denied):
                normalize({**self.payload, "tools": [{"type": kind}]})

    def test_local_tools_remain_usable(self):
        tools = [{"type": "namespace", "name": "functions", "tools": [
            {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
            {"type": "custom", "name": "apply_patch", "format": {"type": "text"}}]}]
        self.assertEqual(normalize({**self.payload, "tools": tools})["tools"], tools)

    def test_namespace_cannot_hide_hosted_tool(self):
        with self.assertRaises(Denied): normalize({**self.payload, "tools": [{"type": "namespace", "name": "functions", "tools": [{"type": "web_search"}]}]})

    def test_unknown_fields_and_paid_tiers_denied(self):
        for extra in ({"service_tier": "priority"}, {"background": True}, {"previous_response_id": "old"}, {"conversation": "old"}, {"store": True}, {"api_key": "override"}, {"max_output_tokens": 4097}):
            with self.subTest(extra=extra), self.assertRaises(Denied): normalize({**self.payload, **extra})

    def test_media_and_external_inputs_denied(self):
        for part in ({"type": "input_audio"}, {"type": "input_file", "file_id": "file-test"}, {"type": "input_image", "image_url": "https://example.com/a.png"}):
            with self.assertRaises(Denied): normalize({**self.payload, "input": [{"role": "user", "content": [part]}]})

    def test_duplicate_json_rejected(self):
        with self.assertRaises(Denied): decode_json(b'{"model":"a","model":"b"}')
        with self.assertRaises(Denied): decode_json(b'{"x":NaN}')

    def test_unverified_free_entitlement_has_zero_network_calls(self):
        data = json.loads((self.root / "verification.json").read_text())
        data["openai"]["count_endpoint_free_confirmed"] = False
        atomic_json(self.root / "verification.json", data)
        with self.assertRaises(Denied): self.request()
        self.assertEqual(self.calls, [])

    def test_expired_receipt_has_zero_network_calls(self):
        data = json.loads((self.root / "verification.json").read_text())
        data["openai"]["valid_until"] = NOW
        atomic_json(self.root / "verification.json", data)
        with self.assertRaises(Denied): self.request()
        self.assertEqual(self.calls, [])

    def metered(self):
        data = json.loads((self.root / "verification.json").read_text())
        data["openai"].update(billing_policy="metered", verified=False, valid_until=0,
            org_traffic_accounted=False, count_endpoint_free_confirmed=False,
            local_tool_inference_free_confirmed=False)
        atomic_json(self.root / "verification.json", data)

    def test_metered_mode_needs_no_free_claim_count_request_or_budget(self):
        self.metered()
        self.ledger.db.execute("DELETE FROM budgets")
        self.request()
        self.assertEqual([c[1] for c in self.calls], ["/v1/responses"])
        self.assertEqual(self.ledger.db.execute("SELECT actual FROM requests").fetchone()[0], 9)
        self.assertFalse(json.loads((self.root / "verification.json").read_text())["openai"]["verified"])

    def test_metered_mode_still_rejects_hosted_tools_and_pause(self):
        self.metered()
        with self.assertRaises(Denied): self.request({**self.payload,"tools":[{"type":"web_search"}]})
        (self.root / "paused").touch()
        with self.assertRaises(Denied): self.request()
        self.assertEqual(self.calls, [])

    def test_metered_unknown_is_recorded_without_blocking_the_next_manual_request(self):
        self.metered()
        self.response = Response({"output": []})
        with self.assertRaises(Denied): self.request()
        self.response = Response({"usage": {"input_tokens": 5, "output_tokens": 4}})
        self.request()
        self.assertEqual(self.ledger.status()["requests"], 2)
        self.assertEqual(self.ledger.status()["unresolved"], 1)
        self.assertEqual([c[1] for c in self.calls], ["/v1/responses", "/v1/responses"])

    def test_paused_has_zero_network_calls(self):
        (self.root / "paused").touch()
        with self.assertRaises(Denied): self.request()
        self.assertEqual(self.calls, [])

    def test_full_history_and_tool_schemas_are_counted(self):
        payload = {**self.payload, "instructions": "system instructions", "input": [
            {"role": "user", "content": "old question"}, {"role": "assistant", "content": "old answer"},
            {"role": "user", "content": "new question"}],
            "tools": [{"type": "function", "name": "exec_command", "parameters": {"type": "object"}}]}
        self.request(payload)
        counted, inferred = self.calls[0][2], self.calls[1][2]
        for field in ("model", "input", "instructions", "tools"): self.assertEqual(counted[field], inferred[field])
        self.assertEqual(inferred["max_output_tokens"], 10)
        self.assertFalse(inferred["store"])
        self.assertEqual(inferred["service_tier"], "default")

    def test_upstream_identity_is_pinned(self):
        self.request()
        self.assertTrue(all(c[0] == "api.openai.com" for c in self.calls))
        self.assertEqual(self.calls[1][3]["OpenAI-Project"], "fake-project")

    def test_threshold_and_whole_request_reservation(self):
        request_id = self.ledger.reserve("openai:A", DAY, 100, {})
        self.ledger.dispatch(request_id); self.ledger.settle(request_id, 100)
        with self.assertRaises(Denied): self.ledger.reserve("openai:A", DAY, 1, {})
        with self.assertRaises(Denied): self.ledger.reserve("openai:B", DAY, 101, {})

    def test_concurrent_reservations_cannot_race(self):
        results = []
        def run():
            try: results.append(self.ledger.reserve("openai:A", DAY, 60, {}))
            except Denied: pass
        threads = [threading.Thread(target=run) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(results), 1)

    def test_timeout_is_not_refunded_or_retried(self):
        def failed(host, path, body, headers, method="POST"):
            self.calls.append(path)
            if path.endswith("input_tokens"): return Connection(), Response({"input_tokens": 5})
            raise TimeoutError("simulated after dispatch")
        self.broker.transport = failed
        with self.assertRaises(TimeoutError): self.request()
        self.assertEqual(self.calls.count("/v1/responses"), 1)
        self.assertEqual(self.ledger.status()["unresolved"], 1)
        with self.assertRaises(Denied): self.ledger.reserve("openai:B", DAY, 1, {})

    def test_missing_terminal_usage_freezes_group(self):
        self.response = Response({"output": []})
        with self.assertRaises(Denied): self.request()
        self.assertEqual(self.ledger.status()["unresolved"], 1)

    def test_duplicate_sse_terminal_settles_once(self):
        event = {"type": "response.completed", "response": {"usage": {"input_tokens": 5, "output_tokens": 4, "output_tokens_details": {"reasoning_tokens": 3}}}}
        raw = b"data: " + json.dumps(event).encode() + b"\n\n"
        self.response = Response(raw=raw + raw + b"data: [DONE]\n\n", content_type="text/event-stream")
        self.request({**self.payload, "stream": True})
        self.assertEqual(self.ledger.db.execute("SELECT actual FROM requests").fetchone()[0], 9)
        self.assertEqual(self.ledger.status()["unresolved"], 0)

    def test_client_disconnect_still_accounts_usage(self):
        def disconnect(_): raise BrokenPipeError()
        self.broker.openai(self.payload, lambda _: None, disconnect)
        self.assertEqual(self.ledger.status()["unresolved"], 0)

    def test_actual_above_reservation_freezes_group(self):
        self.response = Response({"usage": {"input_tokens": 5, "output_tokens": 11}})
        with self.assertRaises(Denied): self.request()
        self.assertEqual(self.ledger.status()["unresolved"], 1)

    def test_cancel_between_count_and_dispatch(self):
        original = self.broker.transport
        def cancel(host, path, body, headers, method="POST"):
            result = original(host, path, body, headers, method)
            if path.endswith("input_tokens"): (self.root / "paused").touch()
            return result
        self.broker.transport = cancel
        with self.assertRaises(Denied): self.request()
        self.assertEqual([c[1] for c in self.calls], ["/v1/responses/input_tokens"])

    def test_process_lock(self):
        with self.assertRaises(Denied): Ledger(self.root / "state", clock=lambda: NOW)

    def test_missing_ledger_never_initializes_silently(self):
        with self.assertRaises(Denied): Ledger(self.root / "missing", clock=lambda: NOW)

    def test_reinitialization_cannot_reset_budget(self):
        other = self.root / "another"
        first = Ledger(other, initialize=True, clock=lambda: NOW); first.close()
        with self.assertRaises(Denied): Ledger(other, initialize=True, clock=lambda: NOW)

    def test_old_database_restore_is_detected(self):
        other = self.root / "restore"
        ledger = Ledger(other, initialize=True, clock=lambda: NOW)
        old = other / "old.sqlite3"
        import sqlite3
        backup = sqlite3.connect(old); ledger.db.backup(backup); backup.close()
        ledger.configure_budget("test", DAY, 100); ledger.close()
        (other / "usage.sqlite3").write_bytes(old.read_bytes())
        with self.assertRaises(Denied): Ledger(other, clock=lambda: NOW)

    def test_clock_jump_stops_admission(self):
        self.ledger.clock = lambda: NOW + 3600
        with self.assertRaises(Denied): self.ledger.reserve("openai:A", DAY, 1, {})

    def test_unknown_survives_restart_and_new_day(self):
        request_id = self.ledger.reserve("openai:A", DAY, 20, {})
        self.ledger.dispatch(request_id); self.ledger.close()
        self.ledger = Ledger(self.root / "state", clock=lambda: NOW + 86400)
        self.ledger.configure_budget("openai:A", "2026-10-22", 100)
        with self.assertRaises(Denied): self.ledger.reserve("openai:A", "2026-10-22", 1, {})

    def test_utc_rollover_dispatch_guard(self):
        other = self.root / "midnight"
        timestamp = dt.datetime(2026,10,21,23,56,tzinfo=dt.timezone.utc).timestamp()
        ledger = Ledger(other, initialize=True, clock=lambda: timestamp)
        try:
            ledger.configure_budget("openai:A", DAY, 100); ledger.pause(False)
            request_id = ledger.reserve("openai:A", DAY, 1, {})
            with self.assertRaises(Denied): ledger.dispatch(request_id)
        finally: ledger.close()

    def test_unverified_search_has_zero_network_calls(self):
        with self.assertRaises(Denied): self.broker.search({"provider": "brave", "query": "test"})
        self.assertEqual(self.calls, [])

    def test_audit_write_failure_prevents_inference(self):
        def disk_full(): raise OSError("simulated disk full")
        self.ledger._write_witness = disk_full
        with self.assertRaises(OSError): self.request()
        self.assertEqual([c[1] for c in self.calls], ["/v1/responses/input_tokens"])
        with self.assertRaises(Denied): self.ledger.reserve("openai:A", DAY, 1, {})

    def test_incomplete_sse_with_usage_is_accounted(self):
        event={"type":"response.incomplete","response":{"usage":{"input_tokens":5,"output_tokens":10}}}
        self.response=Response(raw=b"data: "+json.dumps(event).encode()+b"\n\n",content_type="text/event-stream")
        self.request({**self.payload,"stream":True})
        self.assertEqual(self.ledger.status()["unresolved"],0)

    def test_partial_sse_without_terminal_retains_reservation(self):
        self.response=Response(raw=b'data: {"type":"response.output_text.delta","delta":"partial"}\n\n',content_type="text/event-stream")
        with self.assertRaises(Denied): self.request({**self.payload,"stream":True})
        self.assertEqual(self.ledger.status()["unresolved"],1)


if __name__ == "__main__": unittest.main(verbosity=2)
