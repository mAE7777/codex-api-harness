"""Automatic guest JSONL preservation. All data and transports are local fixtures."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from guard import Denied, atomic_json, canonical
import session_state as state


def entry(path,data):
    if isinstance(data,str):data=data.encode()
    return {'path':path,'sha256':hashlib.sha256(data).hexdigest(),'data':base64.b64encode(data).decode()}


class SessionStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name).resolve()
        self.root=self.base/'installation';self.root.mkdir();self.guest=self.base/'guest';self.guest.mkdir()
        self.files=[entry('sessions/2026/10/22/rollout-one.jsonl','{"type":"session_meta","id":"fake"}\n'),entry('history.jsonl','{"text":"previous command"}\n'),entry('preferences.json','{"model":"gpt-6.1-sol","model_reasoning_effort":"high"}')]
        self.payload={'version':1,'files':self.files}
    def tearDown(self):self.tmp.cleanup()
    def run_guest(self,script,payload=None):
        script=script.replace('/home/agent/.codex-api',str(self.guest))
        return subprocess.run([sys.executable,'-I','-c',script],input=canonical(payload) if payload is not None else None,capture_output=True)
    def capture(self,identity='original'):
        with patch.object(state,'_exchange',return_value=canonical(self.payload)):
            return state.capture(self.root,'fake-sbx','owned',identity,env={})

    def test_capture_backup_is_private_and_contains_no_host_or_other_guest_state(self):
        self.capture();path=self.root/'guest-state/pending.json'
        self.assertFalse(path.stat().st_mode&0o077);self.assertFalse(path.parent.stat().st_mode&0o077)
        record=json.loads(path.read_bytes());self.assertEqual(record['source_id'],'original');self.assertIsNone(record['restored_to'])
        self.assertEqual(record['payload'],self.payload)

    def test_export_filters_preferences_and_ignores_auth_config_policy_plugins_and_databases(self):
        (self.guest/'sessions').mkdir();(self.guest/'sessions/one.jsonl').write_text('{"type":"message","text":"saved"}\n')
        (self.guest/'auth.json').write_text('PRIVATE_LOGIN_SENTINEL');(self.guest/'state_5.sqlite').write_text('PRIVATE_DATABASE_SENTINEL')
        (self.guest/'config.toml').write_text('model="gpt-6.1-sol"\nmodel_provider="UNTRUSTED_PROVIDER"\nnotify=["UNTRUSTED_COMMAND"]\n[features]\nplugins=true\n[tui]\ntheme="nord"\n')
        (self.guest/'preferences.json').write_text('{"model":"gpt-5.6-terra","auth":"PRIVATE_PREF_SENTINEL"}')
        (self.guest/'plugins').mkdir();(self.guest/'plugins/private.json').write_text('PRIVATE_PLUGIN_SENTINEL')
        result=self.run_guest(state.EXPORT);self.assertEqual(result.returncode,0,result.stderr.decode())
        payload=state.validate_payload(json.loads(result.stdout));self.assertEqual({row['path'] for row in payload['files']},{'sessions/one.jsonl','preferences.json'})
        prefs=json.loads(base64.b64decode(next(row['data'] for row in payload['files'] if row['path']=='preferences.json')))
        self.assertEqual(prefs,{'model':'gpt-6.1-sol','tui':{'theme':'nord'}})
        self.assertNotIn('PRIVATE',json.dumps(prefs));self.assertNotIn('UNTRUSTED',json.dumps(prefs))

    def test_export_rejects_links_and_hardlinks_in_selected_history(self):
        (self.guest/'sessions').mkdir();outside=self.base/'outside.jsonl';outside.write_text('{"private":"sentinel"}\n')
        target=self.guest/'sessions/linked.jsonl';target.symlink_to(outside)
        result=self.run_guest(state.EXPORT);self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        target.unlink();os.link(outside,target)
        result=self.run_guest(state.EXPORT);self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_native_compressed_sessions_are_preserved_as_opaque_exact_bytes(self):
        # Transport recognizes only native zstd magic; it never decompresses or
        # interprets archived history on the host.
        compressed=b'\x28\xb5\x2f\xfd\x00\xff\x80\x00fixture'
        folder=self.guest/'archived_sessions/2026/10';folder.mkdir(parents=True)
        path=folder/'rollout.jsonl.zst';path.write_bytes(compressed)
        result=self.run_guest(state.EXPORT);self.assertEqual(result.returncode,0,result.stderr.decode())
        payload=state.validate_payload(json.loads(result.stdout));self.assertEqual(base64.b64decode(payload['files'][0]['data']),compressed)
        path.unlink();restored=self.run_guest(state.RESTORE,payload);self.assertEqual(restored.returncode,0,restored.stderr.decode());self.assertEqual(path.read_bytes(),compressed)
        path.write_bytes(b'not a native zstd frame')
        result=self.run_guest(state.EXPORT);self.assertNotEqual(result.returncode,0)

    def test_unknown_or_in_progress_history_stops_capture_instead_of_dropping_it(self):
        folder=self.guest/'sessions';folder.mkdir();path=folder/'rollout.jsonl.zst.tmp';path.write_text('compression in progress')
        result=self.run_guest(state.EXPORT);self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_restore_script_exact_bytes_idempotence_and_safe_permissions(self):
        result=self.run_guest(state.RESTORE,self.payload);self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),{'restored':3})
        for row in self.files:
            path=self.guest/row['path'];self.assertEqual(path.read_bytes(),base64.b64decode(row['data']));self.assertFalse(path.stat().st_mode&0o077)
        repeated=self.run_guest(state.RESTORE,self.payload);self.assertEqual(repeated.returncode,0,repeated.stderr.decode())
        (self.guest/'history.jsonl').write_text('new history must survive')
        collision=self.run_guest(state.RESTORE,self.payload);self.assertNotEqual(collision.returncode,0)
        self.assertEqual((self.guest/'history.jsonl').read_text(),'new history must survive')

    def test_restore_script_never_follows_guest_links_or_overwrites_login(self):
        outside=self.base/'outside';outside.mkdir();(self.guest/'sessions').symlink_to(outside,target_is_directory=True)
        result=self.run_guest(state.RESTORE,self.payload);self.assertNotEqual(result.returncode,0);self.assertEqual(list(outside.iterdir()),[])
        (self.guest/'sessions').unlink();(self.guest/'auth.json').write_text('KEEP_LOGIN')
        result=self.run_guest(state.RESTORE,self.payload);self.assertNotEqual(result.returncode,0);self.assertEqual((self.guest/'auth.json').read_text(),'KEEP_LOGIN')

    def test_backup_restore_confirmation_and_retention_across_failed_acceptance(self):
        self.capture()
        with patch.object(state,'_exchange',return_value=b'{"restored":3}') as exchange:
            result=state.restore(self.root,'fake-sbx','owned','replacement',env={});again=state.restore(self.root,'fake-sbx','owned','replacement',env={})
        self.assertEqual(exchange.call_count,1);self.assertEqual(result,again)
        self.assertTrue((self.root/'guest-state/pending.json').exists())
        state.complete(self.root,'replacement');self.assertFalse((self.root/'guest-state/pending.json').exists());self.assertTrue((self.root/'guest-state/last.json').exists())

    def test_interrupted_replacement_never_recaptures_empty_guest_over_original_backup(self):
        self.capture();before=(self.root/'guest-state/pending.json').read_bytes()
        with patch.object(state,'_exchange',side_effect=AssertionError('empty replacement must not replace original backup')):
            state.capture(self.root,'fake-sbx','owned','replacement',env={})
        self.assertEqual(before,(self.root/'guest-state/pending.json').read_bytes())

    def test_invalid_confirmation_keeps_backup_for_retry_and_completion_is_fenced(self):
        self.capture();before=(self.root/'guest-state/pending.json').read_bytes()
        with patch.object(state,'_exchange',return_value=b'{"restored":0}'):
            with self.assertRaises(Denied):state.restore(self.root,'fake-sbx','owned','replacement',env={})
        self.assertEqual(before,(self.root/'guest-state/pending.json').read_bytes())
        with self.assertRaises(Denied):state.complete(self.root,'replacement')

    def test_unsafe_paths_duplicate_entries_tampering_and_pref_policy_rejected(self):
        for path in ('auth.json','config.toml','state_5.sqlite','../history.jsonl','sessions/../history.jsonl','sessions//history.jsonl','/history.jsonl','plugins/a.jsonl'):
            with self.subTest(path=path),self.assertRaises(Denied):state.validate_payload({'version':1,'files':[entry(path,'{}')]})
        with self.assertRaises(Denied):state.validate_payload({'version':1,'files':[self.files[0],self.files[0]]})
        bad=entry('history.jsonl','{}');bad['sha256']='0'*64
        with self.assertRaises(Denied):state.validate_payload({'version':1,'files':[bad]})
        with self.assertRaises(Denied):state.validate_payload({'version':1,'files':[entry('preferences.json','{"model_provider":"evil"}') ]})

    def test_corrupt_or_linked_backup_never_reaches_guest(self):
        self.capture();path=self.root/'guest-state/pending.json';record=json.loads(path.read_bytes());record['checksum']='changed';atomic_json(path,record)
        with patch.object(state,'_exchange',side_effect=AssertionError('invalid backup sent')):
            with self.assertRaises(Denied):state.restore(self.root,'fake-sbx','owned','replacement',env={})
        other=path.with_name('linked.json');path.rename(other);path.symlink_to(other)
        with self.assertRaises(Denied):state.restore(self.root,'fake-sbx','owned','replacement',env={})

    def test_limits_reject_export_before_original_vm_replacement(self):
        with patch.object(state,'MAX_TOTAL_BYTES',3):
            with self.assertRaises(Denied):state.validate_payload(self.payload)
        with patch.object(state,'_exchange',return_value=b'not-json'):
            with self.assertRaises(Denied):state.capture(self.root,'fake-sbx','owned','original',env={})
        self.assertFalse((self.root/'guest-state/pending.json').exists())

    def test_untrusted_transport_stdout_is_bounded_and_timeout_kills_owned_process(self):
        sbx=self.base/'fake-sbx';sbx.write_text('#!'+sys.executable+'\nimport sys\nsys.stdout.buffer.write(b"x"*100000)\n');sbx.chmod(0o700)
        with self.assertRaises(Denied):state._exchange(sbx,'owned','unused',env={},maximum=1024)
        sbx.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(10)\n')
        start=time.monotonic()
        with patch.object(state,'TIMEOUT',.1),self.assertRaises(Denied):state._exchange(sbx,'owned','unused',env={})
        self.assertLess(time.monotonic()-start,3)
