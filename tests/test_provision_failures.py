"""Retry an incomplete owned image without losing the original history."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import controller
from guard import Denied, Ledger, atomic_json, canonical
import provision
import session_state


class PartialBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name)
        (self.root/'paused').touch()
        (self.root/'openai-key.env').write_text('OPENAI_API_KEY=fake-provider-key-never-sent\n')
        (self.root/'gateway.token').write_text('fake-guest-token-never-sent')
        ledger=Ledger(self.root/'state',initialize=True);ledger.close()
        atomic_json(self.root/'readiness.json',{name:False for name in ('docker_authenticated','image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested')})
        self.permanent={name:(self.root/name).read_bytes() for name in ('openai-key.env','gateway.token','state/usage.sqlite3','state/ledger-witness.json')}
        self.rows=[];self.calls=[];self.creates=0;self.fail_next_create=True
        self.installation={'files':{'kit/entrypoint.sh':'synthetic-reviewed-kit-digest'}}
        history=b'{"type":"user_message","text":"synthetic previous session"}\n'
        self.payload={'version':1,'files':[{'path':'sessions/2026/10/22/rollout-example.jsonl','sha256':hashlib.sha256(history).hexdigest(),'data':base64.b64encode(history).decode()}]}
        self.exchanges=[]

    def tearDown(self):self.temporary.cleanup()

    def unchanged(self):
        self.assertEqual(self.permanent,{name:(self.root/name).read_bytes() for name in self.permanent})

    def exchange(self,_sbx,_name,script,**options):
        self.exchanges.append(script)
        if script==session_state.EXPORT:return canonical(self.payload)
        self.assertEqual(script,session_state.RESTORE)
        self.assertEqual(json.loads(options['data']),self.payload)
        return canonical({'restored':len(self.payload['files'])})

    def call(self,args,**_):
        self.calls.append(args)
        if args[0]=='rm':
            self.rows.clear()
        elif args[0]=='create':
            self.creates+=1
            self.rows[:]=[{'name':provision.NAME,'id':'partial-'+str(self.creates),'workspaces':[str(provision.WORKSPACE)]}]
            if self.fail_next_create:
                self.fail_next_create=False
                raise Denied('Synthetic image download failed')

    def prepare(self):
        with patch('configuration.refresh_guest',return_value=False),patch.object(provision,'ROOT',self.root),patch.object(controller,'integrity',return_value=self.installation),patch.object(controller,'workspace_check'),patch.object(controller,'owned_sandbox',side_effect=lambda:self.rows[0] if self.rows else None),patch.object(controller,'sandbox_inventory',side_effect=lambda:list(self.rows)),patch.object(provision,'host_issues',return_value=[]),patch.object(provision,'call',side_effect=self.call),patch.object(provision,'acceptance',return_value={'passed':True,'real_provider_requests':0}),patch.object(session_state,'_exchange',side_effect=self.exchange),patch('extensions.verify_build'):
            provision.prepare()

    def test_failed_first_create_is_owned_but_not_marked_built_and_retries_normally(self):
        with self.assertRaises(Denied):self.prepare()
        marker=json.loads((self.root/'sandbox-created.json').read_text())
        self.assertIs(marker['build_completed'],False);self.assertIsNone(marker['kit_digest'])
        self.assertEqual(marker['id'],'partial-1');self.unchanged()
        self.prepare()
        self.assertEqual(self.creates,2)
        self.assertEqual([args for args in self.calls if args[0]=='rm'],[['rm',provision.NAME,'--force']])
        self.assertEqual(self.exchanges,[])
        marker=json.loads((self.root/'sandbox-created.json').read_text())
        self.assertIs(marker['build_completed'],True);self.assertIsInstance(marker['kit_digest'],str)
        self.assertTrue(json.loads((self.root/'readiness.json').read_text())['image_built'])
        self.unchanged()

    def test_failed_replacement_keeps_original_backup_and_restores_it_on_retry(self):
        self.rows=[{'name':provision.NAME,'id':'original','workspaces':[str(provision.WORKSPACE)]}]
        atomic_json(self.root/'sandbox-created.json',{'name':provision.NAME,'id':'original','kit_digest':'old-kit','build_completed':True})
        with self.assertRaises(Denied):self.prepare()
        backup=(self.root/'guest-state/pending.json').read_bytes()
        self.assertEqual(json.loads(backup)['source_id'],'original')
        self.assertEqual(json.loads((self.root/'sandbox-created.json').read_text())['build_completed'],False)
        self.assertEqual(self.exchanges,[session_state.EXPORT]);self.unchanged()
        self.prepare()
        self.assertEqual(self.exchanges,[session_state.EXPORT,session_state.RESTORE])
        self.assertFalse((self.root/'guest-state/pending.json').exists())
        retained=json.loads((self.root/'guest-state/last.json').read_bytes())
        self.assertEqual(retained['source_id'],'original');self.assertEqual(retained['restored_to'],'partial-2')
        self.assertEqual(retained['payload'],self.payload);self.unchanged()

    def test_missing_legacy_build_flag_never_skips_history_capture(self):
        self.rows=[{'name':provision.NAME,'id':'legacy','workspaces':[str(provision.WORKSPACE)]}]
        atomic_json(self.root/'sandbox-created.json',{'name':provision.NAME,'id':'legacy','kit_digest':'old-kit'})
        self.fail_next_create=False
        self.prepare()
        self.assertEqual(self.exchanges,[session_state.EXPORT,session_state.RESTORE])
        retained=json.loads((self.root/'guest-state/last.json').read_text())
        self.assertEqual(retained['source_id'],'legacy');self.unchanged()
