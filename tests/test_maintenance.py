import contextlib
import fcntl
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tomllib
import unittest

from guard import Denied, atomic_json
from maintenance import protect, rotation
from workspace_policy import check_workspace, managed_requirements, validate_protected_paths


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'kit').mkdir();self.workspace=self.root/'project';self.workspace.mkdir()
        atomic_json(self.root/'settings.json',{'workspace':str(self.workspace)})
        atomic_json(self.root/'verification.json',{'openai':{'account_configured':True,'project_id':'example_project'}})
        atomic_json(self.root/'readiness.json',{'image_built':True,'filesystem_tested':True})
        policy=managed_requirements(self.workspace).encode();(self.root/'kit/requirements.toml').write_bytes(policy)
        atomic_json(self.root/'installation.json',{'files':{'kit/requirements.toml':hashlib.sha256(policy).hexdigest()}})
        (self.root/'openai-key.env').write_text('OPENAI_API_KEY=example-old-credential-value\n');(self.root/'openai-key.env').chmod(0o600)
        (self.root/'state').mkdir();(self.root/'state/unchanged').write_text('durable usage fixture')
    def tearDown(self):self.temp.cleanup()
    def quiet(self,fn,*args):
        with contextlib.redirect_stdout(io.StringIO()):return fn(*args)
    def test_rotate_only_key_not_ledger_binding_or_billing(self):
        original=(self.root/'verification.json').read_bytes()
        self.quiet(rotation,self.root,['stage'])
        next_key=self.root/'openai-key.next.env';next_key.write_text('OPENAI_API_KEY=example-new-credential-value\n')
        self.quiet(rotation,self.root,['activate'])
        self.assertIn('example-new-',(self.root/'openai-key.env').read_text())
        self.assertFalse(next_key.exists());self.assertEqual((self.root/'verification.json').read_bytes(),original)
        self.assertEqual((self.root/'state/unchanged').read_text(),'durable usage fixture')
        self.assertEqual(json.loads((self.root/'last-key-rotation.json').read_text())['provider_requests'],0)
    def test_bad_rotation_preserves_old_key(self):
        before=(self.root/'openai-key.env').read_bytes();self.quiet(rotation,self.root,['stage'])
        with self.assertRaises(Denied):rotation(self.root,['activate'])
        self.assertEqual((self.root/'openai-key.env').read_bytes(),before)
    def test_maintenance_refuses_active_session(self):
        with (self.root/'session.lock').open('a+b') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(Denied):rotation(self.root,['stage'])
            with self.assertRaises(Denied):protect(self.root,['add','private'])
    def test_exact_protected_path_masks_and_no_content_read(self):
        sensitive=self.workspace/'private';sensitive.mkdir();(sensitive/'.env').write_text('DO_NOT_READ=example')
        with self.assertRaises(Denied):check_workspace(self.workspace)
        self.assertTrue(self.quiet(protect,self.root,['add','private']))
        check_workspace(self.workspace,protected=['private'])
        policy=(self.root/'kit/requirements.toml').read_text()
        self.assertIn('"private" = "deny"',policy);self.assertIn('"private/**" = "deny"',policy)
        self.assertFalse(json.loads((self.root/'readiness.json').read_text())['image_built'])
    def test_repeated_add_is_noop(self):
        self.quiet(protect,self.root,['add','private'])
        before=(self.root/'installation.json').read_bytes()
        self.assertFalse(self.quiet(protect,self.root,['add','private']))
        self.assertEqual((self.root/'installation.json').read_bytes(),before)
    def test_ambiguous_protected_paths_rejected(self):
        for path in ('','/private','../private','private/../x','a//b','a/*','a/[b]','a\\b','a\nb'):
            with self.subTest(path=path),self.assertRaises(Denied):validate_protected_paths([path])
    def test_changed_native_policy_not_silently_rehashed(self):
        (self.root/'kit/requirements.toml').write_text('unexpected policy')
        with self.assertRaises(Denied):protect(self.root,['add','private'])
        self.assertFalse((self.root/'protected-paths.json').exists())

    def reviewed_policy(self,text):
        path=self.root/'kit/requirements.toml';path.write_text(text)
        manifest=json.loads((self.root/'installation.json').read_text())
        manifest['files']['kit/requirements.toml']=hashlib.sha256(path.read_bytes()).hexdigest()
        atomic_json(self.root/'installation.json',manifest)

    def test_path_changes_keep_newer_guards_and_unknown_builtin_denies(self):
        path=self.root/'kit/requirements.toml';text=path.read_text()
        text='future_top_level_guard = true\n'+text
        text=text.replace('[features]\n','[features]\nfuture_feature = false\n')
        text=text.replace('[hooks]\n','[hooks]\nfuture_hook_guard = true\n')
        text=text.replace('[permissions.filesystem]\n','[permissions.filesystem]\nfuture_filesystem_guard = true\n')
        text=text.replace('[permissions.codex_api_workspace.filesystem.":workspace_roots"]\n','[permissions.codex_api_workspace.filesystem.":workspace_roots"]\n"future-private" = "deny"\n"future-private/**" = "deny"\n')
        text=text.replace('deny_read = [\n','deny_read = [\n  '+json.dumps(str(self.workspace)+'/future-private')+',\n  '+json.dumps(str(self.workspace)+'/future-private/**')+',\n')
        self.reviewed_policy(text)
        for action,folder in (('add','private'),('remove','private'),('add','future-private'),('remove','future-private')):
            self.assertTrue(self.quiet(protect,self.root,[action,folder]))
            current=path.read_text();parsed=tomllib.loads(current)
            for line in ('future_top_level_guard = true','future_feature = false','future_hook_guard = true','future_filesystem_guard = true'):
                self.assertIn(line,current)
            native=parsed['permissions']['codex_api_workspace']['filesystem'][':workspace_roots']
            self.assertEqual(native['future-private'],'deny');self.assertEqual(native['future-private/**'],'deny')
            self.assertIn(str(self.workspace)+'/future-private/**',parsed['permissions']['filesystem']['deny_read'])
        self.assertNotIn('"private" = "deny"',path.read_text())
        self.assertEqual(json.loads((self.root/'protected-paths.json').read_text()),[])

    def test_unknown_policy_format_fails_before_any_mutation(self):
        path=self.root/'kit/requirements.toml'
        self.reviewed_policy(path.read_text().replace('deny_read = [','deny_read=['))
        before={name:(self.root/name).read_bytes() for name in ('kit/requirements.toml','installation.json','readiness.json')}
        with self.assertRaises(Denied):self.quiet(protect,self.root,['add','private'])
        self.assertFalse((self.root/'protected-paths.json').exists())
        self.assertEqual(before,{name:(self.root/name).read_bytes() for name in before})


if __name__=='__main__':unittest.main()
