"""Atomic code selection and permanent accounting; all inputs are synthetic."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

from guard import Denied, atomic_json
import maintenance
import releases
import test_install as install_fixtures
from workspace_policy import managed_requirements, validate_managed_requirements


class ReleaseTests(unittest.TestCase):
    setUp=install_fixtures.InstallTests.setUp
    tearDown=install_fixtures.InstallTests.tearDown
    install=install_fixtures.InstallTests.install

    def initialized(self):
        self.install()
        self.initial=(self.root/'current').readlink().name
        self.original={name:(self.root/name).read_bytes() for name in ('settings.json','openai-key.env','gateway.token','verification.json','state/usage.sqlite3','state/ledger-witness.json')}

    def assert_private_preserved(self):
        self.assertEqual(self.original,{name:(self.root/name).read_bytes() for name in self.original})

    def source(self,version=None,checks='print("SYNTHETIC_OFFLINE_CHECK_PASS")\n'):
        if version is None:
            major,minor,patch_number=map(int,install_fixtures.setup.VERSION.split('.'))
            version=f'{major}.{minor}.{patch_number+1}'
        root=self.base/('review-source-'+uuid.uuid4().hex);root.mkdir()
        for directory in ('app','kit'):
            shutil.copytree(install_fixtures.setup.SOURCE/directory,root/directory,ignore=shutil.ignore_patterns('__pycache__'))
            # Attack/update fixtures are mutable copies even when the suite
            # itself runs from a frozen, read-only reviewed distribution.
            for path in (root/directory).rglob('*'):
                path.chmod(0o700 if path.is_dir() else 0o600)
            (root/directory).chmod(0o700)
        text=(install_fixtures.setup.SOURCE/'setup.py').read_text().replace("VERSION = '"+install_fixtures.setup.VERSION+"'","VERSION = '"+version+"'",1)
        (root/'setup.py').write_text(text)
        (root/'scripts').mkdir();(root/'scripts/check.py').write_text(checks)
        (root/'tests').mkdir();(root/'tests/test_smoke.py').write_text('import unittest\nclass Smoke(unittest.TestCase):\n def test_offline(self):self.assertTrue(True)\n')
        return root

    def staged(self,version=None):
        return releases.stage(self.root,self.source(version))['digest']

    def activate(self,digest):
        with patch.object(releases,'_run_checks',return_value='0'*64):
            return releases.activate(self.root,digest,reviewed_digest=digest)

    def interrupted(self,point):
        digest=self.staged()
        real_atomic=releases.atomic_json;real_switch=releases._switch
        def atomic(path,value):
            if point=='after_pointer' and Path(path)==self.root/'installation.json':raise SystemExit('synthetic interruption')
            if point=='after_manifest' and Path(path).parent==self.root/'upgrades/history':raise SystemExit('synthetic interruption')
            return real_atomic(path,value)
        def switch(root,release_id):
            if point=='before_pointer':raise SystemExit('synthetic interruption')
            return real_switch(root,release_id)
        with patch.object(releases,'_run_checks',return_value='0'*64),patch.object(releases,'atomic_json',side_effect=atomic),patch.object(releases,'_switch',side_effect=switch):
            with self.assertRaises(SystemExit):releases.activate(self.root,digest,reviewed_digest=digest)
        self.assertTrue((self.root/'upgrade-pending.json').is_file())

    def test_fresh_layout_and_settings_anchor_keep_private_state_in_place(self):
        self.initialized()
        payload=releases.validate_layout(self.root)
        self.assertEqual((self.root/'app').readlink(),Path('current/app'))
        self.assertEqual((self.root/'kit').readlink(),Path('current/kit'))
        self.assertTrue((payload/'source/setup.py').is_file())
        spec=importlib.util.spec_from_file_location('test_release_settings',self.root/'app/settings.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.ROOT,self.root);self.assertEqual(module.PORT,49321)
        self.assert_private_preserved()

    def test_staging_compiles_but_never_executes_candidate_source(self):
        self.initialized();marker=self.base/'must-not-run'
        source=self.source(checks='from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
        before=(self.root/'current').readlink()
        result=releases.stage(self.root,source)
        self.assertFalse(marker.exists());self.assertEqual((self.root/'current').readlink(),before)
        self.assertRegex(result['digest'],r'^[0-9a-f]{64}$');self.assert_private_preserved()

    def test_malformed_literal_source_metadata_is_rejected_without_execution(self):
        self.initialized()
        for suffix in ('\nAPP_FILES = ({},)\n','\nUPDATER_ABI = True\n'):
            with self.subTest(suffix=suffix):
                source=self.source();path=source/'setup.py';path.write_text(path.read_text()+suffix)
                with self.assertRaises(Denied):releases.stage(self.root,source)
        self.assert_private_preserved()

    def test_exact_review_is_required_before_running_any_candidate_test(self):
        self.initialized();digest=self.staged()
        with patch.object(releases,'_run_checks') as check:
            with self.assertRaises(Denied):releases.activate(self.root,digest,reviewed_digest='f'*64)
            check.assert_not_called()
        self.assertEqual((self.root/'current').readlink().name,self.initial);self.assert_private_preserved()

    def test_activation_runs_reviewed_check_then_changes_only_code_generation(self):
        self.initialized();digest=self.staged()
        result=releases.activate(self.root,digest,reviewed_digest=digest)
        self.assertNotEqual(result['active_release'],self.initial)
        self.assertEqual(json.loads((self.root/'installation.json').read_text())['harness_version'],result['harness_version'])
        self.assertTrue(result['native_prepare_required']);self.assertFalse((self.root/'upgrade-pending.json').exists())
        self.assertTrue(all(json.loads((self.root/'readiness.json').read_text())[key] is False for key in releases.IMAGE_KEYS))
        self.assert_private_preserved();releases.validate_layout(self.root)
        result=subprocess.run([str(self.launcher),'usage'],capture_output=True,text=True,check=True)
        self.assertEqual(len(result.stdout.splitlines()),2);self.assertTrue(result.stdout.isascii())

    def test_failed_candidate_checks_leave_active_code_and_state_unchanged(self):
        self.initialized()
        digest=releases.stage(self.root,self.source(checks='raise SystemExit(7)\n'))['digest']
        with self.assertRaises(Denied):releases.activate(self.root,digest,reviewed_digest=digest)
        self.assertEqual((self.root/'current').readlink().name,self.initial)
        self.assertFalse((self.root/'upgrade-pending.json').exists());self.assert_private_preserved()

    def test_forward_generation_uses_reviewed_candidate_renderer_and_clean_environment(self):
        self.initialized();source=self.source()
        policy=source/'app/workspace_policy.py'
        policy.write_text(policy.read_text()+'''\n_previous_renderer = managed_requirements
def managed_requirements(workspace=WORKSPACE, protected=()):
    import os
    assert 'SYNTHETIC_DO_NOT_PASS' not in os.environ
    assert Path(os.environ['HOME']).name.startswith('.policy-home-')
    return '# REVIEWED_CANDIDATE_RENDERER\\n' + _previous_renderer(workspace, protected)
''')
        config=source/'kit/config.toml'
        config.write_text(config.read_text().replace('skip_host_skill_discovery = true','skip_host_skill_discovery = true\nreviewed_future_feature = false'))
        digest=releases.stage(self.root,source)['digest']
        with patch.dict(os.environ,{'SYNTHETIC_DO_NOT_PASS':'PRIVATE_ENV_SENTINEL'}):self.activate(digest)
        requirements=(self.root/'kit/requirements.toml').read_text()
        self.assertIn('# REVIEWED_CANDIDATE_RENDERER',requirements)
        self.assertIn('reviewed_future_feature = false',requirements)
        self.assertNotIn('PRIVATE_ENV_SENTINEL',requirements)
        self.assert_private_preserved()

    def test_failed_candidate_renderer_preserves_selected_code_and_private_state(self):
        self.initialized();source=self.source();policy=source/'app/workspace_policy.py'
        policy.write_text(policy.read_text()+'\ndef managed_requirements(*args, **kwargs):\n    raise RuntimeError("SYNTHETIC_RENDER_FAILURE")\n')
        digest=releases.stage(self.root,source)['digest']
        with self.assertRaises(Denied):self.activate(digest)
        self.assertEqual((self.root/'current').readlink().name,self.initial)
        self.assertFalse((self.root/'upgrade-pending.json').exists());self.assert_private_preserved()

    def test_changed_staged_source_cannot_be_activated_after_review(self):
        self.initialized();digest=self.staged()
        path=self.root/'upgrades/candidates'/digest/'source/app/guard.py'
        path.chmod(0o600);path.write_text('CHANGED_AFTER_REVIEW')
        with patch.object(releases,'_run_checks') as check:
            with self.assertRaises(Denied):releases.activate(self.root,digest,reviewed_digest=digest)
            check.assert_not_called()
        self.assert_private_preserved()

    def test_changed_active_source_is_not_silently_blessed_by_upgrade(self):
        self.initialized();path=self.root/'app/guard.py';path.chmod(0o600);path.write_text('CHANGED_ACTIVE_SOURCE')
        with self.assertRaises(Denied):releases.stage(self.root,self.source())
        self.assert_private_preserved()

    def test_active_session_or_coordinator_blocks_upgrade_before_checks(self):
        self.initialized();digest=self.staged()
        for lock_name in ('session.lock','upgrade.lock','state/process.lock'):
            with self.subTest(lock=lock_name), (self.root/lock_name).open('a+b') as lease:
                fcntl.flock(lease,fcntl.LOCK_SH if lock_name=='upgrade.lock' else fcntl.LOCK_EX)
                with patch.object(releases,'_run_checks') as check:
                    with self.assertRaises(Denied):releases.activate(self.root,digest,reviewed_digest=digest)
                    check.assert_not_called()
        self.assert_private_preserved()

    def test_new_runtime_pins_and_direct_downgrades_are_refused(self):
        self.initialized()
        source=self.source();path=source/'setup.py';path.write_text(path.read_text().replace("SBX_VERSION = '0.49.1'","SBX_VERSION = '0.49.2'"))
        changed=releases.stage(self.root,source)['digest']
        lower=self.staged('0.1.9')
        for digest in (changed,lower):
            with self.subTest(digest=digest),patch.object(releases,'_run_checks') as check:
                with self.assertRaises(Denied):releases.activate(self.root,digest,reviewed_digest=digest)
                check.assert_not_called()
        self.assert_private_preserved()

    def test_interruption_before_pointer_recovers_to_old_code_without_state_restore(self):
        self.initialized();self.interrupted('before_pointer')
        self.assertEqual((self.root/'current').readlink().name,self.initial)
        releases.recover(self.root)
        self.assertFalse((self.root/'upgrade-pending.json').exists());self.assert_private_preserved()

    def test_interruption_after_pointer_can_finish_the_recorded_generation(self):
        self.initialized();self.interrupted('after_pointer')
        new=(self.root/'current').readlink().name
        self.assertNotEqual(new,self.initial)
        self.assertEqual(json.loads((self.root/'installation.json').read_text())['active_release'],self.initial)
        result=releases.recover(self.root,finish=True)
        self.assertEqual(result['recovered_to'],'new')
        self.assertEqual(json.loads((self.root/'installation.json').read_text())['active_release'],new)
        self.assert_private_preserved();releases.validate_layout(self.root)

    def test_interruption_after_manifest_can_recover_to_old_code_without_quota_rollback(self):
        self.initialized();self.interrupted('after_manifest')
        self.assertNotEqual(json.loads((self.root/'installation.json').read_text())['active_release'],self.initial)
        releases.recover(self.root)
        self.assertEqual((self.root/'current').readlink().name,self.initial)
        self.assertEqual(json.loads((self.root/'installation.json').read_text())['active_release'],self.initial)
        self.assert_private_preserved()

    def test_corrupt_unselected_candidate_does_not_prevent_verified_old_recovery(self):
        self.initialized();self.interrupted('after_pointer')
        path=self.root/'app/guard.py';path.chmod(0o600);path.write_text('CORRUPTED_NEW_GENERATION')
        with self.assertRaises(Denied):releases.recover(self.root,finish=True)
        releases.recover(self.root)
        self.assertEqual((self.root/'current').readlink().name,self.initial);self.assert_private_preserved()

    def test_pending_activation_fences_new_changes_and_stale_policy_recovery(self):
        self.initialized();self.interrupted('before_pointer')
        with self.assertRaises(Denied):releases.stage(self.root,self.source())
        atomic_json(self.root/'protected-paths.json',['private-notes'])
        with self.assertRaises(Denied):releases.recover(self.root)
        self.assertTrue((self.root/'upgrade-pending.json').exists());self.assert_private_preserved()

    def test_source_checkout_recovery_works_without_importing_selected_candidate(self):
        self.initialized();self.interrupted('after_pointer')
        self.assertEqual(install_fixtures.setup.main(['recover','--home',str(self.root)]),0)
        self.assertEqual((self.root/'current').readlink().name,self.initial)
        self.assert_private_preserved()

    def test_installer_does_not_resume_over_an_activation_fence(self):
        self.initialized();self.interrupted('before_pointer')
        with self.assertRaises(ValueError):self.install()
        self.assertTrue((self.root/'upgrade-pending.json').exists());self.assert_private_preserved()

    def test_rollback_keeps_complete_current_guest_kit_in_a_new_host_generation(self):
        self.initialized();source=self.source()
        entrypoint=source/'kit/entrypoint.sh'
        entrypoint.write_text(entrypoint.read_text()+'\n# CURRENT_REVIEWED_GUEST_POLICY\n')
        policy=source/'app/workspace_policy.py'
        policy.write_text(policy.read_text()+'''\n_previous_renderer = managed_requirements
def managed_requirements(workspace=WORKSPACE, protected=()):
    result = _previous_renderer(workspace, protected)
    return ('future_top_level_guard = true\\n' + result).replace('[features]\\n', '[features]\\nfuture_feature = false\\n').replace('[hooks]\\n', '[hooks]\\nfuture_hook_guard = true\\n')
''')
        self.activate(releases.stage(self.root,source)['digest'])
        maintenance.protect(self.root,['add','private-notes'])
        protected=(self.root/'protected-paths.json').read_bytes()
        current_kit={str(path.relative_to(self.root/'kit')):path.read_bytes() for path in (self.root/'kit').rglob('*') if path.is_file()}
        with patch.object(releases,'_run_checks',return_value='0'*64):result=releases.rollback(self.root,self.initial)
        self.assertNotEqual(result['active_release'],self.initial)
        self.assertEqual(result['harness_version'],install_fixtures.setup.VERSION)
        self.assertEqual((self.root/'protected-paths.json').read_bytes(),protected)
        self.assertIn('private-notes',(self.root/'kit/requirements.toml').read_text())
        self.assertEqual(current_kit,{str(path.relative_to(self.root/'kit')):path.read_bytes() for path in (self.root/'kit').rglob('*') if path.is_file()})
        self.assertNotIn('CURRENT_REVIEWED_GUEST_POLICY',(self.root/'current/source/kit/entrypoint.sh').read_text())
        for action in ('add','remove'):
            maintenance.protect(self.root,[action,'another-private-path'])
            requirements=(self.root/'kit/requirements.toml').read_text()
            for guard in ('future_top_level_guard = true','future_feature = false','future_hook_guard = true'):
                self.assertIn(guard,requirements)
        self.assert_private_preserved();releases.validate_layout(self.root)

    def test_semantic_policy_requires_exact_protected_path_and_descendant_masks(self):
        policy=managed_requirements(self.project,['private-notes'])
        self.assertTrue(validate_managed_requirements('# newer formatting\n'+policy+'\n',self.project,['private-notes']))
        for old,new in (("\"private-notes\" = \"deny\"",'"private-notes-sibling" = "deny"'),
                        ('"private-notes/**" = "deny"','"private-notes/**" = "read"'),
                        (json.dumps(str(self.project)+'/private-notes/**')+',',json.dumps(str(self.project)+'/private-notes-sibling/**')+',')):
            with self.subTest(mask=old):
                self.assertNotEqual(policy,policy.replace(old,new))
                with self.assertRaises(Denied):validate_managed_requirements(policy.replace(old,new),self.project,['private-notes'])

    def test_installed_integrity_accepts_hashed_stricter_policy_but_rejects_unhashed_bytes(self):
        self.initialized();path=self.root/'kit/requirements.toml'
        stronger='# RETAINED_NEWER_POLICY\n'+path.read_text()+'\n# Additional reviewed settings may survive a host rollback.\n'
        path.write_text(stronger)
        manifest=json.loads((self.root/'installation.json').read_text())
        manifest['files']['kit/requirements.toml']=hashlib.sha256(path.read_bytes()).hexdigest()
        atomic_json(self.root/'installation.json',manifest)
        code='import sys;sys.path.insert(0,sys.argv[1]);import controller;controller.integrity()'
        result=subprocess.run([sys.executable,'-I','-c',code,str((self.root/'app').resolve())],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        path.write_text(stronger+'# UNREVIEWED_BYTE_CHANGE\n')
        result=subprocess.run([sys.executable,'-I','-c',code,str((self.root/'app').resolve())],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('Installed file changed: kit/requirements.toml',result.stderr)
        self.assert_private_preserved()

    def test_candidate_checks_cannot_silently_change_private_state(self):
        self.initialized();digest=self.staged()
        def changed(*_):
            (self.root/'gateway.token').write_text('SYNTHETIC_CHANGED_TOKEN')
            return '0'*64
        with patch.object(releases,'_run_checks',side_effect=changed):
            with self.assertRaises(Denied):releases.activate(self.root,digest,reviewed_digest=digest)
        self.assertEqual((self.root/'current').readlink().name,self.initial)
        self.assertEqual((self.root/'gateway.token').read_text(),'SYNTHETIC_CHANGED_TOKEN')
        self.assertEqual((self.root/'state/usage.sqlite3').read_bytes(),self.original['state/usage.sqlite3'])

    def test_unreviewed_symlinks_in_source_and_active_aliases_are_rejected(self):
        self.initialized();source=self.source()
        target=source/'app/guard.py'
        # copytree preserves a staged release's read-only directory modes.
        # Only this disposable attack fixture becomes writable; the reviewed
        # source and installed code keep their original permissions.
        target.parent.chmod(0o700);target.unlink();target.symlink_to(self.root/'openai-key.env')
        with self.assertRaises(Denied):releases.stage(self.root,source)
        alias=self.root/'kit';alias.unlink();alias.symlink_to(self.base)
        with self.assertRaises(Denied):releases.validate_layout(self.root)
        self.assert_private_preserved()

    def test_legacy_layout_is_not_migrated_or_reinitialized_implicitly(self):
        self.initialized()
        (self.root/'current').unlink()
        with self.assertRaises(Denied):releases.stage(self.root,self.source())
        self.assert_private_preserved()
