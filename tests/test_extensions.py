"""Immutable extension reviews and guest catalog checks. No provider calls."""
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import controller
import extensions
import provision
import session_state
from guard import Denied, atomic_json

spec=importlib.util.spec_from_file_location('extension_guest_preferences',Path(__file__).parents[1]/'kit/preferences.py')
preferences=importlib.util.module_from_spec(spec);spec.loader.exec_module(preferences)
client_spec=importlib.util.spec_from_file_location('extension_guest_client',Path(__file__).parents[1]/'kit/quota-client.py')
client=importlib.util.module_from_spec(client_spec);client_spec.loader.exec_module(client)


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        from policy import legacy
        self.policy_patcher=patch.object(preferences,'model_policy',return_value=legacy());self.policy_patcher.start();self.addCleanup(self.policy_patcher.stop)
        self.client_policy_patcher=patch.object(client.runpy,'run_path',return_value={'model_policy':lambda:legacy()});self.client_policy_patcher.start();self.addCleanup(self.client_policy_patcher.stop)
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name).resolve()
        self.root=self.base/'installation';self.root.mkdir();(self.root/'kit').mkdir();(self.root/'paused').touch()
        (self.root/'readiness.json').write_text(json.dumps({key:True for key in extensions.IMAGE_KEYS}))
        atomic_json(self.root/'installation.json',{'files':{'kit/config.toml':'untouched-policy-hash'}})
        (self.root/'ledger-sentinel').write_text('KEEP_USAGE');(self.root/'key-sentinel').write_text('KEEP_KEY')
        self.source=self.base/'skill';self.source.mkdir();self.skill()
    def tearDown(self):self.tmp.cleanup()
    def skill(self,name='release-review',extra=''):
        (self.source/'SKILL.md').write_text('---\nname: '+name+'\ndescription: Review a release when asked.\n---\nRead the local change and explain concerns.\n'+extra)
    def stage(self):return extensions.stage(self.root,self.source)
    def approve(self,**kwargs):
        digest=self.stage()['digest'];extensions.approve(self.root,digest,reviewed=True,**kwargs);return digest

    def test_stage_is_bounded_copy_not_activation_and_same_bytes_have_same_digest(self):
        result=self.stage();again=self.stage()
        self.assertEqual(result['digest'],again['digest']);self.assertEqual(extensions.verify(self.root)['skills'],[])
        self.assertFalse((self.root/'kit/extensions').exists())
        self.skill(extra='An update.');self.assertNotEqual(self.stage()['digest'],result['digest'])
        snapshot=Path(result['review_directory'])/'SKILL.md'
        self.assertNotIn('An update.',snapshot.read_text());self.assertFalse(snapshot.stat().st_mode&0o222)

    def test_recover_interrupted_candidate_write_from_same_immutable_snapshot(self):
        first=self.stage();(self.root/'extensions/candidates'/(first['digest']+'.json')).unlink()
        self.assertEqual(self.stage()['digest'],first['digest'])

    def test_approval_requires_exact_digest_and_deliberate_review(self):
        result=self.stage()
        with self.assertRaises(Denied):extensions.approve(self.root,result['digest'])
        with self.assertRaises(Denied):extensions.approve(self.root,result['digest'][:12],reviewed=True)
        self.assertEqual(extensions.verify(self.root)['skills'],[])

    def test_scripts_require_separate_review_and_do_not_execute(self):
        script=self.source/'scripts/check.py';script.parent.mkdir();script.write_text('from pathlib import Path\nPath("INSTALLER_RAN").touch()\n')
        result=self.stage();self.assertEqual(result['scripts'],['scripts/check.py'])
        with self.assertRaises(Denied):extensions.approve(self.root,result['digest'],reviewed=True)
        with patch.object(subprocess,'run',side_effect=AssertionError('install execution forbidden')):
            extensions.approve(self.root,result['digest'],reviewed=True,allow_scripts=True)
        self.assertFalse((self.source/'INSTALLER_RAN').exists())
        self.assertFalse((self.root/'kit/extensions/skills/release-review/scripts/check.py').stat().st_mode&0o111)

    def test_build_contains_only_exact_approved_bytes_and_verifies_in_guest(self):
        digest=self.approve();self.assertEqual(extensions.verify_build(self.root),extensions.render_build(self.root))
        skills=preferences.managed_extensions(self.root/'kit/extensions')
        self.assertEqual(skills[0]['digest'],digest);self.assertFalse(skills[0]['allow_implicit'])
        self.assertEqual(skills[0]['path'],'/etc/codex-api/extensions/skills/release-review/SKILL.md')
        self.assertEqual((self.root/'ledger-sentinel').read_text(),'KEEP_USAGE');self.assertEqual((self.root/'key-sentinel').read_text(),'KEEP_KEY')
        manifest=json.loads((self.root/'installation.json').read_text())
        self.assertEqual(manifest['files']['kit/config.toml'],'untouched-policy-hash')
        self.assertIn('kit/extensions/catalog.json',manifest['files'])

    def test_approval_is_idempotent_and_replacement_needs_explicit_selection(self):
        digest=self.approve();before=(self.root/'extensions/registry.json').read_bytes()
        result=extensions.approve(self.root,digest,reviewed=True)
        self.assertFalse(result['changed']);self.assertEqual(before,(self.root/'extensions/registry.json').read_bytes())
        self.skill(extra='New reviewed version.');new=self.stage()['digest']
        with self.assertRaises(Denied):extensions.approve(self.root,new,reviewed=True)
        extensions.approve(self.root,new,reviewed=True,replace=True)
        self.assertEqual(extensions.verify(self.root)['skills'][0]['digest'],new)

    def test_remove_invalidates_image_not_usage_or_credentials(self):
        self.approve();atomic_json(self.root/'readiness.json',{key:True for key in extensions.IMAGE_KEYS})
        extensions.remove(self.root,'release-review')
        self.assertEqual(extensions.verify(self.root)['skills'],[])
        self.assertTrue(all(v is False for v in json.loads((self.root/'readiness.json').read_text()).values()))
        self.assertEqual(preferences.managed_extensions(self.root/'kit/extensions'),[])
        self.assertEqual((self.root/'ledger-sentinel').read_text(),'KEEP_USAGE')

    def test_active_session_and_running_gateway_prevent_any_mutation(self):
        with (self.root/'session.lock').open('a+b') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(Denied):self.stage()
        (self.root/'gateway-process.json').write_text('{}')
        with self.assertRaises(Denied):self.stage()
        (self.root/'gateway-process.json').unlink();(self.root/'paused').unlink()
        with self.assertRaises(Denied):self.stage()

    def test_symlink_hardlink_special_files_and_linked_root_are_rejected(self):
        target=self.base/'outside.txt';target.write_text('PRIVATE_SENTINEL')
        link=self.source/'linked.txt';link.symlink_to(target)
        with self.assertRaises(Denied):self.stage()
        link.unlink();os.link(target,link)
        with self.assertRaises(Denied):self.stage()
        link.unlink();os.mkfifo(link)
        with self.assertRaises(Denied):self.stage()
        link.unlink();linked=self.base/'linked';linked.symlink_to(self.source,target_is_directory=True)
        with self.assertRaises((OSError,Denied)):extensions.stage(self.root,linked)

    def test_secrets_and_binary_files_never_print_or_stage_value(self):
        secret='sk-proj-'+'A'*28;self.skill(extra=secret)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(Denied) as error:self.stage()
        self.assertNotIn(secret,str(error.exception));self.assertNotIn(secret,output.getvalue())
        self.assertFalse((self.root/'extensions/snapshots').exists())
        self.skill();(self.source/'binary.md').write_bytes(b'\xff\x00')
        with self.assertRaises(Denied):self.stage()

    def test_json_yaml_dependencies_and_secret_env_code_rejected(self):
        for name,text in [('SKILL.json','{"dependencies":{"tools":[]}}'),('agents/openai.yaml','dependencies:\n  tools: []\n'),('scripts/run.py','import os\nprint(os.getenv("OPENAI_API_KEY"))\n')]:
            with self.subTest(name=name):
                file=self.source/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(text)
                with self.assertRaises(Denied):self.stage()
                file.unlink()

    def test_size_and_unknown_types_rejected(self):
        file=self.source/'huge.md';file.write_text('x'*(extensions.MAX_FILE_BYTES+1))
        with self.assertRaises(Denied):self.stage()
        file.unlink();(self.source/'archive.zip').write_bytes(b'fake')
        with self.assertRaises(Denied):self.stage()

    def test_duplicate_frontmatter_and_nested_skills_rejected(self):
        self.skill(extra='');(self.source/'SKILL.md').write_text('---\nname: a\nname: b\ndescription: invalid\n---\n')
        with self.assertRaises(Denied):self.stage()
        self.skill();nested=self.source/'other/SKILL.md';nested.parent.mkdir();nested.write_text((self.source/'SKILL.md').read_text())
        with self.assertRaises(Denied):self.stage()

    def test_skill_only_plugin_flattens_selected_skills_without_enabling_plugin_runtime(self):
        plugin=self.base/'plugin';(plugin/'.codex-plugin').mkdir(parents=True);(plugin/'skills/release-review').mkdir(parents=True)
        (plugin/'.codex-plugin/plugin.json').write_text(json.dumps({'name':'release-tools','skills':['./skills'],'version':'1'}))
        (plugin/'skills/release-review/SKILL.md').write_text((self.source/'SKILL.md').read_text())
        staged=extensions.stage(self.root,plugin);self.assertEqual(staged['kind'],'skill-only plugin')
        extensions.approve(self.root,staged['digest'],reviewed=True)
        self.assertTrue((self.root/'kit/extensions/skills/release-review/SKILL.md').is_file())
        self.assertFalse((self.root/'kit/extensions/.codex-plugin').exists())
        manifest=plugin/'.codex-plugin/plugin.json'
        for bad in ({'name':'bad','skills':['../outside']},{'name':'bad','skills':'./skills','mcpServers':{}},{'name':'bad','skills':'./skills','hooks':{}},{'name':'bad','skills':'./skills','apps':{}}):
            manifest.write_text(json.dumps(bad))
            with self.subTest(bad=bad),self.assertRaises(Denied):extensions.stage(self.root,plugin)
        manifest.write_text(json.dumps({'name':'release-tools','skills':'./skills'}));(plugin/'install.py').write_text('print("unlisted")')
        with self.assertRaises(Denied):extensions.stage(self.root,plugin)

    def test_changed_snapshot_report_build_extra_file_and_links_fail_closed(self):
        digest=self.approve();snapshot=self.root/'extensions/snapshots'/digest/'SKILL.md';snapshot.chmod(0o600);snapshot.write_text('CHANGED')
        with self.assertRaises(Denied):extensions.verify(self.root)
        with self.assertRaises(Denied):extensions.verify_build(self.root)

    def test_build_manifest_detects_unexpected_guest_file_and_symlink(self):
        self.approve();extra=self.root/'kit/extensions/unreviewed.md';extra.write_text('UNREVIEWED')
        with self.assertRaises(Denied):extensions.verify_build(self.root)
        with self.assertRaises(ValueError):preferences.managed_extensions(self.root/'kit/extensions')
        extra.unlink();extra.symlink_to(self.root/'key-sentinel')
        with self.assertRaises(Denied):extensions.verify_build(self.root)
        with self.assertRaises(ValueError):preferences.managed_extensions(self.root/'kit/extensions')

    def test_protected_catalog_is_inserted_but_never_saved_as_preferences(self):
        self.approve();home=self.base/'guest';home.mkdir()
        base=Path(__file__).parents[1]/'kit/config.toml'
        preferences.prepare(home,base,self.root/'kit/extensions')
        config=preferences.read_config(home/'config.toml')
        self.assertTrue(config['features']['skip_host_skill_discovery']);self.assertFalse(config['features']['plugins'])
        self.assertIn('$release-review',config['developer_instructions'])
        self.assertIn('explicit user invocation required',config['developer_instructions'])
        preferences.save(home)
        self.assertNotIn('developer_instructions',json.loads((home/'preferences.json').read_text()))
        (home/'config.toml').write_text('developer_instructions="UNTRUSTED"\n[features]\nskip_host_skill_discovery=false\nplugins=true\n')
        preferences.prepare(home,base,self.root/'kit/extensions');config=preferences.read_config(home/'config.toml')
        self.assertNotIn('UNTRUSTED',config['developer_instructions']);self.assertTrue(config['features']['skip_host_skill_discovery']);self.assertFalse(config['features']['plugins'])

    def test_child_cli_pins_policy_above_project_config_and_keeps_literal_prompt_untouched(self):
        self.approve();home=self.base/'guest';home.mkdir()
        _,policy=preferences.prepare(home,Path(__file__).parents[1]/'kit/config.toml',self.root/'kit/extensions',return_policy=True)
        arguments=preferences.protected_cli_args(policy)
        overrides={arguments[index+1].partition('=')[0]:arguments[index+1].partition('=')[2] for index in range(0,len(arguments),2)}
        self.assertEqual(overrides['features.skip_host_skill_discovery'],'true');self.assertEqual(overrides['features.plugins'],'false')
        self.assertEqual(overrides['model_provider'],'"quota_gateway"');self.assertEqual(overrides['cli_auth_credentials_store'],'"ephemeral"')
        self.assertEqual(overrides['skills.bundled.enabled'],'false');self.assertEqual(overrides['skills.include_instructions'],'false')
        self.assertIn('"/bin/busybox"',overrides['mcp_servers']);self.assertEqual(overrides['notify'],'[]')
        self.assertIn('"/etc/codex-api/tool-client.py"',overrides['mcp_servers'])
        self.assertNotIn('mcp_servers.harness.command',overrides)
        self.assertIn('$release-review',json.loads(overrides['developer_instructions']))
        for attempt in ('features.skip_host_skill_discovery=false','features.plugins=true','developer_instructions="untrusted"','mcp_servers.x.command="untrusted"','model_provider="untrusted"','notify=["untrusted"]'):
            with self.subTest(attempt=attempt),self.assertRaises(preferences.PolicyArgumentError):preferences.validate_cli_args(['-c',attempt])
        prompt=['exec','--','--config','literal prompt, not an override'];combined=arguments+prompt
        self.assertEqual(combined[-len(prompt):],prompt)

    def test_guest_listing_uses_local_managed_catalog_without_gateway(self):
        self.approve();skills=preferences.managed_extensions(self.root/'kit/extensions')
        with patch.object(client.runpy,'run_path',return_value={'managed_extensions':lambda:skills}),patch.object(client.urllib.request,'Request',side_effect=AssertionError('network forbidden')),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(client.main(['extensions','list']),0)
        self.assertIn('$release-review',out.getvalue())

    def test_guest_quota_request_uses_only_fixed_local_route_and_validated_amount(self):
        requests=[]
        class Response(io.BytesIO):
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(self,request,timeout):
                requests.append(request)
                return Response(json.dumps({'request_id':json.loads(request.data)['request_id'],'state':'pending','replayed':False}).encode())
        with patch.dict(os.environ,{'CODEX_GATEWAY_TOKEN':'fake-local-token'}),patch.object(client.urllib.request,'build_opener',return_value=Opener()),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(client.main(['team','request','--group','A','--tokens','1000']),0)
        self.assertEqual(requests[0].full_url,'http://host.docker.internal:49187/v1/quota/request')
        payload=json.loads(requests[0].data);self.assertEqual(payload['amount'],1000);self.assertEqual(payload['group'],'A');self.assertRegex(payload['request_id'],r'^[a-f0-9]{32}$')
        self.assertIn('limit is unchanged until approval',out.getvalue())
        for arguments in (['--group','A','--tokens','-1'],['--group','A','--tokens','0'],['--group','A','--tokens','1.2'],['--group','C','--tokens','1'],['--group','B','--tokens','5000000'],['--group','B','--tokens','1','--url','https://example.com']):
            with self.subTest(arguments=arguments),patch.object(client.urllib.request,'Request',side_effect=AssertionError('invalid request reached network')),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):client.main(['team','request',*arguments])
        with patch.object(client.urllib.request,'Request',side_effect=AssertionError('owner command reached network')),contextlib.redirect_stderr(io.StringIO()):self.assertEqual(client.main(['team','approve','someone']),2)

    def test_reused_pending_quota_request_displays_coordinator_id_and_amount(self):
        class Response(io.BytesIO):
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(self,*args,**kwargs):return Response(b'{"request_id":"existing-request-1234","state":"pending","replayed":true,"amount":2000}')
        with patch.dict(os.environ,{'CODEX_GATEWAY_TOKEN':'fake-local-token'}),patch.object(client.urllib.request,'build_opener',return_value=Opener()),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(client.main(['team','request','--group','A','--tokens','1000']),0)
        self.assertIn('Existing quota request: existing-request-1234',out.getvalue());self.assertIn('2000 tokens',out.getvalue())


class KitActivationTests(unittest.TestCase):
    setUp=ExtensionTests.setUp
    tearDown=ExtensionTests.tearDown
    skill=ExtensionTests.skill
    def test_prepare_rebuilds_only_proven_owned_vm_once_when_managed_kit_changes(self):
        extensions.render_build(self.root)
        marker=self.root/'sandbox-created.json';atomic_json(marker,{'name':provision.NAME,'id':'owned','kit_digest':'old'})
        (self.root/'gateway.token').write_text('fake-local-token');(self.root/'verification.json').write_text('{}')
        rows=[{'name':provision.NAME,'id':'owned','workspaces':[str(provision.WORKSPACE)]}];calls=[]
        def call(args,**kwargs):
            calls.append(args)
            if args[0]=='rm':rows.clear()
            if args[0]=='create':rows.append({'name':provision.NAME,'id':'replacement','workspaces':[str(provision.WORKSPACE)]})
            return subprocess.CompletedProcess(args,0,'','')
        installation={'files':{'kit/config.toml':hashlib.sha256(b'policy').hexdigest()}}
        with patch('configuration.refresh_guest',return_value=False),patch.object(provision,'ROOT',self.root),patch.object(controller,'integrity',return_value=installation),patch.object(controller,'workspace_check'),patch.object(controller,'owned_sandbox',side_effect=lambda:rows[0] if rows else None),patch.object(controller,'sandbox_inventory',side_effect=lambda:list(rows)),patch.object(provision,'host_issues',return_value=[]),patch.object(provision,'call',side_effect=call),patch.object(provision,'acceptance',return_value={'passed':True}),patch.object(session_state,'capture') as capture,patch.object(session_state,'restore'),patch.object(session_state,'complete'):
            provision.prepare();provision.prepare()
        self.assertEqual(capture.call_args.args[3],'owned')
        self.assertEqual([c for c in calls if c[0]=='rm'],[['rm',provision.NAME,'--force']])
        self.assertEqual(len([c for c in calls if c[0]=='create']),1)
        self.assertNotEqual(json.loads(marker.read_text())['kit_digest'],'old')
        self.assertEqual((self.root/'ledger-sentinel').read_text(),'KEEP_USAGE')

    def test_prepare_refuses_unproven_identity_without_removal(self):
        extensions.render_build(self.root);atomic_json(self.root/'sandbox-created.json',{'name':provision.NAME,'id':'owned'})
        with patch('configuration.refresh_guest',return_value=False),patch.object(provision,'ROOT',self.root),patch.object(controller,'integrity',return_value={'files':{}}),patch.object(controller,'workspace_check'),patch.object(controller,'owned_sandbox',return_value=None),patch.object(provision,'host_issues',return_value=[]),patch.object(provision,'call') as call:
            with self.assertRaises(Denied):provision.prepare()
        call.assert_not_called()

    def test_capture_failure_stops_before_owned_vm_removal(self):
        extensions.render_build(self.root);marker=self.root/'sandbox-created.json';atomic_json(marker,{'name':provision.NAME,'id':'owned','kit_digest':'old'})
        with patch('configuration.refresh_guest',return_value=False),patch.object(provision,'ROOT',self.root),patch.object(controller,'integrity',return_value={'files':{}}),patch.object(controller,'workspace_check'),patch.object(controller,'owned_sandbox',return_value={'id':'owned'}),patch.object(provision,'host_issues',return_value=[]),patch.object(provision,'call') as call,patch.object(session_state,'capture',side_effect=Denied('unsafe export')):
            with self.assertRaises(Denied):provision.prepare()
        call.assert_not_called();self.assertEqual(json.loads(marker.read_text())['id'],'owned')
