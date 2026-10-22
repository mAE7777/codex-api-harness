import json
from pathlib import Path
import tempfile
import unittest
import fcntl
import signal
import subprocess
from unittest.mock import patch
import controller
from guard import Denied


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.parent=Path(self.temp.name)
        self.root=self.parent/'CodexAPI'; self.root.mkdir()
        self.workspace=self.parent/'project'; self.workspace.mkdir()
        (self.workspace/'user-code.txt').write_text('preserve-project')
        (self.root/'openai-key.env').write_text('fake-key-for-test-only')
        self.patches=[patch.object(controller,'ROOT',self.root),patch.object(controller,'WORKSPACE',self.workspace)]
        for p in self.patches: p.start()
    def tearDown(self):
        for p in self.patches: p.stop()
        self.temp.cleanup()

    def test_reused_name_is_never_stopped_or_removed(self):
        (self.root/'sandbox-created.json').write_text(json.dumps({'name':controller.NAME,'id':'original-id'}))
        replacement={'name':controller.NAME,'id':'different-id','workspaces':[str(self.workspace)]}
        with patch.object(controller,'sandbox_inventory',return_value=[replacement]),patch.object(controller.subprocess,'run') as run:
            with self.assertRaises(Denied): controller.reset()
            run.assert_not_called()
        self.assertEqual((self.workspace/'user-code.txt').read_text(),'preserve-project')
        self.assertTrue((self.root/'openai-key.env').exists())

    def test_retire_never_stops_shared_daemon_or_removes_another_sandbox(self):
        with patch.object(controller,'integrity'),patch.object(controller,'sandbox_inventory',return_value=[{'name':'another-project'}]),patch.object(controller,'reset') as reset,patch.object(controller.subprocess,'run') as run:
            controller.retire()
            reset.assert_called_once();run.assert_not_called()
        self.assertFalse(self.root.exists())
        self.assertEqual(len(list(self.parent.glob('CodexAPI-disabled-*'))),1)

    def test_second_start_does_not_pause_or_stop_existing_session(self):
        with (self.root/'session.lock').open('a+b') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(controller,'_start') as launch:
                with self.assertRaises(Denied):controller.start()
                launch.assert_not_called()
        self.assertFalse((self.root/'paused').exists())

    def test_health_check_uses_only_the_configured_gateway_port(self):
        (self.root/'gateway-process.json').write_text(json.dumps({'pid':12345,'identity':'gateway-test'}))
        with patch.object(controller,'PORT',49273),patch.object(controller,'process_identity',return_value='gateway-test'),patch.object(controller.http.client,'HTTPConnection') as connection:
            response=connection.return_value.getresponse.return_value
            response.status=200;response.read.return_value=b'{"pid":12345}'
            self.assertEqual(controller.runtime_state(),'running')
            connection.assert_called_once_with('127.0.0.1',49273,timeout=.4)

    def test_reset_and_retire_cannot_race_an_active_session(self):
        with (self.root/'session.lock').open('a+b') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(controller,'stop') as stop:
                for operation in (controller.reset,controller.retire):
                    with self.subTest(operation=operation.__name__),self.assertRaises(Denied):operation()
                stop.assert_not_called()
        self.assertTrue(self.root.exists());self.assertFalse((self.root/'paused').exists())

    def test_ctrl_c_is_left_to_native_cli_and_exit_cleans_up_without_traceback(self):
        class GatewayChild:
            pid=12345
            def poll(self):return None
        before=signal.getsignal(signal.SIGINT)
        def run(*args,**kwargs):
            self.assertIn('--no-daemon',args[0])
            handler=signal.getsignal(signal.SIGINT)
            self.assertTrue(callable(handler))
            handler(signal.SIGINT,None)  # Must not raise KeyboardInterrupt or stop the VM.
            stop.assert_not_called()
            return subprocess.CompletedProcess(args[0],130)
        with patch.object(controller,'blockers',return_value=[]),patch.object(controller,'owned_sandbox',return_value={}),patch.object(controller.subprocess,'Popen',return_value=GatewayChild()),patch.object(controller,'process_identity',return_value='gateway'),patch.object(controller.subprocess,'run',side_effect=run),patch.object(controller,'stop') as stop:
            controller._start()
            stop.assert_called_once()
        self.assertEqual(signal.getsignal(signal.SIGINT),before)

    def test_ctrl_c_during_startup_cleans_up_before_attaching(self):
        class Child:
            pid=12345
            def poll(self):return None
        def launch(*args,**kwargs):
            signal.getsignal(signal.SIGINT)(signal.SIGINT,None)
            return Child()
        with patch.object(controller,'blockers',return_value=[]),patch.object(controller,'owned_sandbox',return_value={}),patch.object(controller.subprocess,'Popen',side_effect=launch),patch.object(controller,'process_identity',return_value='gateway'),patch.object(controller,'stop') as stop,patch.object(controller.subprocess,'run') as run:
            with self.assertRaises(KeyboardInterrupt):controller._start()
            stop.assert_called_once();run.assert_not_called()

    def test_metered_startup_skips_only_the_free_eligibility_gate(self):
        ready={k:True for k in ('docker_authenticated','image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested')}
        ready['openai_free_verified']=False
        (self.root/'readiness.json').write_text(json.dumps(ready))
        (self.root/'verification.json').write_text(json.dumps({'openai':{'billing_policy':'metered'}}))
        with patch.object(controller,'verify_guest'),patch.object(controller,'integrity'),patch.object(controller,'workspace_check'),patch.object(controller,'credentials',return_value={'OPENAI_API_KEY':'fake'}):
            self.assertEqual(controller.blockers(),[])
            ready['network_tested']=False
            (self.root/'readiness.json').write_text(json.dumps(ready))
            self.assertIn('Sandbox outbound network restrictions have not been tested',controller.blockers())

    def test_retire_archives_credentials_and_preserves_project(self):
        with patch.object(controller,'integrity'),patch.object(controller,'sandbox_inventory',return_value=[]),patch.object(controller,'reset'),patch.object(controller.subprocess,'run') as run:
            controller.retire()
            self.assertFalse(run.called)
        archives=list(self.parent.glob('CodexAPI-disabled-*'))
        self.assertEqual(len(archives),1)
        self.assertEqual((archives[0]/'openai-key.env').read_text(),'fake-key-for-test-only')
        self.assertEqual((self.workspace/'user-code.txt').read_text(),'preserve-project')
        self.assertFalse(self.root.exists())

    def test_cli_failure_does_not_echo_private_prompt_or_config_arguments(self):
        class Child:
            pid=12345
            def poll(self):return None
        with patch.object(controller,'blockers',return_value=[]),patch.object(controller,'owned_sandbox',return_value={}),patch.object(controller.subprocess,'Popen',return_value=Child()),patch.object(controller,'process_identity',return_value='gateway'),patch.object(controller.subprocess,'run',return_value=subprocess.CompletedProcess([],2)),patch.object(controller,'show_noninteractive_notices'),patch.object(controller,'stop') as stop:
            with self.assertRaises(Denied) as error:controller._start(('exec','PRIVATE_PROMPT_SENTINEL'))
            self.assertNotIn('PRIVATE_PROMPT_SENTINEL',str(error.exception));stop.assert_called_once()
