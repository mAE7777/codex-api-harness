import base64
import contextlib
import concurrent.futures
import fcntl
import http.client
import io
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import platform
import pwd
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from guard import Denied, atomic_json
from shared import Team, make_server
from team_ssh import parse_public_key, fingerprint, render_config, register_key, _listen, _port
from test_guard import Connection, Response


def example_key(seed=0):
    raw=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes((value+seed)%256 for value in range(32))
    return 'ssh-ed25519 '+base64.b64encode(raw).decode()


class TeamSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'team'
        self.team=Team.initialize(self.root,'org-examplessh',0,0,all_traffic=True)
        self.team.add_member('alice','proj_examplessh',100,100)
        self.team.add_member('bob','proj_examplebob',100,100)

    def tearDown(self):
        if self.team:self.team.close()
        self.temp.cleanup()

    def test_shutdown_falls_back_to_the_owned_child_if_its_group_is_missing(self):
        from team_ssh import ManagedSSHD
        process=Mock();process.pid=12345;process.poll.return_value=None
        process.wait.side_effect=[subprocess.TimeoutExpired('owned-sshd',3),0]
        with patch('team_ssh.os.killpg',side_effect=ProcessLookupError):ManagedSSHD(process).stop()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_args.kwargs['timeout'],10)

    def test_unconfirmed_shutdown_has_an_actionable_error_without_pid_discovery(self):
        from team_ssh import ManagedSSHD
        process=Mock();process.pid=12345;process.poll.return_value=None
        process.wait.side_effect=subprocess.TimeoutExpired('owned-sshd',3)
        with patch('team_ssh.os.killpg'),self.assertRaises(Denied) as error:ManagedSSHD(process).stop()
        self.assertEqual(error.exception.code,'team_ssh_stop_unconfirmed');process.kill.assert_called_once_with()

    def test_tunnel_stop_failure_still_releases_the_coordinator_ledger(self):
        from guard import Ledger
        self.team.close();self.team=None
        server=make_server(self.root,port=0)
        server.tunnel=Mock();server.tunnel.stop.side_effect=Denied('Synthetic stop failure',code='team_ssh_stop_unconfirmed')
        try:
            with self.assertRaises(Denied):server.close_shared()
            self.assertTrue(server.team.stopping.is_set())
            ledger=Ledger(self.root/'state');ledger.close()
        finally:server.server_close()

    def test_key_wire_format_is_complete_and_only_ed25519(self):
        self.assertEqual(parse_public_key(example_key()+' comment'),example_key())
        self.assertTrue(fingerprint(example_key()).startswith('SHA256:'))
        for key in ('ssh-rsa AAAA','restrict '+example_key(),example_key()+'\n'+example_key(),example_key()[:-4],'ssh-ed25519 '+base64.b64encode(b'bad').decode(),'-----BEGIN '+'OPENSSH PRIVATE KEY-----'):
            with self.subTest(key=key[:20]):
                with self.assertRaises(Denied):parse_public_key(key)

    def test_listener_rejects_wildcards_public_multicast_and_invalid_ports(self):
        for address in ('0.0.0.0','::','8.8.8.8','224.0.0.1','example.test'):
            with self.assertRaises(Denied):_listen(address)
        for address in ('127.0.0.1','192.168.1.2','10.0.0.2','100.101.1.2','fd00::1'):
            self.assertEqual(_listen(address),address)
        for port in (0,22,65536,True,'49202'):
            with self.assertRaises(Denied):_port(port)

    def test_rendered_daemon_policy_has_only_one_forward_destination_and_no_sessions(self):
        directory=self.root/'ssh';directory.mkdir(mode=0o700)
        settings={'host':'127.0.0.1','port':49202,'remote_port':49200,'user':pwd.getpwuid(os.getuid()).pw_name}
        content=render_config(self.root,settings)
        for line in ('MaxSessions 0','PermitTTY no','PermitUserRC no','AllowAgentForwarding no','X11Forwarding no','AllowStreamLocalForwarding no','PermitListen none','AllowTcpForwarding local','PermitOpen 127.0.0.1:49200','PasswordAuthentication no','KbdInteractiveAuthentication no','UsePAM no','AuthenticationMethods publickey','TrustedUserCAKeys none','AuthorizedKeysCommand none'):
            self.assertIn(line+'\n',content)
        self.assertNotIn('Include ',content);self.assertNotIn('/etc/ssh/',content)

    def test_registering_a_key_is_member_bound_deduplicated_and_revoked(self):
        path=Path(self.temp.name)/'client.pub';path.write_text(example_key()+' alice-comment\n')
        first=register_key(self.team,'alice',path);second=register_key(self.team,'alice',path)
        self.assertEqual(first['fingerprint'],second['fingerprint'])
        self.assertEqual(self.team.ledger.db.execute('SELECT COUNT(*) FROM team_tunnel_keys').fetchone()[0],1)
        with self.assertRaises(Denied):register_key(self.team,'bob',path)
        authorized=self.root/'ssh/authorized_keys'
        self.assertIn(example_key(),authorized.read_text());self.assertEqual(stat.S_IMODE(authorized.stat().st_mode),0o600)
        self.team.revoke('alice');self.assertNotIn(example_key(),authorized.read_text())

    def test_shared_lifetime_blocks_upgrades_and_pending_upgrade_blocks_mutations(self):
        with (self.root.parent/'upgrade.lock').open('a+b') as writer:
            with self.assertRaises(BlockingIOError):fcntl.flock(writer,fcntl.LOCK_EX|fcntl.LOCK_NB)
        atomic_json(self.root.parent/'upgrade-pending.json',{'example':True})
        self.assertEqual(self.team.status()['members'][0]['member_id'],'alice')
        with self.assertRaises(Denied):self.team.revoke('alice')
        self.team.close();self.team=None
        with self.assertRaises(Denied):make_server(self.root,port=0)
        with (self.root.parent/'upgrade.lock').open('a+b') as writer:fcntl.flock(writer,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_client_never_accepts_partial_ssh_defaults_or_hardlinked_credentials(self):
        from team_client import validate
        identity=Path(self.temp.name)/'identity';identity.write_text('fake-private-identity');identity.chmod(0o600)
        known=Path(self.temp.name)/'known-hosts';known.write_text('[127.0.0.1]:49202 '+example_key()+'\n');known.chmod(0o600)
        config={'version':1,'coordinator_id':'example_coordinator','member_id':'alice','endpoint':'http://127.0.0.1:49201','token':'x'*48,
            'ssh':'example@127.0.0.1','remote_port':49200,'ssh_port':49202,'ssh_host_key':example_key(),'identity_file':str(identity),'known_hosts':str(known)}
        self.assertEqual(validate(config),49201)
        for field in ('identity_file','known_hosts','ssh_host_key','ssh_port','remote_port'):
            candidate=dict(config);candidate.pop(field)
            with self.subTest(field=field),self.assertRaises(Denied):validate(candidate)
        hardlink=Path(self.temp.name)/'identity-link';os.link(identity,hardlink)
        with self.assertRaises(Denied):validate(config)
        hardlink.unlink();os.link(known,hardlink)
        with self.assertRaises(Denied):validate(config)


@unittest.skipUnless(platform.system()=='Darwin' and os.getuid()!=0 and Path('/usr/sbin/sshd').is_file(), 'native unprivileged OpenSSH acceptance requires a normal macOS user')
class NativeTeamSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='harness-team-ssh-');self.directory=Path(self.temp.name)
        self.root=self.directory/'team';self.server=None;self.daemon=None;self.client=None;self.thread=None
        team=Team.initialize(self.root,'org-examplenative',0,0,all_traffic=True)
        try:
            team.add_member('alice','proj_examplenative',100,100)
            team.billing('alice',charges=True)
            key_path=self.root/'projects/proj_examplenative/openai-key.env'
            key_path.write_text('OPENAI_API_KEY=fake-test-only-key\n');key_path.chmod(0o600)
            self.identity=self.directory/'client-key'
            subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.identity)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            register_key(team,'alice',str(self.identity)+'.pub')
            self.remote_port=self.free_port();self.ssh_port=self.free_port()
            while self.ssh_port==self.remote_port:self.ssh_port=self.free_port()
            team.share(listen='127.0.0.1',ssh_port=self.ssh_port,coordinator_port=self.remote_port)
            invite=json.loads((self.root/'invites/alice.json').read_text());self.token=invite['token'];self.ssh=invite['ssh']
            self.known_hosts=self.directory/'known-hosts'
            self.known_hosts.write_text('[127.0.0.1]:'+str(self.ssh_port)+' '+self.ssh['host_key']+'\n');self.known_hosts.chmod(0o600)
        finally:team.close()
        self.calls=[]
        def transport(host,path,body,headers,method='POST'):
            self.calls.append(path)
            if path.endswith('input_tokens'):return Connection(),Response({'input_tokens':5},date=time.time())
            return Connection(),Response({'usage':{'input_tokens':5,'output_tokens':4},'output':[]})
        self.server=make_server(self.root,port=self.remote_port,transport=transport)
        self.daemon=self.server.start_tunnel()
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()

    def tearDown(self):
        if self.client:
            self.client.terminate()
            try:self.client.wait(timeout=3)
            except subprocess.TimeoutExpired:self.client.kill();self.client.wait(timeout=3)
            if self.client.stderr:self.client.stderr.close()
        if self.server:
            self.server.team.stopping.set()
            if self.thread:self.server.shutdown()
            self.server.server_close()
            if self.thread:self.thread.join()
            self.server.close_shared()
        self.temp.cleanup()

    def free_port(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));return listener.getsockname()[1]

    def ssh_command(self,options=(),command=()):
        return ['/usr/bin/ssh','-F','/dev/null','-p',str(self.ssh_port),'-i',str(self.identity),
            '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
            '-o','UserKnownHostsFile='+str(self.known_hosts),'-o','GlobalKnownHostsFile=/dev/null',
            '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ControlMaster=no','-o','ControlPath=none',
            '-o','ConnectTimeout=3','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
            *options,self.ssh['user']+'@127.0.0.1',*command]

    def run_ssh(self,options=(),command=()):
        return subprocess.run(self.ssh_command(options,command),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=6,
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'})

    def open_forward(self):
        port=self.free_port()
        self.client=subprocess.Popen(self.ssh_command(('-N','-o','ExitOnForwardFailure=yes','-L','127.0.0.1:'+str(port)+':127.0.0.1:'+str(self.remote_port))),
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'})
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            if self.client.poll() is not None:raise AssertionError('Dedicated SSH forward failed: '+self.client.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):return port
            except OSError:time.sleep(.05)
        raise AssertionError('Dedicated SSH forward did not become ready')

    def http(self,port,path,body=None):
        client=http.client.HTTPConnection('127.0.0.1',port,timeout=4)
        client.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),
            {'Authorization':'Bearer '+self.token,'Idempotency-Key':'native-encrypted-request','Host':'127.0.0.1:'+str(self.remote_port)})
        response=client.getresponse();raw=response.read();client.close();return response.status,json.loads(raw)

    def test_encrypted_shared_request_works_and_revoke_closes_api_authority(self):
        port=self.open_forward();status,data=self.http(port,'/identity')
        self.assertEqual(status,200);self.assertEqual(data['member_id'],'alice')
        status,data=self.http(port,'/v1/responses',{'model':'gpt-5.6-terra','input':'hello','max_output_tokens':10})
        self.assertEqual(status,200);self.assertEqual(self.calls,['/v1/responses/input_tokens','/v1/responses'])
        self.assertEqual(self.server.team.quota('alice')['daily_pools']['B']['remaining'],91)
        self.server.team.revoke('alice')
        self.assertEqual(self.http(port,'/identity')[0],401)
        self.assertNotEqual(self.run_ssh(('-W','127.0.0.1:'+str(self.remote_port))).returncode,0)

    def test_shell_sftp_other_destination_and_reverse_forward_are_blocked(self):
        sentinel=self.directory/'private-sentinel';sentinel.write_text('LOCAL_PRIVATE_SENTINEL_NOT_FOR_SSH')
        shell=self.run_ssh(command=('cat',str(sentinel)))
        self.assertNotEqual(shell.returncode,0);self.assertNotIn(b'LOCAL_PRIVATE_SENTINEL_NOT_FOR_SSH',shell.stdout)
        self.assertNotEqual(self.run_ssh(('-s',),('sftp',)).returncode,0)
        other=self.run_ssh(('-W','127.0.0.1:'+str(self.free_port())))
        self.assertNotEqual(other.returncode,0);self.assertIn(b'administratively prohibited',other.stderr)
        reverse=self.run_ssh(('-N','-o','ExitOnForwardFailure=yes','-R','127.0.0.1:'+str(self.free_port())+':127.0.0.1:'+str(self.remote_port)))
        self.assertNotEqual(reverse.returncode,0)
        self.assertEqual(self.calls,[])

    def test_wrong_host_key_is_not_accepted_and_managed_cleanup_stops_only_its_child(self):
        self.known_hosts.write_text('[127.0.0.1]:'+str(self.ssh_port)+' '+example_key(1)+'\n')
        result=self.run_ssh(('-W','127.0.0.1:'+str(self.remote_port)))
        self.assertNotEqual(result.returncode,0);self.assertIn(b'HOST IDENTIFICATION HAS CHANGED',result.stderr)
        process=self.daemon.process;self.daemon.stop();self.assertIsNotNone(process.poll())
        self.assertEqual(self.calls,[])

    def test_unix_socket_forwarding_is_blocked_in_both_directions(self):
        # Prove this identity is otherwise usable before probing a different
        # channel type. Never use a real Docker, browser, or SSH-agent socket.
        allowed_port=self.open_forward()
        self.assertEqual(self.http(allowed_port,'/identity')[0],200)
        with tempfile.TemporaryDirectory(prefix='harness-uds-',dir='/private/tmp') as temporary:
            directory=Path(temporary);destination=directory/'canary.sock';reverse_path=directory/'reverse.sock'
            reached=threading.Event();stopping=threading.Event()
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(destination));listener.listen();listener.settimeout(.1)
            def receive():
                while not stopping.is_set():
                    try:connection,_=listener.accept()
                    except socket.timeout:continue
                    except OSError:return
                    reached.set()
                    with connection:
                        connection.settimeout(.3)
                        try:
                            connection.recv(1024)
                            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nUNIX_CANARY!')
                        except OSError:pass
            thread=threading.Thread(target=receive);thread.start();client=None
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as control:
                    control.settimeout(1);control.connect(str(destination));control.sendall(b'GET /control HTTP/1.0\r\n\r\n')
                    control_reply=bytearray()
                    while len(control_reply)<2048:
                        part=control.recv(1024)
                        if not part:break
                        control_reply.extend(part)
                    self.assertIn(b'UNIX_CANARY!',control_reply)
                self.assertTrue(reached.is_set());reached.clear()
                port=self.free_port()
                client=subprocess.Popen(self.ssh_command(('-N','-o','ExitOnForwardFailure=yes','-L','127.0.0.1:'+str(port)+':'+str(destination))),
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'})
                deadline=time.monotonic()+4
                response=b''
                while time.monotonic()<deadline:
                    if client.poll() is not None:raise AssertionError('SSH identity failed before the UNIX forwarding probe')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2) as stream:
                            stream.settimeout(1);stream.sendall(b'GET /canary HTTP/1.0\r\n\r\n')
                            try:response=stream.recv(1024)
                            except OSError:pass
                        break
                    except ConnectionRefusedError:time.sleep(.05)
                else:raise AssertionError('UNIX forwarding probe local listener did not become ready')
                self.assertFalse(reached.wait(.25),'A forbidden direct-streamlocal channel reached the host UNIX socket')
                self.assertNotIn(b'UNIX_CANARY!',response)
                client.terminate();client.wait(timeout=3)
                # OpenSSH reports this policy refusal as either a generic
                # connect failure or "administratively prohibited" by version.
                self.assertIn(b'open failed',client.stderr.read())
                reverse=self.run_ssh(('-N','-o','ExitOnForwardFailure=yes','-R',str(reverse_path)+':127.0.0.1:'+str(self.remote_port)))
                self.assertNotEqual(reverse.returncode,0);self.assertFalse(reverse_path.exists())
                self.assertIn(b'remote port forwarding failed',reverse.stderr)
                self.assertEqual(self.calls,[])
            finally:
                if client is not None:
                    if client.poll() is None:
                        client.terminate()
                        try:client.wait(timeout=3)
                        except subprocess.TimeoutExpired:client.kill();client.wait(timeout=3)
                    if client.stderr:client.stderr.close()
                stopping.set();listener.close();thread.join(timeout=2)

    def test_public_keygen_join_relay_rotation_and_local_owner_flow_with_spaces(self):
        from team_client import command as real_join, keygen, private_json, RemoteBroker
        def join(root,args):
            from policy import digest,legacy
            with patch('configuration.refresh_guest',return_value=False):return real_join(root,[*args,'--reviewed-policy-digest',digest(legacy())])
        client_root=self.directory/'Client Application Support';client_root.mkdir(mode=0o700)
        workspace=self.directory/'member-workspace';workspace.mkdir(mode=0o700)
        atomic_json(client_root/'settings.json',{'workspace':str(workspace)})
        atomic_json(client_root/'verification.json',{'openai':{'account_configured':False}})
        with contextlib.redirect_stdout(io.StringIO()):keygen(client_root)
        self.server.team.tunnel_key('alice',str(client_root/'team-tunnel.key.pub'))
        invitation=self.root/'invites/alice.json'
        with contextlib.redirect_stdout(io.StringIO()):join(client_root,['--invite',str(invitation),'--local-port',str(self.free_port())])
        saved=private_json(client_root/'team-client.json')
        self.assertIn('Client Application Support',saved['known_hosts'])
        self.assertEqual(saved['ssh_host_key'],self.ssh['host_key'])
        self.assertEqual(stat.S_IMODE(Path(saved['known_hosts']).stat().st_mode),0o600)
        quota=RemoteBroker(client_root).quota();self.assertEqual(len(quota['usage_lines']),2)
        chunks=[]
        RemoteBroker(client_root).openai({'model':'gpt-5.6-terra','input':'public client fixture','max_output_tokens':10},lambda _:None,chunks.append,operation_id='native-public-interface')
        self.assertEqual(json.loads(b''.join(chunks))['usage']['input_tokens'],5)
        self.assertEqual(self.server.team.quota('alice')['daily_pools']['B']['remaining'],91)
        response=RemoteBroker(client_root).request_more({'request_id':'native-public-quota-request','group':'B','amount':10})
        self.assertEqual(response['state'],'pending')
        self.server.team.rotate('alice')
        with self.assertRaises(Denied):RemoteBroker(client_root).quota()
        with contextlib.redirect_stdout(io.StringIO()):join(client_root,['--invite',str(invitation),'--replace-member-credential','--local-port',str(self.free_port())])
        self.assertEqual(RemoteBroker(client_root).quota()['daily_pools']['B']['remaining'],91)
        owner_root=self.directory/'Owner Local Application Support';owner_root.mkdir(mode=0o700)
        atomic_json(owner_root/'verification.json',{'openai':{'account_configured':False}})
        with contextlib.redirect_stdout(io.StringIO()):join(owner_root,['--invite',str(invitation),'--local'])
        self.assertNotIn('ssh',private_json(owner_root/'team-client.json'))
        self.assertEqual(RemoteBroker(owner_root).quota()['daily_pools']['B']['remaining'],91)
        self.assertEqual(self.calls,['/v1/responses/input_tokens','/v1/responses'])

    def test_busy_preferred_port_never_gets_credentials_and_concurrent_tunnels_are_owned(self):
        from team_client import Connection as ClientConnection
        seen=[]
        class Trap(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                seen.append(self.headers.get('Authorization'));self.send_response(500);self.end_headers()
        trap=ThreadingHTTPServer(('127.0.0.1',0),Trap)
        thread=threading.Thread(target=trap.serve_forever);thread.start()
        config={'version':1,'coordinator_id':self.server.team.coordinator_id,'member_id':'alice','endpoint':'http://127.0.0.1:'+str(trap.server_port),'token':self.token,
            'ssh':self.ssh['user']+'@127.0.0.1','remote_port':self.remote_port,'ssh_port':self.ssh_port,'ssh_host_key':self.ssh['host_key'],'identity_file':str(self.identity),'known_hosts':str(self.known_hosts)}
        try:
            barrier=threading.Barrier(2)
            def connect(_):
                with ClientConnection(config) as remote:
                    barrier.wait(timeout=5)
                    self.assertNotEqual(remote.port,trap.server_port)
                    self.assertTrue(remote._owned_tunnel())
                    self.assertEqual(remote.identity()['member_id'],'alice')
                    port=remote.port;child=remote.child
                self.assertIsNotNone(child.poll())
                return port
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:ports=list(workers.map(connect,(1,2)))
            self.assertEqual(len(set(ports)),2);self.assertEqual(seen,[])
        finally:trap.shutdown();trap.server_close();thread.join()

    def test_dead_owned_tunnel_does_not_send_credentials_to_a_replacement_listener(self):
        from team_client import Connection as ClientConnection
        seen=[]
        class Trap(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                seen.append(self.headers.get('Authorization'));self.send_response(500);self.end_headers()
        config={'version':1,'coordinator_id':self.server.team.coordinator_id,'member_id':'alice','endpoint':'http://127.0.0.1:'+str(self.free_port()),'token':self.token,
            'ssh':self.ssh['user']+'@127.0.0.1','remote_port':self.remote_port,'ssh_port':self.ssh_port,'ssh_host_key':self.ssh['host_key'],'identity_file':str(self.identity),'known_hosts':str(self.known_hosts)}
        with ClientConnection(config) as remote:
            remote.child.terminate();remote.child.wait(timeout=3)
            trap=ThreadingHTTPServer(('127.0.0.1',remote.port),Trap)
            thread=threading.Thread(target=trap.serve_forever);thread.start()
            try:
                with self.assertRaises(Denied):remote.identity()
                self.assertEqual(seen,[])
            finally:trap.shutdown();trap.server_close();thread.join()

    def test_cancel_during_tunnel_start_cleans_up_the_owned_child(self):
        from team_client import Connection as ClientConnection
        config={'version':1,'coordinator_id':self.server.team.coordinator_id,'member_id':'alice','endpoint':'http://127.0.0.1:'+str(self.free_port()),'token':self.token,
            'ssh':self.ssh['user']+'@127.0.0.1','remote_port':self.remote_port,'ssh_port':self.ssh_port,'ssh_host_key':self.ssh['host_key'],'identity_file':str(self.identity),'known_hosts':str(self.known_hosts)}
        class CancelAfterSpawn:
            checks=0
            def check(inner):
                inner.checks+=1
                if inner.checks>=3:raise Denied('The request was cancelled.',code='client_cancelled')
        remote=ClientConnection(config,control=CancelAfterSpawn())
        with self.assertRaises(Denied):remote.__enter__()
        self.assertIsNotNone(remote.child);self.assertIsNotNone(remote.child.poll())
        self.assertIsNone(remote.control_directory)
        self.assertEqual(self.calls,[])
