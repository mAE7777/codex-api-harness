"""Host-side shared-mode relay. The guest never receives the member credential.

Remote access is an explicit SSH port-forward to a loopback-only coordinator.
No HTTP proxy, subscription credential, shell startup, or SSH agent is inherited.
"""
from __future__ import annotations
import argparse
import base64
import contextlib
import fcntl
import hmac
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import threading
import tempfile
import time
import uuid

from guard import Denied, atomic_json, canonical, normalize
from policy import load as load_policy, validate as validate_policy, digest as policy_digest, limits as policy_limits, usage_lines, PolicyError, legacy
from transport_control import RequestControl


def private_json(path):
    path = Path(path)
    try:
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(descriptor,'rb') as source:
            info=os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>131072:raise Denied('The team connection file must be a private regular file with one link.',code='team_connection_invalid')
            raw=source.read(131073)
            if len(raw)>131072:raise Denied('The team connection file is too large.',code='team_connection_invalid')
    except OSError:raise Denied('The private team connection file is unavailable.',code='team_connection_invalid')
    from gateway import decode_json
    data=decode_json(raw)
    if not isinstance(data, dict): raise Denied('Invalid team connection file.', code='team_connection_invalid')
    return data


def validate(config):
    required = {'version', 'coordinator_id', 'member_id', 'endpoint', 'token'}
    if not required <= set(config) or set(config) - required - {'ssh', 'remote_port', 'identity_file','ssh_port','ssh_host_key','known_hosts','policy','policy_digest'}:
        raise Denied('Unsupported team connection fields.', code='team_connection_invalid')
    if type(config['version']) is not int or config['version'] != 1 or not all(isinstance(config[k], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', config[k]) for k in ('coordinator_id', 'member_id')):
        raise Denied('Invalid coordinator or member identity.', code='team_connection_invalid')
    if not isinstance(config['token'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,256}', config['token']):
        raise Denied('Invalid private member credential.', code='team_connection_invalid')
    match = re.fullmatch(r'http://127\.0\.0\.1:([0-9]{1,5})', config['endpoint']) if isinstance(config['endpoint'], str) else None
    if not match or not 1024 <= int(match[1]) <= 65535:
        raise Denied('Use a loopback endpoint; remote connections require the managed SSH tunnel.', code='team_connection_invalid')
    if ('policy' in config)!=('policy_digest' in config):raise Denied('Incomplete shared policy binding.',code='team_connection_invalid')
    if 'policy' in config:
        try:p=validate_policy(config['policy'])
        except PolicyError:raise Denied('Invalid coordinator model and quota policy.',code='team_connection_invalid') from None
        if config['policy_digest']!=policy_digest(p):raise Denied('The invitation policy digest differs.',code='team_identity_changed')
    if 'ssh' in config:
        if not {'remote_port','identity_file','ssh_port','ssh_host_key','known_hosts'}<=set(config):
            raise Denied('The managed SSH connection needs its dedicated private identity, pinned host key and private known-hosts file. Host SSH defaults are never inherited.',code='team_connection_invalid')
        # Treat destinations as data, never a shell fragment or SSH option.
        destination=config['ssh']
        ssh_destination(destination)
        if type(config.get('remote_port')) is not int or not 1024 <= config['remote_port'] <= 65535:
            raise Denied('Invalid coordinator SSH destination port.', code='team_connection_invalid')
        private_file(config['identity_file'])
        if 'ssh_port' in config and (type(config['ssh_port']) is not int or not 1024<=config['ssh_port']<=65535):raise Denied('Invalid SSH tunnel port.',code='team_connection_invalid')
        if 'ssh_host_key' in config:
            host_key(config['ssh_host_key'])
            known=private_file(config['known_hosts'])
            expected='['+config['ssh'].split('@',1)[1]+']:'+str(config.get('ssh_port',22))+' '+config['ssh_host_key']+'\n'
            if known.read_text()!=expected:raise Denied('The pinned team SSH host key changed.',code='team_identity_changed')
    elif set(config)&{'remote_port','identity_file','ssh_port','ssh_host_key','known_hosts'}:
        raise Denied('SSH options require an SSH destination.', code='team_connection_invalid')
    return int(match[1])


def ssh_destination(destination):
    if not isinstance(destination,str) or destination.count('@')!=1:raise Denied('Use an explicit SSH destination such as user@host.',code='team_connection_invalid')
    username,hostname=destination.split('@')
    try:address=ipaddress.ip_address(hostname)
    except ValueError:address=None
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}',username) or address is None and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',hostname):
        raise Denied('Use an explicit SSH destination such as user@host.',code='team_connection_invalid')


def private_file(filename):
    if not isinstance(filename,str) or not Path(filename).is_absolute():raise Denied('Choose a private absolute SSH file path.',code='team_connection_invalid')
    path=Path(filename)
    try:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077:
            raise OSError()
    except OSError:raise Denied('The dedicated SSH identity and host-key files must be owner-only regular files with one link, outside the workspace.',code='team_connection_invalid') from None
    return path


def host_key(value):
    if not isinstance(value,str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]{40,160}',value):raise Denied('Invalid pinned SSH host key.',code='team_connection_invalid')
    try:raw=base64.b64decode(value.split()[1],validate=True)
    except ValueError:raise Denied('Invalid pinned SSH host key.',code='team_connection_invalid')
    if len(raw)!=51 or raw[:15]!=b'\x00\x00\x00\x0bssh-ed25519' or raw[15:19]!=b'\x00\x00\x00\x20' or value.split()[1]!=base64.b64encode(raw).decode():raise Denied('Invalid pinned SSH host key.',code='team_connection_invalid')
    return value


class Connection:
    """One owned, host-pinned tunnel per operation. Never reuse a busy listener."""
    def __init__(self, config, *, control=None):
        self.config, self.port, self.child = config, validate(config), None
        self.control_directory=None;self.control_path=None
        self.control=control

    def __enter__(self):
        try:
            if self.control:self.control.check()
            return self._enter()
        except BaseException:
            self.__exit__()
            raise

    def _enter(self):
        if 'ssh' not in self.config: return self
        # The stored endpoint is a preference, never proof of an existing tunnel.
        # Separate operations choose separate loopback ports to avoid conflicts
        # between inference, notices and an external usage command.
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));self.port=probe.getsockname()[1]
        self.control_directory=tempfile.TemporaryDirectory(prefix='cah-',dir='/private/tmp' if Path('/private/tmp').is_dir() else '/tmp')
        os.chmod(self.control_directory.name,0o700)
        self.control_path=str(Path(self.control_directory.name)/'control')
        args = ['/usr/bin/ssh', '-F', '/dev/null', '-N', '-T',
                '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no','-o','IdentityAgent=none','-o','AddKeysToAgent=no',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'ControlMaster=yes','-o','ControlPersist=no',
                '-S',self.control_path,'-o', 'ConnectTimeout=8',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                '-L', f"127.0.0.1:{self.port}:127.0.0.1:{self.config['remote_port']}"]
        if 'ssh_port' in self.config:args+=['-p',str(self.config['ssh_port'])]
        if 'ssh_host_key' in self.config:
            args+=['-o','UserKnownHostsFile='+json.dumps(self.config['known_hosts'],ensure_ascii=False),'-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no']
        if self.config.get('identity_file'): args += ['-o', 'IdentitiesOnly=yes', '-i', self.config['identity_file']]
        args += [self.config['ssh']]
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'}
        if self.control:self.control.check()
        self.child = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, start_new_session=True,umask=0o077)
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            if self.control:self.control.check()
            if self.child.poll() is not None: break
            if self._owned_tunnel():return self
            time.sleep(.05)
        raise Denied('The encrypted team connection could not start. Check SSH access and the saved host key in your own terminal. No local or subscription fallback was used.', code='team_unavailable', status=503)

    def __exit__(self, *_):
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try: self.child.wait(timeout=3)
            except subprocess.TimeoutExpired: self.child.kill(); self.child.wait(timeout=3)
        if self.control_directory is not None:
            self.control_directory.cleanup();self.control_directory=None

    def _owned_tunnel(self):
        if self.child is None or self.child.poll() is not None or not self.control_path:return False
        path=Path(self.control_path)
        try:
            info=path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:return False
            result=subprocess.run(['/usr/bin/ssh','-F','/dev/null','-S',self.control_path,'-O','check',self.config['ssh']],
                env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1)
            return result.returncode==0 and result.stderr.strip()==('Master running (pid='+str(self.child.pid)+')').encode() and self.child.poll() is None
        except (OSError,subprocess.TimeoutExpired):return False

    def request(self, method, route, body=None, *, operation_id=None, control=None):
        if 'ssh' in self.config and not self._owned_tunnel():
            raise Denied('The owned encrypted team connection is unavailable. No credential was sent to another loopback listener.',code='team_unavailable',status=503)
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        if control: control.track(conn)
        headers = {'Authorization':'Bearer '+self.config['token'], 'Content-Type':'application/json',
                   'Host':'127.0.0.1:'+str(self.config.get('remote_port',self.port))}
        if operation_id: headers['Idempotency-Key'] = operation_id
        try:
            if control: control.check()
            conn.request(method, route, body=None if body is None else canonical(body), headers=headers)
            conn._api_socket = conn.sock
            if conn.sock: conn.sock.settimeout(max(120,control.phase_timeout) if control else 120)
            return conn, conn.getresponse()
        except (OSError, http.client.HTTPException):
            conn.close()
            if control: control.check()
            raise Denied('The team coordinator is unavailable. Requests stop here; no local quota, provider, or subscription fallback is used. A sent request may still hold its reservation.', code='team_unavailable', status=503)

    def json(self, method, route, body=None, *, control=None):
        conn, response = self.request(method, route, body, control=control)
        try:
            data = response.read(65537)
            if len(data) > 65536: raise ValueError()
            value = json.loads(data)
            if response.status != 200: raise remote_error(value, response.status)
            return value
        except (ValueError, TypeError):
            raise Denied('The team coordinator returned an invalid response. No fallback was used.', code='team_protocol_error', status=502)
        finally: conn.close()

    def identity(self, control=None):
        identity = self.json('GET', '/identity', control=control)
        if not isinstance(identity, dict) or identity.get('service') != 'codex-api-team' or type(identity.get('version')) is not int or identity.get('version')!=1 or any(not hmac.compare_digest(str(identity.get(k,'')), self.config[k]) for k in ('coordinator_id','member_id')):
            raise Denied('The team coordinator identity does not match the approved invitation. Connection stopped.', code='team_identity_changed')
        if 'policy_digest' in self.config and identity.get('policy_digest')!=self.config['policy_digest']:raise Denied('The coordinator policy differs from the reviewed invitation. Requests are stopped; review a refreshed invitation.',code='team_policy_changed')
        return identity


def remote_error(value, status):
    error = value.get('error', {}) if isinstance(value,dict) else {}
    code, message = error.get('code'), error.get('message')
    if not isinstance(code,str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,96}',code): code='team_request_rejected'
    if not isinstance(message,str) or len(message)>2000 or any(ord(c)<32 for c in message):
        message='The team coordinator rejected the request. Check your membership and remaining quota.'
    return Denied(message, code=code, status=status if 400<=status<=599 else 502)


class RemoteBroker:
    def __init__(self, root):
        self.root = Path(root)
        self.config = private_json(self.root/'team-client.json')
        validate(self.config)
        self.admission = threading.Lock()
        self.clock = time.time
        self.policy=load_policy(self.root)
        self.workspace_guard = lambda: None
        from settings import ROOT
        if self.root == ROOT:
            from workspace_policy import check_workspace
            self.workspace_guard = check_workspace

    def quota(self):
        with Connection(self.config) as conn:
            conn.identity()
            value = conn.json('GET', '/v1/quota')
        pools = value.get('daily_pools',{}) if isinstance(value,dict) else {}
        if set(pools)!=set(self.policy['pools']):raise Denied('Coordinator quota pools differ from the approved policy.',code='team_policy_changed')
        if 'policy_digest' in self.config and value.get('policy_digest')!=self.config['policy_digest']:raise Denied('Coordinator quota policy changed.',code='team_policy_changed')
        for group in self.policy['pools']:
            row = pools.get(group,{})
            if any(type(row.get(k)) is not int for k in ('remaining','limit')) or not 0<=row['remaining']<=row['limit']<=policy_limits(self.policy)[group]:
                raise Denied('Shared quota could not be verified. No cached balance is used.', code='team_protocol_error')
        value['usage_lines'] = usage_lines(self.policy,pools)
        value['shared'] = True
        return value

    def notices(self):
        with Connection(self.config) as conn:
            conn.identity()
            return conn.json('POST', '/v1/notices/claim', {})

    def request_more(self,payload):
        if not isinstance(payload,dict) or set(payload)!={'group','amount','request_id'} or payload['group'] not in self.policy['pools'] or type(payload['amount']) is not int or not 0<payload['amount']<=policy_limits(self.policy)[payload['group']] or not isinstance(payload['request_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,80}',payload['request_id']):
            raise Denied('Choose group A or B and a positive token amount.',code='team_request_invalid')
        with Connection(self.config) as conn:
            conn.identity()
            return conn.json('POST','/v1/quota/request',payload)

    def search(self, *_args, **_kwargs):
        raise Denied('Search providers are disabled in shared mode until an independently budgeted adapter is approved.', code='provider_disabled')

    def openai(self, payload, send_headers, send_chunk, cancelled=lambda:False, *, operation_id=None, operation_namespace='local'):
        normalized = normalize(payload, output_cap=self.policy['defaults']['output_token_cap'],policy=self.policy)
        self.workspace_guard()
        operation = operation_id or uuid.uuid4().hex
        with RequestControl(cancelled, lambda:(self.root/'paused').exists(),total=self.policy['defaults']['request_deadline_seconds']) as control:
            with Connection(self.config,control=control) as remote:
                remote.identity(control)
                control.check(); self.workspace_guard()
                conn, response = control.call(lambda:remote.request('POST','/v1/responses',normalized,operation_id=operation,control=control), 'team_response_headers',900 if self.policy['defaults']['service_tier']=='flex' else 120,returns_connection=True)
                try:
                    if response.status != 200:
                        raw = control.call(lambda:response.read(65537),'team_error',30)
                        if len(raw)>65536: raise Denied('Invalid team response.',code='team_protocol_error')
                        raise remote_error(json.loads(raw),response.status)
                    content_type = response.getheader('Content-Type','').split(';')[0]
                    if content_type not in {'application/json','text/event-stream'}:
                        raise Denied('Unexpected team response format.',code='team_protocol_error')
                    send_headers(content_type)
                    control.begin('team_response_stream',900 if self.policy['defaults']['service_tier']=='flex' else 120)
                    total = 0
                    while True:
                        control.check()
                        # read1 forwards partial SSE promptly; read(n) can wait for n bytes.
                        chunk = response.read1(65536)
                        control.touch()
                        if not chunk: break
                        total += len(chunk)
                        if total > 16_000_000: raise Denied('Team response size exceeded.',code='team_protocol_error')
                        send_chunk(chunk)
                except (OSError,http.client.HTTPException):
                    control.check()
                    raise Denied('The team response was interrupted. Its reservation remains authoritative at the coordinator; no retry was made.',code='team_connection_interrupted',status=503)
                finally: conn.close()


def command(root, args):
    root = Path(root)
    parser = argparse.ArgumentParser(prog='codex-api team join')
    parser.add_argument('--invite',type=Path,required=True)
    parser.add_argument('--ssh')
    parser.add_argument('--local-port',type=int,default=49201)
    parser.add_argument('--identity-file',type=Path)
    parser.add_argument('--remote-port',type=int)
    parser.add_argument('--ssh-port',type=int)
    parser.add_argument('--local',action='store_true',help='Owner on the same Mac: use the coordinator loopback directly.')
    parser.add_argument('--replace-member-credential',action='store_true')
    parser.add_argument('--inspect',action='store_true',help='Show only the invitation policy; do not connect or install.')
    parser.add_argument('--reviewed-policy-digest')
    parsed = parser.parse_args(args)
    with (root/'session.lock').open('a+b') as lease:
        try: fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Denied('Exit the API session before joining a team.')
        if (root/'gateway-process.json').exists(): raise Denied('Stop the API gateway before joining a team.')
        previous=private_json(root/'team-client.json') if (root/'team-client.json').exists() else None
        if previous and not parsed.replace_member_credential: raise Denied('This installation already has a team binding. Use --replace-member-credential only for a renewed invitation from the same coordinator and member.')
        profile = json.loads((root/'verification.json').read_text()).get('openai',{})
        if profile.get('account_configured'):
            raise Denied('Keep this personal account binding intact. Install a separate launcher for shared mode; no personal usage was reset.')
        config = private_json(parsed.invite)
        tunnel=config.pop('ssh',None) if isinstance(config.get('ssh'),dict) else None
        remote_port = validate(config)
        if parsed.inspect:
            p=config.get('policy',legacy());print(json.dumps({'policy':p,'digest':policy_digest(p),'effective_daily_limits':policy_limits(p)},indent=2));return
        if 'policy_digest' in config and parsed.reviewed_policy_digest!=config['policy_digest']:raise Denied('Review the invitation policy with --inspect, then provide --reviewed-policy-digest. No connection was installed.',code='policy_review_required')
        if previous and any(previous[k]!=config[k] for k in ('coordinator_id','member_id')):
            raise Denied('A renewed invitation must preserve the coordinator and member identity; use a separate installation for another account.')
        if tunnel is not None and not parsed.local:
            if set(tunnel)!={'host','port','user','host_key','remote_port'}:raise Denied('Invalid tunnel invitation.',code='team_connection_invalid')
            pinned=host_key(tunnel['host_key'])
            destination=parsed.ssh or str(tunnel['user'])+'@'+str(tunnel['host'])
            identity=(parsed.identity_file or root/'team-tunnel.key').expanduser().absolute()
            workspace=Path(json.loads((root/'settings.json').read_text())['workspace'])
            if identity.is_relative_to(workspace):raise Denied('The SSH identity must be outside the shared project.')
            ssh_destination(destination)
            config.update(ssh=destination,remote_port=parsed.remote_port if parsed.remote_port is not None else tunnel['remote_port'],ssh_port=parsed.ssh_port if parsed.ssh_port is not None else tunnel['port'],
                          endpoint='http://127.0.0.1:'+str(parsed.local_port),identity_file=str(identity),ssh_host_key=pinned)
            # No incomplete SSH configuration is ever accepted as a connection.
            # Validate all file and port fields after creating the private pin.
            expected='['+destination.split('@',1)[1]+']:'+str(config['ssh_port'])+' '+pinned+'\n'
            known=root/('team-known-hosts-'+hashlib.sha256(expected.encode()).hexdigest()[:16])
            if known.is_symlink():raise Denied('The pinned host key file must not be a symlink.')
            if known.exists():
                if known.read_text()!=expected or known.stat().st_mode&0o077:raise Denied('The pinned host key file changed.',code='team_identity_changed')
            else:
                fd=os.open(known,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as out:out.write(expected)
            config['known_hosts']=str(known)
        elif parsed.ssh:
            raise Denied('Use an invitation containing the managed tunnel host key. Ordinary remote shell access is not a team boundary.',code='team_connection_invalid')
        elif parsed.local:
            if parsed.identity_file or parsed.remote_port or parsed.ssh_port:raise Denied('--local cannot be combined with SSH options.')
        elif previous and 'ssh' in previous:
            config.update({k:previous[k] for k in ('ssh','remote_port','identity_file','endpoint','ssh_port','ssh_host_key','known_hosts') if k in previous})
        elif parsed.identity_file or parsed.remote_port or parsed.ssh_port:
            raise Denied('SSH options require a managed tunnel invitation.')
        validate(config)
        with Connection(config) as remote: remote.identity()
        atomic_json(root/'team-client.json',config)
        from configuration import refresh_guest
        refresh_guest(root)
    print('Team connection verified. The member credential stays outside the sandbox. Daily startup and usage use the approved coordinator policy.')
    print('The coordinator handles prompts and responses. Its owner must be trusted and the Mac must remain online.')


def keygen(root):
    root=Path(root)
    key=root/'team-tunnel.key'
    if key.exists() or key.is_symlink() or key.with_suffix('.key.pub').exists() or key.with_suffix('.key.pub').is_symlink():
        raise Denied('A dedicated tunnel key already exists. It was not overwritten; share only its .pub file with the coordinator owner.')
    with (root/'session.lock').open('a+b') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('Exit the API session before preparing its tunnel identity.')
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'}
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','codex-api-tunnel','-f',str(key)],
                       env=env,stdin=subprocess.DEVNULL,capture_output=True,check=True)
        key.chmod(0o600);Path(str(key)+'.pub').chmod(0o600)
    print('Tunnel identity created. Share only this public file with the coordinator owner: '+str(key)+'.pub')
    print('The private key stays on this Mac, outside the sandbox. No subscription, GitHub, or existing SSH identity was imported.')
