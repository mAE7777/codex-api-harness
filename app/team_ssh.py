"""A private, unprivileged OpenSSH listener that permits one TCP destination.

No system Remote Login, user SSH configuration, login key, or SSH agent is used.
The listener permits forwarding to the coordinator and has zero session slots.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import struct
import subprocess
import time

from guard import Denied, atomic_json

SSH_PORT=49202


def parse_public_key(value):
    if not isinstance(value,str) or len(value)>4096 or len(value.strip().splitlines())!=1:
        raise Denied('Use one OpenSSH Ed25519 public key, without authorized_keys options.',code='team_ssh_key_invalid')
    parts=value.strip().split()
    if len(parts)<2 or parts[0]!='ssh-ed25519':
        raise Denied('Only a plain Ed25519 public key is supported. Never provide a private key.',code='team_ssh_key_invalid')
    try:
        raw=base64.b64decode(parts[1],validate=True)
        length=struct.unpack('>I',raw[:4])[0]
        algorithm=raw[4:4+length]
        offset=4+length
        key_length=struct.unpack('>I',raw[offset:offset+4])[0]
        key=raw[offset+4:]
        if algorithm!=b'ssh-ed25519' or key_length!=32 or len(key)!=32 or parts[1]!=base64.b64encode(raw).decode():raise ValueError()
    except (ValueError,struct.error):
        raise Denied('The Ed25519 public key is malformed.',code='team_ssh_key_invalid') from None
    return 'ssh-ed25519 '+parts[1]


def fingerprint(value):
    key=parse_public_key(value)
    return 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(key.split()[1])).digest()).decode().rstrip('=')


def _directory(path,create=False):
    path=Path(path)
    if path.is_symlink():raise Denied('The private SSH directory must not be a symlink.',code='team_ssh_state_unsafe')
    if create:path.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:raise Denied('The SSH directory must be owner-only (0700).',code='team_ssh_state_unsafe')
    return path


def _file(path,*,public=False):
    info=Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or (not public and info.st_mode & 0o077):
        raise Denied('Unexpected SSH key/configuration file permissions.',code='team_ssh_state_unsafe')
    return Path(path)


def _binary(name):
    candidate='/usr/sbin/sshd' if name=='sshd' else '/usr/bin/ssh-keygen'
    if not Path(candidate).is_file() or not os.access(candidate,os.X_OK):raise Denied('OpenSSH '+name+' is unavailable. Install the system OpenSSH tools before enabling team sharing.',code='team_ssh_unavailable')
    return str(Path(candidate).resolve())


def _listen(value):
    try:address=ipaddress.ip_address(value)
    except ValueError:raise Denied('Choose a literal local/private IP for the dedicated SSH listener.',code='team_ssh_address_invalid') from None
    private_networks=('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10','::1/128','fc00::/7')
    if address.is_unspecified or address.is_multicast or not any(address in ipaddress.ip_network(network) for network in private_networks if address.version==ipaddress.ip_network(network).version):
        raise Denied('The SSH listener requires loopback, a private LAN address, or a private VPN address. Public/wildcard listeners are disabled.',code='team_ssh_address_invalid')
    return str(address)


def _port(value):
    if type(value) is not int or not 1024<=value<=65535:raise Denied('Choose SSH/coordinator ports from 1024 to 65535.',code='team_ssh_port_invalid')
    return value


def _path(path):
    value=str(Path(path).absolute())
    if any(c in value for c in ('\n','\r','\x00','"','\\','%','$')):raise Denied('Use a private SSH state path without quotes, backslashes, control characters, percent or dollar signs.',code='team_ssh_path_invalid')
    return '"'+value+'"'


def _read_settings(root):
    import json
    path=_file(_directory(Path(root)/'ssh')/'settings.json')
    if path.stat().st_size>8192:raise Denied('SSH settings are too large.',code='team_ssh_state_unsafe')
    settings=json.loads(path.read_text())
    expected={'version','host','port','user','host_key','remote_port'}
    if not isinstance(settings,dict) or set(settings)!=expected or type(settings['version']) is not int or settings['version']!=1:raise Denied('Unsupported private SSH settings.',code='team_ssh_state_unsafe')
    settings['host']=_listen(settings['host']);_port(settings['port']);_port(settings['remote_port'])
    if settings['user']!=pwd.getpwuid(os.getuid()).pw_name:raise Denied('The dedicated SSH listener belongs to another operating-system user.',code='team_ssh_state_unsafe')
    settings['host_key']=parse_public_key(settings['host_key'])
    return settings


def invite_metadata(root):
    path=Path(root)/'ssh/settings.json'
    if not path.exists() and not path.is_symlink():return None
    settings=_read_settings(root)
    return {key:value for key,value in settings.items() if key!='version'}


def _write_text(path,content,mode=0o600):
    path=Path(path)
    if path.exists() or path.is_symlink():_file(path)
    temporary=path.with_name(path.name+'.new-'+os.urandom(8).hex())
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(descriptor,'w') as out:out.write(content);out.flush();os.fsync(out.fileno())
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if temporary.exists():temporary.unlink()


def render_config(root,settings):
    directory=_directory(Path(root)/'ssh')
    host=_listen(settings['host']);port=_port(settings['port']);destination=_port(settings['remote_port'])
    username=settings['user']
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',username):raise Denied('The local short account name cannot be used for this dedicated listener.',code='team_ssh_user_invalid')
    return '\n'.join([
        'AddressFamily '+('inet6' if ':' in host else 'inet'),
        'ListenAddress '+host,'Port '+str(port),
        'HostKey '+_path(directory/'host_key'),
        'PidFile '+_path(directory/'sshd.pid'),
        'AuthorizedKeysFile '+_path(directory/'authorized_keys'),
        'AuthorizedKeysCommand none','AuthorizedPrincipalsFile none','TrustedUserCAKeys none',
        'AllowUsers '+username,'AuthenticationMethods publickey','PubkeyAuthentication yes',
        'PubkeyAcceptedAlgorithms ssh-ed25519','HostKeyAlgorithms ssh-ed25519',
        'PasswordAuthentication no','KbdInteractiveAuthentication no','UsePAM no',
        'HostbasedAuthentication no','GSSAPIAuthentication no','PermitEmptyPasswords no','PermitRootLogin no',
        'StrictModes yes','MaxSessions 0','PermitTTY no','PermitUserRC no','PermitUserEnvironment no',
        'AllowAgentForwarding no','X11Forwarding no','PermitTunnel no',
        'AllowTcpForwarding local','AllowStreamLocalForwarding no',
        'PermitOpen 127.0.0.1:'+str(destination),'PermitListen none','GatewayPorts no',
        'ForceCommand /usr/bin/false','UseDNS no','LoginGraceTime 15','MaxAuthTries 3','MaxStartups 4:30:12',
        'ClientAliveInterval 30','ClientAliveCountMax 3','PrintMotd no','PrintLastLog no','LogLevel ERROR','',
    ])


def _check_config(root):
    path=_file(Path(root)/'ssh/sshd_config')
    result=subprocess.run([_binary('sshd'),'-t','-f',str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    if result.returncode:raise Denied('The dedicated OpenSSH configuration did not pass validation. No listener was started and no system SSH configuration was changed.',code='team_ssh_configuration_failed')


def render_authorized_keys(team):
    directory=_directory(team.root/'ssh',create=True)
    with team.mutex:
        keys=team.ledger.db.execute('SELECT k.public_key FROM team_tunnel_keys k JOIN team_members m ON k.member=m.id WHERE m.active=1 ORDER BY k.fingerprint').fetchall()
        destination=invite_metadata(team.root)
        # Global sshd policy also restricts the one destination. A key cannot
        # accidentally authorize sessions if a later deployment changes defaults.
        options='restrict,port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc'
        if destination:options+=',permitopen="127.0.0.1:'+str(destination['remote_port'])+'"'
        content=''.join(options+' '+parse_public_key(key)+'\n' for (key,) in keys)
        _write_text(directory/'authorized_keys',content)


def configure(team,*,listen='127.0.0.1',ssh_port=SSH_PORT,coordinator_port=49200):
    if team.running:raise Denied('Stop the team coordinator before changing its SSH listener. Member public keys can be registered while it runs.',code='team_stop_required')
    if os.getuid()==0:raise Denied('Run the harness as a normal user. This listener does not permit root login.',code='team_ssh_user_invalid')
    host=_listen(listen);_port(ssh_port);_port(coordinator_port)
    if ssh_port==coordinator_port:raise Denied('SSH and coordinator ports must differ.',code='team_ssh_port_invalid')
    username=pwd.getpwuid(os.getuid()).pw_name
    directory=_directory(team.root/'ssh',create=True);host_key=directory/'host_key'
    if host_key.exists() or host_key.is_symlink():_file(host_key)
    else:
        result=subprocess.run([_binary('ssh-keygen'),'-q','-t','ed25519','-N','','-f',str(host_key)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
        if result.returncode:raise Denied('Unable to create the private team SSH host key.',code='team_ssh_keygen_failed')
    result=subprocess.run([_binary('ssh-keygen'),'-y','-f',str(host_key)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    if result.returncode:raise Denied('Unable to verify the private team SSH host key.',code='team_ssh_key_invalid')
    public_key=parse_public_key(result.stdout.decode())
    settings={'version':1,'host':host,'port':ssh_port,'remote_port':coordinator_port,'user':username,'host_key':public_key}
    atomic_json(directory/'settings.json',settings)
    _write_text(directory/'sshd_config',render_config(team.root,settings))
    render_authorized_keys(team);_check_config(team.root)
    return {'ssh':invite_metadata(team.root),'configured':True,'system_ssh_unchanged':True,'listener_started':False}


def register_key(team,member,public_key_file):
    path=Path(public_key_file)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>4096:raise Denied('Use a small regular Ed25519 public key file.',code='team_ssh_key_invalid')
        try:key=parse_public_key(source.read(4097).decode('ascii'))
        except UnicodeError:raise Denied('The public key must be plain OpenSSH text.',code='team_ssh_key_invalid') from None
    digest=fingerprint(key)
    with team.mutex,team.ledger.transaction():
        team._member(member)
        existing=team.ledger.db.execute('SELECT member FROM team_tunnel_keys WHERE fingerprint=?',(digest,)).fetchone()
        if existing and existing[0]!=member:raise Denied('A tunnel public key is already bound to another member. Generate a distinct key for each member.',code='team_ssh_key_conflict')
        team.ledger.db.execute('INSERT OR IGNORE INTO team_tunnel_keys VALUES (?,?,?)',(member,digest,key))
    render_authorized_keys(team)
    return {'member_id':member,'fingerprint':digest,'registered':True,'private_key_uploaded':False}


class ManagedSSHD:
    def __init__(self,process):self.process=process
    def stop(self):
        process=self.process
        # This handle was created with start_new_session; never trust a PID file
        # or kill an existing system/user SSH daemon.
        if process.poll() is None:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                # A native daemon can leave the original process group. The
                # retained Popen handle still identifies our own direct child;
                # never look up or kill an unrelated daemon from a PID file.
                process.kill()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    raise Denied('The dedicated SSH child has not confirmed shutdown. Shared admission is stopped; retry stopping this coordinator. No system SSH service was changed.',code='team_ssh_stop_unconfirmed') from None


def start(team,coordinator_port):
    if not (team.root/'ssh/settings.json').exists():return None
    settings=_read_settings(team.root)
    if settings['remote_port']!=coordinator_port:raise Denied('The coordinator port differs from the configured tunnel destination. Stop it and run team share with matching ports.',code='team_ssh_port_invalid')
    directory=_directory(team.root/'ssh')
    result=subprocess.run([_binary('ssh-keygen'),'-y','-f',str(_file(directory/'host_key'))],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    if result.returncode or parse_public_key(result.stdout.decode())!=settings['host_key']:raise Denied('The dedicated SSH host key changed. Existing invites were not silently trusted.',code='team_ssh_host_key_changed')
    _write_text(directory/'sshd_config',render_config(team.root,settings));render_authorized_keys(team);_check_config(team.root)
    process=subprocess.Popen([_binary('sshd'),'-D','-e','-f',str(directory/'sshd_config')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C'})
    daemon=ManagedSSHD(process)
    try:
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if process.poll() is not None:break
            try:
                with socket.create_connection((settings['host'],settings['port']),timeout=.15) as connection:
                    connection.settimeout(.15);banner=connection.recv(256)
                if banner.startswith(b'SSH-') and process.poll() is None:return daemon
            except OSError:pass
            time.sleep(.05)
    except BaseException:daemon.stop();raise
    daemon.stop()
    raise Denied('The dedicated SSH listener could not start. Check that the selected private IP belongs to this Mac and the SSH port is available. System Remote Login was not changed.',code='team_ssh_start_failed')
