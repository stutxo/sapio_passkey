#!/usr/bin/env python3
"""Install the HTTPS API on an existing Amazon Linux 2023 signer parent.

No domain, new compute instance, enclave restart, setup call or root rotation.
The public IPv4 address must already belong to this host. Security-group and
host-firewall ingress must allow TCP 80 (ACME) and 443 (API). The HTTP listener
exists only during certificate validation; wallet traffic always uses HTTPS.

Run from a checked-out sapio_passkey release on the existing parent:
  sudo python3 deploy/install-ip-gateway.py --ip 13.216.90.100 \
    --origin https://stutxo.github.io

--stage-dir writes the service files and gateway only, without installing
packages, contacting a CA, reading keys or changing services. Production
installation uses Certbot 5.8.0 and verifies staging issuance before requesting
a trusted short-lived IP certificate. Renewal runs twice daily and restarts
only sapio-passkey-gateway.service after successful renewal. Inspect failures
with journalctl -u sapio-passkey-renew.service. TLS/ACME private keys stay on
the parent in /etc/sapio-passkey; they are never printed or copied to Pages.
"""

import argparse
import http.client
import ipaddress
import os
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
APP = Path('/opt/sapio-passkey')
CONFIG = Path('/etc/sapio-passkey/letsencrypt')
WORK = Path('/var/lib/sapio-passkey-acme')
LOGS = Path('/var/log/sapio-passkey-acme')
UNITS = Path('/etc/systemd/system')
PYTHON = '/usr/bin/python3.11'
CERTBOT = APP / 'certbot/bin/certbot'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
       'HOME': '/root', 'PYTHONDONTWRITEBYTECODE': '1'}


def command(*arguments):
    subprocess.run([str(value) for value in arguments], check=True,
                   stdin=subprocess.DEVNULL, env=ENV, timeout=300)


def safe_directory(path, mode=0o755):
    if path == path.parent:
        return
    safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f'unsafe installation directory: {path}')
    else:
        path.mkdir(mode=mode)


def install_file(path, data):
    safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError(f'unsafe installation file: {path}')
    descriptor, temporary = tempfile.mkstemp(prefix='.gateway-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def service_files(ip, origin):
    common = f'--config-dir {CONFIG} --work-dir {WORK} --logs-dir {LOGS} --cert-name {ip}'
    return {
        'sapio-passkey-gateway.service': f'''[Unit]
Description=Sapio passkey bounded HTTPS gateway
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
DynamicUser=yes
ExecStart={PYTHON} -I -B {APP}/server.py --api-url https://{ip} --origin {origin} --listen 0.0.0.0 --port 443 --tls-cert %d/fullchain.pem --tls-key %d/privkey.pem
LoadCredential=fullchain.pem:{CONFIG}/live/{ip}/fullchain.pem
LoadCredential=privkey.pem:{CONFIG}/live/{ip}/privkey.pem
Restart=on-failure
RestartSec=3
TimeoutStopSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
InaccessiblePaths=-/etc/sapio-passkey -/opt/sapio-tee
MemoryMax=192M
TasksMax=32
LimitNOFILE=128
LimitCORE=0
CPUQuota=100%

[Install]
WantedBy=multi-user.target
''',
        'sapio-passkey-renew.service': f'''[Unit]
Description=Renew the Sapio passkey short-lived IP certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart={CERTBOT} renew --non-interactive {common} --deploy-hook "/usr/bin/systemctl try-restart sapio-passkey-gateway.service"
Environment=PYTHONDONTWRITEBYTECODE=1
TimeoutStartSec=300
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths={CONFIG} {WORK} {LOGS}
MemoryMax=256M
TasksMax=32
LimitNOFILE=128
LimitCORE=0
CPUQuota=100%
''',
        'sapio-passkey-renew.timer': '''[Unit]
Description=Check the Sapio passkey IP certificate twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=yes

[Install]
WantedBy=timers.target
''',
    }


def ready(ip, origin):
    connection = http.client.HTTPSConnection(ip, timeout=35)
    for attempt in range(20):
        try:
            transport = socket.create_connection(('127.0.0.1', 443), timeout=2)
            break
        except ConnectionRefusedError:
            if attempt == 19:
                raise
            time.sleep(0.25)
    transport.settimeout(35)
    connection.sock = ssl.create_default_context().wrap_socket(transport, server_hostname=ip)
    try:
        connection.request('GET', '/esplora/blocks/tip/height', headers={'Origin': origin})
        response = connection.getresponse()
        body = response.read(1025)
        if (response.status != 200 or response.getheader('Access-Control-Allow-Origin') != origin
                or not body.strip().isdigit() or len(body) > 1024):
            raise RuntimeError(f'HTTPS chain readiness failed: HTTP {response.status}')
        print(f'HTTPS and exact-origin CORS verified; indexer tip {body.decode().strip()}')
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ip', required=True, help='existing public Elastic IPv4 address')
    parser.add_argument('--origin', required=True, help='exact HTTPS Pages origin, without a path')
    parser.add_argument('--stage-dir', type=Path, help='stage public deployment files only; no host changes')
    args = parser.parse_args()
    ip = str(ipaddress.IPv4Address(args.ip))
    if ip != args.ip or not ipaddress.ip_address(ip).is_global:
        parser.error('--ip must be a canonical public IPv4 address')
    source = ROOT / 'gateway/server.py'
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 262144:
        parser.error('gateway source must be a regular release file below 256 KiB')
    runpy.run_path(str(source))['validate_origin'](args.origin, False)
    units = service_files(ip, args.origin)
    if args.stage_dir is not None:
        install_file(args.stage_dir / APP.relative_to('/') / 'server.py', source.read_bytes())
        for name, content in units.items():
            install_file(args.stage_dir / UNITS.relative_to('/') / name, content.encode())
        print(f'Staged public gateway and service files in {args.stage_dir}')
        return
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os.geteuid() != 0 or release.get('ID', '').strip('"') != 'amzn' or release.get('VERSION_ID', '').strip('"') != '2023':
        parser.error('installation requires root on the existing Amazon Linux 2023 parent')
    command('/usr/bin/dnf', 'install', '-y', 'python3.11', 'python3.11-pip')
    for directory in (APP, CONFIG, WORK, LOGS):
        safe_directory(directory, 0o700 if directory == CONFIG else 0o755)
    CONFIG.chmod(0o700)
    install_file(APP / 'server.py', source.read_bytes())
    if not CERTBOT.exists():
        command(PYTHON, '-m', 'venv', APP / 'certbot')
    command(APP / 'certbot/bin/python', '-m', 'pip', 'install', '--disable-pip-version-check',
            '--no-cache-dir', '--only-binary=:all:', 'certbot==5.8.0', 'acme==5.8.0')
    common = ['--config-dir', str(CONFIG), '--work-dir', str(WORK), '--logs-dir', str(LOGS), '--cert-name', ip]
    issue = [str(CERTBOT), 'certonly', '--non-interactive', '--agree-tos',
             '--register-unsafely-without-email', '--standalone', '--preferred-profile', 'shortlived',
             '--ip-address', ip, *common]
    command(*issue, '--dry-run')
    command(*issue, '--keep-until-expiring')
    for name, content in units.items():
        install_file(UNITS / name, content.encode())
    command('/usr/bin/systemctl', 'daemon-reload')
    command('/usr/bin/systemctl', 'enable', 'sapio-passkey-gateway.service')
    command('/usr/bin/systemctl', 'restart', 'sapio-passkey-gateway.service')
    command('/usr/bin/systemctl', 'enable', '--now', 'sapio-passkey-renew.timer')
    command('/usr/bin/systemctl', 'is-active', '--quiet', 'sapio-passkey-gateway.service', 'sapio-passkey-renew.timer')
    command(CERTBOT, 'renew', '--non-interactive', *common, '--dry-run', '--run-deploy-hooks',
            '--deploy-hook', '/usr/bin/systemctl try-restart sapio-passkey-gateway.service')
    ready(ip, args.origin)
    print(f'Gateway installed at https://{ip}; certificate renewal and gateway reload verified.')
    print('Enclave, signer, KMS and wallet identity were not modified.')


if __name__ == '__main__':
    main()
