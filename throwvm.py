#!/usr/bin/env python3
"""Throwaway QEMU/KVM Ubuntu VMs reachable over SSH (stdlib only, no root needed).

Shared by the VM tests of several projects. Python: `sys.path.insert(0, '~/code/dotfiles/lib'); import throwvm`.
Bash: `eval "$(lib/throwvm.py up DIR --vm-dir ... --owner $$)"`, then `"${VM_SSH[@]}" cmd`, `lib/throwvm.py down DIR`.

- The Ubuntu cloud image is downloaded once (signature and checksum checked).
- The first VM of a kind (name, hostname, RAM, CPUs, disk size) boots the cloud image and runs cloud-init; then its
  disk and RAM are saved as a snapshot. Every later VM resumes that snapshot from a copy-on-write overlay and is
  reachable over SSH within seconds. `fresh=True` skips the snapshot (cloud-init boot, ~25 s).
- Each VM runs in its own `systemd-run --user --scope` unit with MemoryHigh/MemoryMax, so stopping it stops the
  whole group and its memory and CPU use is read from the cgroup.
- A VM only starts when free RAM allows (MemAvailable minus what running VMs may still grow into, minus a reserve);
  otherwise it waits. Starts are serialized by a lock file.
- The VM is stopped when its owner process exits (a guard process watches it), so no VM outlives a killed run.
- On failure `stop(failed=True)` keeps console.log, qemu.log and the guest journal; only the disk is deleted.
"""
import argparse, contextlib, ctypes, fcntl, functools, glob, hashlib, http.server, json, os, select, shlex, shutil, \
    signal, socket, subprocess, sys, threading, time

RELEASE, VERSION = 'resolute', '26.04'
IMG = f'ubuntu-{VERSION}-server-cloudimg-amd64.img'
URL = f'https://cloud-images.ubuntu.com/releases/{RELEASE}/release'
KEYRING = '/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg'
LAYOUT = 1               # bump when the QEMU command line or the snapshot preparation changes: old snapshots go stale
OVERHEAD_MB = 1024       # MemoryMax = guest RAM + this (QEMU itself, page cache of the disk files)
HIGH_MB = 512            # MemoryHigh = guest RAM + this: above it the kernel reclaims the scope's page cache first
RESERVE_MB = int(os.environ.get('THROWVM_RESERVE_MB', 4096))   # RAM always left free for the host


def log(msg):
    print(f'throwvm: {msg}', file=sys.stderr, flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def ensure_image(cache_dir):
    """Path of the verified cloud image in cache_dir, downloading it if missing or stale."""
    os.makedirs(cache_dir, exist_ok=True)
    run = functools.partial(subprocess.run, cwd=cache_dir, check=True)
    run(['curl', '-fsS', '--max-time', '60', '-O', f'{URL}/SHA256SUMS', '-O', f'{URL}/SHA256SUMS.gpg'])
    run(['gpgv', '--keyring', KEYRING, 'SHA256SUMS.gpg', 'SHA256SUMS'], capture_output=True)
    check = _sum_line(cache_dir)
    ok = subprocess.run(['sha256sum', '-c', '--status'], input=check, text=True, cwd=cache_dir).returncode == 0
    if not ok:
        run(['curl', '-fL', '--retry', '3', '--max-time', '1800', '-o', IMG, f'{URL}/{IMG}'])
        run(['sha256sum', '-c'], input=check, text=True)
    return os.path.join(cache_dir, IMG)


def _sum_line(cache_dir):
    line = next(l for l in open(os.path.join(cache_dir, 'SHA256SUMS')) if l.rstrip().endswith('*' + IMG))
    return line.replace('*', '')


# --- cgroup accounting and admission ------------------------------------------------------------------------------

def _systemctl(*args, timeout=30):
    return subprocess.run(['systemctl', '--user', *args], capture_output=True, text=True, timeout=timeout)


def _unit_props(units, props):
    """{unit: {prop: int or None}} read from systemd (the scope's cgroup)."""
    if not units:
        return {}
    out = _systemctl('show', '-p', 'Id,' + ','.join(props), '--', *units).stdout
    res = {}
    for block in out.strip().split('\n\n'):
        kv = dict(l.split('=', 1) for l in block.splitlines() if '=' in l)
        res[kv.get('Id')] = {p: int(kv[p]) if kv.get(p, '').isdigit() else None for p in props}
    return res


def running_scopes():
    out = _systemctl('list-units', '--plain', '--no-legend', '--state=running', 'throwvm-*.scope').stdout
    return [l.split()[0] for l in out.splitlines() if l.strip()]


def vm_usage():
    """Memory and CPU of every running throwvm scope, from its cgroup."""
    return _unit_props(running_scopes(), ['MemoryCurrent', 'MemoryPeak', 'MemoryMax', 'CPUUsageNSec'])


def mem_available_mb():
    for l in open('/proc/meminfo'):
        if l.startswith('MemAvailable:'):
            return int(l.split()[1]) // 1024
    raise RuntimeError('no MemAvailable in /proc/meminfo')


def headroom_mb(available_mb, usage, need_mb, reserve_mb=RESERVE_MB):
    """RAM left after a new VM of need_mb starts, counting what running VMs may still grow into. >= 0: may start."""
    committed = sum(max(0, (u['MemoryMax'] or 0) - (u['MemoryCurrent'] or 0)) for u in usage.values()) // 2**20
    return available_mb - committed - need_mb - reserve_mb


@contextlib.contextmanager
def admitted(vm_dir, need_mb, wait_s=1800):
    """Hold the start lock once need_mb of RAM is free for a new VM. The VM's scope must exist before release."""
    os.makedirs(vm_dir, exist_ok=True)
    with open(os.path.join(vm_dir, '.throwvm-start.lock'), 'w') as lock:
        end, said = time.time() + wait_s, 0.0
        while True:
            fcntl.flock(lock, fcntl.LOCK_EX)
            free = headroom_mb(mem_available_mb(), vm_usage(), need_mb)
            if free >= 0:
                break
            fcntl.flock(lock, fcntl.LOCK_UN)
            if time.time() > end:
                raise RuntimeError(f'not enough free RAM for a {need_mb} MiB VM after {wait_s} s ({-free} MiB short)')
            if time.time() - said > 30:
                log(f'waiting for RAM: {-free} MiB short of {need_mb} MiB + {RESERVE_MB} MiB reserve')
                said = time.time()
            time.sleep(2)
        yield


# --- QEMU -----------------------------------------------------------------------------------------------------------

class QMP:
    """Minimal QEMU machine protocol client (JSON lines over a unix socket)."""

    def __init__(self, path, timeout=30):
        end = time.time() + timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.settimeout(timeout)
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                self.sock.close()
                if time.time() > end:
                    raise
                time.sleep(0.1)
        self.f = self.sock.makefile('rwb')
        self.f.readline()                      # greeting
        self.cmd('qmp_capabilities')

    def cmd(self, name, **args):
        self.f.write(json.dumps({'execute': name, 'arguments': args}).encode() + b'\n')
        self.f.flush()
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError(f'QMP connection closed during {name}')
            msg = json.loads(line)
            if 'return' in msg:
                return msg['return']
            if 'error' in msg:
                raise RuntimeError(f'QMP {name}: {msg["error"].get("desc")}')

    def close(self):
        self.sock.close()


class VM:
    """One throwaway VM. Files live in workdir: disk overlay, logs, vm.json (so the CLI can find it again)."""

    def __init__(self, workdir, vm_dir, name='vm', mem_mb=3072, cpus=2, disk_gb=20, hostname='testbox',
                 owner=None, fresh=False):
        self.dir, self.vm_dir, self.name = os.path.abspath(workdir), vm_dir, name
        self.mem_mb, self.cpus, self.disk_gb, self.hostname, self.fresh = mem_mb, cpus, disk_gb, hostname, fresh
        self.owner = os.getpid() if owner is None else owner      # 0: nobody, the VM runs until stopped
        self.ssh_port = self.unit = self.key = self.proc = None

    # -- state shared with the CLI
    def _save(self):
        keys = ('vm_dir', 'name', 'mem_mb', 'cpus', 'disk_gb', 'hostname', 'ssh_port', 'unit', 'key')
        with open(os.path.join(self.dir, 'vm.json'), 'w') as f:
            json.dump({k: getattr(self, k) for k in keys}, f)

    @classmethod
    def load(cls, workdir):
        d = json.load(open(os.path.join(workdir, 'vm.json')))
        vm = cls(workdir, d['vm_dir'], d['name'], d['mem_mb'], d['cpus'], d['disk_gb'], d['hostname'], owner=0)
        vm.ssh_port, vm.unit, vm.key = d['ssh_port'], d['unit'], d['key']
        return vm

    def ssh_argv(self):
        return ['ssh', '-q', '-i', self.key, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8',
                '-p', str(self.ssh_port), 'tester@127.0.0.1']

    # -- boot
    def boot(self, timeout=300):
        """Start the VM (from the snapshot unless fresh) and wait until SSH works. Returns self."""
        os.makedirs(self.dir, exist_ok=True)
        image = ensure_image(os.path.join(self.vm_dir, 'images'))
        t0 = time.time()
        try:
            if self.fresh:
                self.key = os.path.join(self.dir, 'id_vm')
                _keygen(self.key)
                self._cold_boot(image, os.path.join(self.dir, 'disk.qcow2'), self.dir, timeout)
            else:
                snap = self._snapshot(image, timeout)
                self.key = os.path.join(snap, 'id_vm')
                _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', os.path.join(snap, 'disk.qcow2'),
                      os.path.join(self.dir, 'disk.qcow2')])
                self._start(os.path.join(self.dir, 'disk.qcow2'), self.dir, incoming=os.path.join(snap, 'state'))
                qmp = QMP(_qmp_path(self.dir))
                end = time.time() + timeout
                while (st := qmp.cmd('query-migrate').get('status')) != 'completed':   # loading the RAM state
                    if st in ('failed', 'cancelled') or time.time() > end:
                        raise RuntimeError(f'resuming the snapshot: {st}')
                    time.sleep(0.05)
                qmp.cmd('cont')               # saved while stopped, so it resumes paused
                qmp.close()
                self._wait_ssh(timeout)
                # The guest clock resumes where the snapshot was taken.
                self.sh(f'date -u -s @{time.time():.3f} >/dev/null', root=True, timeout=30)
        except BaseException:
            self.stop(failed=True)
            raise
        self._save()
        log(f'VM up in {time.time() - t0:.1f} s ({"fresh" if self.fresh else "from snapshot"}), unit {self.unit}')
        return self

    def _seed(self, d):
        seed = os.path.join(d, 'seed')
        os.makedirs(seed, exist_ok=True)
        pub = open(self.key + '.pub').read().strip()
        open(os.path.join(seed, 'user-data'), 'w').write(
            f'#cloud-config\nhostname: {self.hostname}\npackage_update: false\nusers:\n  - name: tester\n'
            '    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n'
            f'    ssh_authorized_keys: ["{pub}"]\nssh_pwauth: false\n')
        open(os.path.join(seed, 'meta-data'), 'w').write(f'instance-id: {self.name}-{time.time_ns()}\n'
                                                          f'local-hostname: {self.hostname}\n')
        open(os.path.join(seed, 'vendor-data'), 'w').close()
        return seed

    def _cold_boot(self, image, disk, d, timeout):
        """Boot the cloud image through cloud-init (seeded over HTTP from this process)."""
        _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', image, disk, f'{self.disk_gb}G'])
        handler = functools.partial(_QuietHandler, directory=self._seed(d))
        httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            self._start(disk, d, seed_port=httpd.server_address[1])
            self._wait_ssh(timeout)
            rc, out = self.sh('cloud-init status --wait >/dev/null', timeout=timeout)
            if rc not in (0, 2):        # 2: done with recoverable errors (as before: only SSH access matters)
                raise RuntimeError(f'cloud-init failed: {out}')
        finally:
            httpd.shutdown()
            httpd.server_close()

    def _snapshot(self, image, timeout):
        """Directory with disk.qcow2 + state (RAM) + id_vm of a VM just after cloud-init; made once per kind."""
        sums = _sum_line(os.path.dirname(image)).split()[0]
        kind = json.dumps([LAYOUT, sums, self.hostname, self.mem_mb, self.cpus, self.disk_gb])
        snaps = os.path.join(self.vm_dir, 'snapshots')
        snap = os.path.join(snaps, f'{self.name}-{hashlib.sha256(kind.encode()).hexdigest()[:12]}')
        os.makedirs(snaps, exist_ok=True)
        with open(snap + '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)          # a second run of the same kind waits for the first to finish
            if os.path.exists(os.path.join(snap, 'state')):
                os.utime(snap)                        # last use, for prune
                return snap
            log(f'preparing snapshot {os.path.basename(snap)} (once: cloud-init boot, then save disk and RAM)')
            tmp = f'{snap}.tmp-{os.getpid()}'
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp)
            self.key = os.path.join(tmp, 'id_vm')
            _keygen(self.key)
            try:
                self._cold_boot(image, os.path.join(tmp, 'disk.qcow2'), tmp, timeout)
                # cloud-init never runs again; the journal also goes to the serial console, so console.log shows
                # what happened even when SSH drops.
                rc, out = self.sh(
                    'touch /etc/cloud/cloud-init.disabled && mkdir -p /etc/systemd/journald.conf.d && printf '
                    '"[Journal]\\nForwardToConsole=yes\\nTTYPath=/dev/ttyS0\\nMaxLevelConsole=info\\n" '
                    '> /etc/systemd/journald.conf.d/throwvm-console.conf && systemctl restart systemd-journald && '
                    'sync && echo 3 > /proc/sys/vm/drop_caches', root=True, timeout=60)
                if rc != 0:
                    raise RuntimeError(f'preparing the snapshot failed: {out}')
                qmp = QMP(_qmp_path(tmp))
                qmp.cmd('stop')
                qmp.cmd('migrate-set-parameters', **{'max-bandwidth': 2**40})
                qmp.cmd('migrate', uri=f'file:{tmp}/state')
                end = time.time() + 300
                while (st := qmp.cmd('query-migrate').get('status')) != 'completed':
                    if st in ('failed', 'cancelled') or time.time() > end:
                        raise RuntimeError(f'saving the VM state: {st}')
                    time.sleep(0.2)
                qmp.close()
                self._stop_unit()
                for f in ('disk.qcow2', 'state'):
                    os.chmod(os.path.join(tmp, f), 0o444)   # backing files of every later VM: never written again
                os.remove(os.path.join(tmp, 'qemu.log'))
                shutil.rmtree(os.path.join(tmp, 'seed'))
                os.rename(tmp, snap)
            except BaseException:
                self._stop_unit()
                shutil.rmtree(tmp, ignore_errors=True)
                raise
            log(f'snapshot ready: {os.path.getsize(os.path.join(snap, "state")) // 2**20} MiB RAM state')
            return snap

    def _start(self, disk, d, seed_port=None, incoming=None):
        """Start QEMU in its own scope (waiting for free RAM first). Retries if the random SSH port was taken."""
        for attempt in range(3):
            self.ssh_port = free_port()
            qemu = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-machine', 'q35', '-smp', str(self.cpus),
                    '-m', str(self.mem_mb), '-display', 'none', '-serial', f'file:{d}/console.log',
                    '-monitor', 'none', '-qmp', f'unix:{_qmp_path(d)},server=on,wait=off',
                    '-device', 'virtio-rng-pci', '-device', 'vmgenid',   # fresh entropy after a snapshot resume
                    '-drive', f'file={disk},if=virtio',
                    '-nic', f'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22']
            if seed_port:
                qemu += ['-smbios', f'type=1,serial=ds=nocloud;s=http://10.0.2.2:{seed_port}/']
            if incoming:
                qemu += ['-incoming', f'file:{incoming}']
            self.unit = f'throwvm-{self.name}-{os.getpid()}-{attempt}-{time.time_ns() % 10**6}.scope'
            mem = self.mem_mb + OVERHEAD_MB
            with admitted(self.vm_dir, mem):
                self.proc = subprocess.Popen(
                    ['systemd-run', '--user', '--scope', '--quiet', f'--unit={self.unit}',
                     '-p', f'MemoryMax={mem}M', '-p', f'MemoryHigh={self.mem_mb + HIGH_MB}M',
                     '-p', 'CollectMode=inactive-or-failed',
                     sys.executable, '-I', os.path.abspath(__file__), '_guard', str(self.owner), '--', *qemu],
                    stdin=subprocess.DEVNULL, stdout=open(f'{d}/qemu.log', 'w'), stderr=subprocess.STDOUT,
                    start_new_session=True)
                end = time.time() + 10
                while _systemctl('is-active', self.unit).stdout.strip() != 'active' and self.proc.poll() is None:
                    if time.time() > end:
                        raise RuntimeError(f'scope {self.unit} did not start')
                    time.sleep(0.05)
            time.sleep(0.3)
            if self.proc.poll() is None:
                return
            err = open(f'{d}/qemu.log').read()
            if 'host forwarding' not in err:
                raise RuntimeError(f'QEMU exited at start: {err.strip()}')
        raise RuntimeError('no free SSH port after 3 tries')

    def _wait_ssh(self, timeout):
        end = time.time() + timeout
        while self.sh('true', timeout=10)[0] != 0:
            if time.time() > end or self.proc.poll() is not None:
                raise RuntimeError(f'VM did not come up (see {self.dir}/console.log and qemu.log)')
            time.sleep(0.5)

    # -- use
    def sh(self, command, input=None, timeout=120, root=False):
        """Run a command in the VM as tester (or root). Returns (exit code, combined output); 124 on timeout."""
        cmd = f'sudo bash -c {shlex.quote(command)}' if root else command
        try:
            r = subprocess.run([*self.ssh_argv()[:-1], '-o', 'ConnectTimeout=5', 'tester@127.0.0.1', cmd],
                               input=input, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b'') + (e.stderr or b'')
            return 124, out.decode(errors='replace') + f'\n[timed out after {timeout} s]'
        return r.returncode, (r.stdout + r.stderr).decode(errors='replace')

    def offline(self):
        """Drop all outgoing guest traffic except loopback and replies (the SSH session from the host)."""
        # One atomic transaction: added rule by rule, the drop policy would briefly cut the SSH session running it.
        rules = ('table inet bench {\n chain out {\n  type filter hook output priority 0; policy drop;\n'
                 '  oif lo accept\n  ct state established,related accept\n }\n}\n').encode()
        for _ in range(2):
            rc, out = self.sh('nft list table inet bench >/dev/null 2>&1 || nft -f -', input=rules, root=True,
                              timeout=60)
            if rc == 0:
                return
        raise RuntimeError(f'could not take the VM offline: {out}')

    def stats(self):
        """Memory (MiB) and CPU time (s) of the VM's scope, read from its cgroup."""
        p = _unit_props([self.unit], ['MemoryCurrent', 'MemoryPeak', 'CPUUsageNSec']).get(self.unit, {})
        mib = lambda v: v // 2**20 if v is not None else None
        return {'mem_current_mb': mib(p.get('MemoryCurrent')), 'mem_peak_mb': mib(p.get('MemoryPeak')),
                'cpu_s': round(p['CPUUsageNSec'] / 1e9, 1) if p.get('CPUUsageNSec') is not None else None}

    def stop(self, failed=False, remove=False):
        """Stop the VM's scope and delete its disk. failed: first save the guest journal; logs stay in workdir.
        remove (only when not failed): delete the whole workdir."""
        if failed and self.unit and self.ssh_port and self.key:
            rc, out = self.sh('journalctl -b --no-pager -o short-precise', root=True, timeout=60)
            open(os.path.join(self.dir, 'journal.log'), 'w').write(out if rc == 0 else f'[exit {rc}]\n{out}')
        self._stop_unit()
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(self.dir, 'disk.qcow2'))
        if remove and not failed:
            shutil.rmtree(self.dir, ignore_errors=True)
        elif failed:
            log(f'logs kept in {self.dir} (console.log, qemu.log, journal.log)')

    def _stop_unit(self):
        if self.unit:
            _systemctl('stop', self.unit)
        if self.proc:
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(15)
        for d in (self.dir, *glob.glob(os.path.join(self.vm_dir, 'snapshots', f'*.tmp-{os.getpid()}'))):
            with contextlib.suppress(FileNotFoundError):
                os.remove(_qmp_path(d))


def _qmp_path(d):
    """QMP socket of the VM in directory d: unix socket paths must stay under 108 bytes."""
    run = os.environ.get('XDG_RUNTIME_DIR') or '/tmp'
    return os.path.join(run, f'throwvm-{hashlib.sha256(os.path.abspath(d).encode()).hexdigest()[:16]}.sock')


def _run(argv):
    subprocess.run(argv, check=True)


def _keygen(path):
    for f in (path, path + '.pub'):
        with contextlib.suppress(FileNotFoundError):
            os.remove(f)
    _run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'throwvm', '-f', path])


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def _die_with_parent():
    """In the child before exec: get SIGTERM when the guard dies, so QEMU never outlives it."""
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)   # 1 = PR_SET_PDEATHSIG


def guard(owner, argv):
    """Inside the scope: run QEMU, stop it when the owner process exits (owner 0: never). Returns QEMU's exit code."""
    p = subprocess.Popen(argv, preexec_fn=_die_with_parent)
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, lambda *_: p.terminate())
    poll = select.poll()
    poll.register(os.pidfd_open(p.pid), select.POLLIN)
    if owner:
        try:
            poll.register(os.pidfd_open(owner), select.POLLIN)
        except ProcessLookupError:
            p.terminate()
    while p.poll() is None and not poll.poll(1000):
        pass
    if p.poll() is None:            # the owner exited
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    rc = p.wait()
    return 128 - rc if rc < 0 else rc      # killed by a signal: shell convention


# --- CLI ------------------------------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    up = sub.add_parser('up', help='start a VM in DIR and print bash assignments (VM_SSH array, VM_SSH_PORT, ...)')
    up.add_argument('dir')
    up.add_argument('--vm-dir', default=os.environ.get('VM_DIR'), required='VM_DIR' not in os.environ,
                    help='cache for the image and snapshots (default: $VM_DIR)')
    up.add_argument('--name', default='vm', help='kind of VM: names the snapshot and the scope unit')
    up.add_argument('--mem', type=int, default=3072, help='MiB')
    up.add_argument('--cpus', type=int, default=2)
    up.add_argument('--disk-gb', type=int, default=20)
    up.add_argument('--hostname', default='testbox')
    up.add_argument('--owner', type=int, required=True,
                    help='stop the VM when this PID exits (bash: $$, not the $(...) subshell); 0 = keep running')
    up.add_argument('--fresh', action='store_true', help='boot through cloud-init instead of the snapshot')
    up.add_argument('--timeout', type=int, default=300)
    down = sub.add_parser('down', help='stop the VM in DIR and delete its disk')
    down.add_argument('dir')
    down.add_argument('--failed', action='store_true', help='save the guest journal and keep the logs')
    down.add_argument('--rm', action='store_true', help='delete DIR too (ignored with --failed)')
    sub.add_parser('offline', help='block outgoing traffic of the VM in DIR').add_argument('dir')
    sub.add_parser('stats', help='memory and CPU of the VM in DIR (from its cgroup)').add_argument('dir')
    sub.add_parser('status', help='running VMs and free RAM')
    prune = sub.add_parser('prune', help='delete snapshots not used for DAYS days')
    prune.add_argument('--vm-dir', default=os.environ.get('VM_DIR'), required='VM_DIR' not in os.environ)
    prune.add_argument('--days', type=float, default=14)
    g = sub.add_parser('_guard')
    g.add_argument('owner', type=int)
    g.add_argument('qemu', nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)

    if a.cmd == '_guard':
        return guard(a.owner, a.qemu[1:] if a.qemu[:1] == ['--'] else a.qemu)
    if a.cmd == 'up':
        vm = VM(a.dir, a.vm_dir, a.name, a.mem, a.cpus, a.disk_gb, a.hostname, owner=a.owner, fresh=a.fresh)
        vm.boot(a.timeout)
        print(f'VM_SSH=({shlex.join(vm.ssh_argv())})\nVM_SSH_PORT={vm.ssh_port}\nVM_KEY={shlex.quote(vm.key)}\n'
              f'VM_UNIT={vm.unit}')
    elif a.cmd == 'down':
        vm = VM.load(a.dir)
        s = vm.stats()
        if s['mem_peak_mb'] is not None:
            log(f'VM used: peak {s["mem_peak_mb"]} MiB RAM, {s["cpu_s"]} s CPU')
        vm.stop(failed=a.failed, remove=a.rm)
    elif a.cmd == 'offline':
        VM.load(a.dir).offline()
    elif a.cmd == 'stats':
        print(json.dumps(VM.load(a.dir).stats()))
    elif a.cmd == 'status':
        usage = vm_usage()
        for unit, u in usage.items():
            print(f'{unit}  {(u["MemoryCurrent"] or 0) >> 20} MiB now, peak {(u["MemoryPeak"] or 0) >> 20} MiB, '
                  f'max {(u["MemoryMax"] or 0) >> 20} MiB, {(u["CPUUsageNSec"] or 0) / 1e9:.0f} s CPU')
        print(f'MemAvailable {mem_available_mb()} MiB; a 3 GiB VM could start now: '
              f'{headroom_mb(mem_available_mb(), usage, 3072 + OVERHEAD_MB) >= 0}')
    elif a.cmd == 'prune':
        snaps, cutoff = os.path.join(a.vm_dir, 'snapshots'), time.time() - a.days * 86400
        for e in os.listdir(snaps) if os.path.isdir(snaps) else []:
            p = os.path.join(snaps, e)
            if os.path.isdir(p) and os.path.getmtime(p) < cutoff:
                with open(p + '.lock', 'w') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    shutil.rmtree(p)
                print(f'deleted {p}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
