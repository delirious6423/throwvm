#!/usr/bin/env python3
"""Throwaway QEMU/KVM Ubuntu VMs reachable over SSH (stdlib only, no root needed).

Needs Linux with KVM, QEMU, a systemd user session and Python 3.9+. https://github.com/delirious6423/throwvm (MIT)
Python: `import throwvm; vm = throwvm.VM(workdir, vm_dir).boot(); vm.sh('uname -a'); vm.stop()`.
Bash: `VM_ENV=$(throwvm.py up DIR --vm-dir ... --owner $$); eval "$VM_ENV"`, then `"${VM_SSH[@]}" cmd`,
`throwvm.py down DIR`.

- The Ubuntu cloud image is downloaded once (signature and checksum checked).
- The first VM of a size (RAM, CPUs, disk) boots the cloud image and runs cloud-init; then its disk and RAM are
  saved as the base snapshot. Every later VM resumes a snapshot from a copy-on-write overlay and is reachable over
  SSH within seconds (its clock and hostname are set on resume). `fresh=True` skips snapshots (cloud-init, ~25 s).
- `provision=SCRIPT` (CLI: `--provision`): a bash script run once as root with network on top of the base; the
  result is a second snapshot layer, rebuilt automatically when the script changes.
- Each VM runs in its own `systemd-run --user --scope` unit with MemoryHigh/MemoryMax, so stopping it stops the
  whole group and its memory and CPU use is read from the cgroup.
- A VM only starts when free RAM allows (MemAvailable minus what running VMs may still grow into, minus a reserve);
  otherwise it waits. Starts are serialized by a lock file.
- The VM is stopped when its owner process exits (a guard process watches it), so no VM outlives a killed run.
- On failure `stop(failed=True)` keeps console.log, qemu.log and the guest journal; only the disk is deleted.
- `WindowsVM` (CLI: `up-windows`): the same for a Windows golden image you build (see WindowsVM), with UEFI
  Secure Boot and a swtpm TPM in the scope. Its snapshot keeps the RAM as a file that VMs map copy-on-write, so a
  6 GiB Windows resumes in ~3 s instead of booting in ~15 s.
- `MacVM` / `MacWindowsVM` (CLI: `up-mac`, `up-mac-windows`): arm64 VMs on an Apple Silicon Mac over SSH (Tart VMs,
  or Windows on Arm under UTM's QEMU), each an APFS clone; see the README.
"""
import argparse, contextlib, ctypes, fcntl, functools, glob, hashlib, http.server, json, os, select, shlex, shutil, \
    signal, socket, subprocess, sys, threading, time

RELEASE, VERSION = 'resolute', '26.04'
IMG = f'ubuntu-{VERSION}-server-cloudimg-amd64.img'
URL = f'https://cloud-images.ubuntu.com/releases/{RELEASE}/release'
KEYRING = '/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg'
LAYOUT = 2               # bump when the QEMU command line or the snapshot preparation changes: old snapshots go stale
WINDOWS_LAYOUT = 1       # the same for WindowsVM snapshots
OVERHEAD_MB = 1024       # MemoryMax = guest RAM + this (QEMU itself, page cache of the disk files)
HIGH_MB = 512            # MemoryHigh = guest RAM + this: above it the kernel reclaims the scope's page cache first
RESERVE_MB = int(os.environ.get('THROWVM_RESERVE_MB', 4096))   # RAM always left free for the host


def log(msg):
    print(f'throwvm: {msg}', file=sys.stderr, flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def ensure_image(cache_dir, recheck_s=3600):
    """Path of the verified cloud image in cache_dir, downloading it if missing or stale. Parallel callers take turns
    (a lock), and the checksums are fetched again only if the last check is older than recheck_s."""
    os.makedirs(cache_dir, exist_ok=True)
    run = functools.partial(subprocess.run, cwd=cache_dir, check=True)
    stamp, image = os.path.join(cache_dir, '.verified'), os.path.join(cache_dir, IMG)
    with open(os.path.join(cache_dir, '.lock'), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with contextlib.suppress(FileNotFoundError):
            if time.time() - os.path.getmtime(stamp) < recheck_s and os.path.getmtime(image) <= os.path.getmtime(stamp):
                return image
        # New names first, then rename: _kind() of other VMs reads SHA256SUMS without the lock.
        run(['curl', '-fsS', '--max-time', '60', '-o', 'SHA256SUMS.new', f'{URL}/SHA256SUMS',
             '-o', 'SHA256SUMS.gpg.new', f'{URL}/SHA256SUMS.gpg'])
        run(['gpgv', '--keyring', KEYRING, 'SHA256SUMS.gpg.new', 'SHA256SUMS.new'], capture_output=True)
        for f in ('SHA256SUMS', 'SHA256SUMS.gpg'):
            os.replace(os.path.join(cache_dir, f + '.new'), os.path.join(cache_dir, f))
        check = _sum_line(cache_dir)
        ok = subprocess.run(['sha256sum', '-c', '--status'], input=check, text=True, cwd=cache_dir).returncode == 0
        if not ok:
            run(['curl', '-fL', '--retry', '3', '--max-time', '1800', '-o', IMG, f'{URL}/{IMG}'])
            run(['sha256sum', '-c'], input=check, text=True)
        open(stamp, 'w').close()
        return image


@functools.cache
def host_identity():
    """What a saved RAM and device state depends on besides the VM itself: QEMU's version and the host CPU (VMs
    run with -cpu host). Part of every snapshot key, so a QEMU upgrade or another machine makes a new snapshot."""
    qemu = subprocess.run(['qemu-system-x86_64', '--version'], capture_output=True, text=True, timeout=30,
                          check=True).stdout.splitlines()[0].strip()
    model = flags = ''
    for line in open('/proc/cpuinfo'):
        key, _, value = line.partition(':')
        if key.strip() == 'model name' and not model:
            model = value.strip()
        elif key.strip() == 'flags' and not flags:
            flags = ' '.join(sorted(value.split()))
    return [qemu, model, hashlib.sha256(flags.encode()).hexdigest()[:16]]


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

    BASE_HOSTNAME = 'throwvm'   # in the shared base snapshot; each VM sets its own hostname on resume

    def __init__(self, workdir, vm_dir, name='vm', mem_mb=3072, cpus=2, disk_gb=40, hostname='testbox',
                 owner=None, fresh=False, provision=None, provision_timeout=1800, max_age_days=7):
        """provision: a script run once as root (bash, with network) on top of the base snapshot; the result is saved as
        a second snapshot layer, rebuilt when the script changes or is older than max_age_days (0: never), so the
        packages it installed do not stay frozen."""
        self.max_age_s = max_age_days * 86400 if max_age_days else None
        self.dir, self.vm_dir, self.name = os.path.abspath(workdir), vm_dir, name
        self.provision = os.path.abspath(provision) if provision else None
        self.provision_timeout = provision_timeout
        self.mem_mb, self.cpus, self.disk_gb, self.hostname, self.fresh = mem_mb, cpus, disk_gb, hostname, fresh
        self.owner = os.getpid() if owner is None else owner      # 0: nobody, the VM runs until stopped
        self.ssh_port = self.unit = self.key = self.proc = self.image = None
        self.fixed_port = None                                    # set: always forward this host port to SSH
        self.made_snapshot = False
        self.made = set()               # snapshots made by this process: a failed resume of one is not retried

    # -- state shared with the CLI
    KIND = 'ubuntu'
    SAVED = ('vm_dir', 'name', 'mem_mb', 'cpus', 'disk_gb', 'hostname', 'ssh_port', 'unit', 'key')

    def _save(self):
        with open(os.path.join(self.dir, 'vm.json'), 'w') as f:
            json.dump({'kind': self.KIND, **{k: getattr(self, k) for k in self.SAVED}}, f)

    @staticmethod
    def load(workdir):
        """The VM started in workdir (by this or another process), owned by nobody."""
        d = json.load(open(os.path.join(workdir, 'vm.json')))
        if d.get('kind') == MacVM.KIND:
            vm = MacVM(workdir, d['host'], d['base'], d['key'], d['user'], owner=0)
            vm.ip = d['ip']
            return vm
        if d.get('kind') == MacWindowsVM.KIND:
            return MacWindowsVM(workdir, d['host'], d['golden'], d['key'], d['mem_mb'], d['cpus'], d['ssh_port'],
                                d['vnc'], owner=0)
        if d.get('kind') == WindowsVM.KIND:
            vm = WindowsVM(workdir, d['vm_dir'], d['golden'], d['key'], d['name'], d['mem_mb'], d['cpus'], owner=0)
        else:
            vm = VM(workdir, d['vm_dir'], d['name'], d['mem_mb'], d['cpus'], d['disk_gb'], d['hostname'], owner=0)
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
        self._check()
        t0 = time.time()
        try:
            if self.fresh:
                self._fresh_boot(timeout)
            else:
                self._resume_copy(lambda: self._snapshot(timeout), self.dir, timeout)
        except BaseException:
            self.stop(failed=True)
            raise
        self._save()
        how = 'fresh' if self.fresh else 'snapshot made, then resumed' if self.made_snapshot else 'from snapshot'
        log(f'VM up in {time.time() - t0:.1f} s ({how}), unit {self.unit}')
        return self

    def _check(self):
        """Inputs present before anything starts: here the verified cloud image."""
        self.image = ensure_image(os.path.join(self.vm_dir, 'images'))

    def _fresh_boot(self, timeout):
        self.key = os.path.join(self.dir, 'id_vm')
        _keygen(self.key)
        self._cold_boot(self.image, os.path.join(self.dir, 'disk.qcow2'), self.dir, timeout, self.hostname)
        if self.provision:
            self._run_provision(timeout)

    def _overlay(self, snap, d):
        """Set up the VM's files in d on top of the snapshot; returns the disk to start."""
        self.key = os.path.join(snap, 'id_vm')
        disk = os.path.join(d, 'disk.qcow2')
        _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', os.path.join(snap, 'disk.qcow2'), disk])
        return disk

    def _ready(self, timeout):
        """After a resume: wait for SSH, set the guest clock (it resumes where the snapshot was taken) and the
        hostname (the base snapshot is shared by VMs of every name)."""
        self._wait_ssh(timeout)
        h = shlex.quote(self.hostname)
        rc, out = self.sh(f'date -u -s @{time.time():.3f} >/dev/null && hostnamectl set-hostname {h} && '
                          f'sed -i "s/^127\\.0\\.1\\.1\\s.*/127.0.1.1 {self.hostname}/" /etc/hosts',
                          root=True, timeout=30)
        if rc != 0:
            raise RuntimeError(f'setting clock and hostname after resume: {out}')

    def _seed(self, d, hostname):
        seed = os.path.join(d, 'seed')
        os.makedirs(seed, exist_ok=True)
        pub = open(self.key + '.pub').read().strip()
        open(os.path.join(seed, 'user-data'), 'w').write(
            f'#cloud-config\nhostname: {hostname}\npackage_update: false\nusers:\n  - name: tester\n'
            '    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n'
            f'    ssh_authorized_keys: ["{pub}"]\nssh_pwauth: false\n')
        open(os.path.join(seed, 'meta-data'), 'w').write(f'instance-id: {self.name}-{time.time_ns()}\n'
                                                          f'local-hostname: {hostname}\n')
        open(os.path.join(seed, 'vendor-data'), 'w').close()
        return seed

    def _cold_boot(self, image, disk, d, timeout, hostname):
        """Boot the cloud image through cloud-init (seeded over HTTP from this process)."""
        _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', image, disk, f'{self.disk_gb}G'])
        handler = functools.partial(_QuietHandler, directory=self._seed(d, hostname))
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

    def _kind(self):
        """What a snapshot depends on: VMs of the same kind share one."""
        sums = _sum_line(os.path.dirname(self.image)).split()[0]
        return [LAYOUT, sums, *host_identity(), self.mem_mb, self.cpus, self.disk_gb]

    def _base(self, timeout):
        """The base snapshot: the VM just after it booted, shared by every VM of a kind."""
        return self._layer(self.KIND, self._kind(), self.SNAPSHOT_HOW, self._prepare_snapshot, self._seal_snapshot,
                           timeout)

    def _snapshot(self, timeout):
        """Directory of the saved VM to resume: the base snapshot, or with provision the layer on top of it."""
        base = self._base(timeout)
        if not self.provision:
            return base
        script = hashlib.sha256(open(self.provision, 'rb').read()).hexdigest()
        return self._layer(self.name, [os.path.basename(base), script],
                           f'resume {os.path.basename(base)}, run {os.path.basename(self.provision)}',
                           self._prepare_provisioned, self._seal_provisioned, timeout, max_age_s=self.max_age_s)

    def _layer(self, prefix, kind, how, prepare, seal, timeout, max_age_s=None):
        """vm_dir/snapshots/<prefix>-<hash of kind>: made once (prepare boots a VM in a temporary directory, which is
        then saved and sealed), and again once it is older than max_age_s; later calls only mark it used, for prune."""
        snaps = os.path.join(self.vm_dir, 'snapshots')
        snap = os.path.join(snaps, f'{prefix}-{hashlib.sha256(json.dumps(kind).encode()).hexdigest()[:12]}')
        os.makedirs(snaps, exist_ok=True)
        with open(snap + '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)          # a second run of the same kind waits for the first to finish
            state = os.path.join(snap, 'state')
            if os.path.exists(state) and max_age_s and time.time() - os.path.getmtime(state) > max_age_s:
                log(f'snapshot {os.path.basename(snap)} is older than {max_age_s / 86400:g} days: making it again')
                _discard_locked(snap)
            if os.path.exists(state):
                os.utime(snap)
                return snap
            log(f'preparing snapshot {os.path.basename(snap)} (once: {how}, then save disk and RAM)')
            self.made_snapshot = True
            tmp = f'{snap}.tmp-{os.getpid()}'
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp)
            try:
                prepare(tmp, timeout)
                self._save_state(tmp, os.path.join(tmp, 'state'))
                self._stop_unit()
                seal(tmp)
                os.rename(tmp, snap)
            except BaseException:
                self._stop_unit()
                shutil.rmtree(tmp, ignore_errors=True)
                raise
            self.made.add(snap)
            log(f'snapshot ready: {os.path.getsize(os.path.join(snap, "state")) // 2**20} MiB RAM state')
            return snap

    def _resume_copy(self, get_snap, d, timeout):
        """Resume a copy of the snapshot get_snap() returns, in d. If that fails for a snapshot made earlier (it no
        longer fits this host, or its files are damaged), discard it, make it again and retry once."""
        snap = get_snap()
        try:
            self._resume_in(snap, d, timeout)
        except Exception as e:
            if snap in self.made:
                raise
            log(f'resuming snapshot {os.path.basename(snap)} failed ({str(e).strip()[:200]}); '
                'discarding it and making it again')
            self._stop_unit()
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(d, 'disk.qcow2'))
            discard(snap)
            snap = get_snap()
            self._resume_in(snap, d, timeout)
        return snap

    def _resume_in(self, snap, d, timeout):
        ram = os.path.join(snap, 'ram')
        self._start(self._overlay(snap, d), d, incoming=True, ram=(ram, False) if os.path.exists(ram) else None)
        self._resume(d, snap, timeout)
        self._ready(timeout)

    def _prepare_provisioned(self, tmp, timeout):
        """Resume the base snapshot in tmp and run the provision script in it."""
        base = self._resume_copy(lambda: self._base(timeout), tmp, timeout)
        for f in ('id_vm', 'id_vm.pub'):
            shutil.copy2(os.path.join(base, f), os.path.join(tmp, f))
        self.key = os.path.join(tmp, 'id_vm')
        self._run_provision(timeout)
        rc, out = self.sh('sync && echo 3 > /proc/sys/vm/drop_caches', root=True, timeout=60)
        if rc != 0:
            raise RuntimeError(f'preparing the snapshot failed: {out}')

    def _run_provision(self, timeout):
        """The provision script as root; its output goes to provision.log in the VM's directory."""
        t0 = time.time()
        rc, out = self.sh('bash -s', input=open(self.provision, 'rb').read(), root=True,
                          timeout=self.provision_timeout)
        out_log = os.path.join(self.dir, 'provision.log')
        open(out_log, 'w').write(out)
        if rc != 0:
            tail = '\n'.join(out.splitlines()[-15:])
            raise RuntimeError(f'provision script failed (exit {rc}); full output in {out_log}:\n{tail}')
        log(f'provisioned in {time.time() - t0:.0f} s')

    def _seal_provisioned(self, tmp):
        for f in ('disk.qcow2', 'state'):
            os.chmod(os.path.join(tmp, f), 0o444)
        os.remove(os.path.join(tmp, 'qemu.log'))

    SNAPSHOT_HOW = 'cloud-init boot'

    def _prepare_snapshot(self, tmp, timeout):
        """Boot the VM that will be saved, in tmp, and leave it running."""
        self.key = os.path.join(tmp, 'id_vm')
        _keygen(self.key)
        self._cold_boot(self.image, os.path.join(tmp, 'disk.qcow2'), tmp, timeout, self.BASE_HOSTNAME)
        # cloud-init never runs again; the journal also goes to the serial console, so console.log shows
        # what happened even when SSH drops.
        rc, out = self.sh(
            'touch /etc/cloud/cloud-init.disabled && mkdir -p /etc/systemd/journald.conf.d && printf '
            '"[Journal]\\nForwardToConsole=yes\\nTTYPath=/dev/ttyS0\\nMaxLevelConsole=info\\n" '
            '> /etc/systemd/journald.conf.d/throwvm-console.conf && systemctl restart systemd-journald && '
            'sync && echo 3 > /proc/sys/vm/drop_caches', root=True, timeout=60)
        if rc != 0:
            raise RuntimeError(f'preparing the snapshot failed: {out}')

    def _seal_snapshot(self, tmp):
        for f in ('disk.qcow2', 'state'):
            os.chmod(os.path.join(tmp, f), 0o444)   # backing files of every later VM: never written again
        os.remove(os.path.join(tmp, 'qemu.log'))
        shutil.rmtree(os.path.join(tmp, 'seed'))

    def _save_state(self, d, path):
        """Stop the VM running in d and save its RAM and device state to path (the disk is saved as it is).
        If the guest RAM is the file d/ram (see _start), it stays there and path only gets the device state."""
        ram = os.path.join(d, 'ram')
        qmp = QMP(_qmp_path(d))
        qmp.cmd('stop')
        if os.path.exists(ram):
            qmp.cmd('migrate-set-capabilities', capabilities=[{'capability': 'x-ignore-shared', 'state': True}])
        qmp.cmd('migrate-set-parameters', **{'max-bandwidth': 2**40})
        qmp.cmd('migrate', uri=f'file:{path}')
        end = time.time() + 300
        while (st := qmp.cmd('query-migrate').get('status')) != 'completed':
            if st in ('failed', 'cancelled') or time.time() > end:
                raise RuntimeError(f'saving the VM state: {st}')
            time.sleep(0.2)
        qmp.close()
        if os.path.exists(ram):
            fd = os.open(ram, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def _resume(self, d, snap, timeout):
        """Load the snapshot's saved state into the VM in d (started with incoming=True), then run it."""
        qmp = QMP(_qmp_path(d))
        if os.path.exists(os.path.join(snap, 'ram')):    # RAM is mapped from the file, only device state is loaded
            qmp.cmd('migrate-set-capabilities', capabilities=[{'capability': 'x-ignore-shared', 'state': True}])
        qmp.cmd('migrate-incoming', uri=f'file:{os.path.join(snap, "state")}')
        end = time.time() + timeout
        while (st := qmp.cmd('query-migrate').get('status')) != 'completed':   # loading the RAM state
            if st in ('failed', 'cancelled') or time.time() > end:
                raise RuntimeError(f'resuming the snapshot: {st}')
            time.sleep(0.05)
        qmp.cmd('cont')               # saved while stopped, so it resumes paused
        qmp.close()

    def _start(self, disk, d, seed_port=None, incoming=False, ram=None):
        """Start QEMU in its own scope (waiting for free RAM first). Retries if the random SSH port was taken.
        incoming: wait for _resume to load a saved state. ram: (file, shared) to back the guest RAM by a file:
        shared while preparing a snapshot (the file is then the saved RAM), private on resume (copy-on-write: pages
        are read from the file as the guest touches them, and VMs of a kind share the page cache)."""
        for attempt in range(1 if self.fixed_port else 3):
            self.ssh_port = self.fixed_port or free_port()
            qemu = self._qemu_argv(disk, d, seed_port)
            if ram:
                opts = 'share=on' if ram[1] else 'share=off,readonly=on,rom=off'
                qemu += ['-object', f'memory-backend-file,id=ram0,size={self.mem_mb}M,mem-path={ram[0]},{opts}',
                         '-machine', 'memory-backend=ram0']
            if incoming:
                qemu += ['-incoming', 'defer']
            self.unit = f'throwvm-{self.name}-{os.getpid()}-{attempt}-{time.time_ns() % 10**6}.scope'
            mem = self.mem_mb + OVERHEAD_MB
            with admitted(self.vm_dir, mem):
                self.proc = subprocess.Popen(
                    ['systemd-run', '--user', '--scope', '--quiet', f'--unit={self.unit}',
                     '-p', f'MemoryMax={mem}M', '-p', f'MemoryHigh={self.mem_mb + HIGH_MB}M',
                     '-p', 'CollectMode=inactive-or-failed',
                     sys.executable, '-I', os.path.abspath(__file__), '_guard', str(self.owner), '--',
                     *self._scope_argv(qemu, d)],
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

    def _qemu_argv(self, disk, d, seed_port=None):
        qemu = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-machine', 'q35', '-smp', str(self.cpus),
                '-m', str(self.mem_mb), '-display', 'none', '-serial', f'file:{d}/console.log',
                '-monitor', 'none', '-qmp', f'unix:{_qmp_path(d)},server=on,wait=off',
                '-device', 'virtio-rng-pci', '-device', 'vmgenid',   # fresh entropy after a snapshot resume
                '-drive', f'file={disk},if=virtio',
                '-nic', f'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22']
        if seed_port:
            qemu += ['-smbios', f'type=1,serial=ds=nocloud;s=http://10.0.2.2:{seed_port}/']
        return qemu

    def _scope_argv(self, qemu, d):
        """What runs in the VM's scope (under the guard): QEMU, or a wrapper that starts helpers and execs it."""
        return qemu

    def _wait_ssh(self, timeout):
        end = time.time() + timeout
        while self.sh('exit 0', timeout=10)[0] != 0:            # also a no-op in PowerShell
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


class WindowsVM(VM):
    """Throwaway copy of a Windows golden image; SSH lands in PowerShell as tester.

    The golden image is a directory with disk.qcow2 (Windows with OpenSSH Server accepting `key` for an
    administrator `tester`, auto-logon to the desktop), vars.fd (its OVMF NVRAM vars) and tpm/ (its swtpm state).
    The machine must match the one it was installed on: UEFI Secure Boot (OVMF code + a copy of the image's NVRAM
    vars), a swtpm TPM 2.0 that runs inside the VM's scope, AHCI disk, e1000e NIC. The snapshot of a golden image
    is its first boot, saved once the desktop is up and the guest has gone quiet. The firmware vars (pflash) and the
    TPM state (QEMU's tpm-emulator backend) are saved with the RAM, so on resume they match the running Windows.
    """
    KIND = 'windows'
    SAVED = VM.SAVED + ('golden',)
    SNAPSHOT_HOW = 'Windows boot until the desktop is idle'
    OVMF_CODE = '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd'
    # Starts swtpm (args: live TPM dir, QEMU argv), waits for its control socket, then becomes QEMU. With
    # --terminate swtpm exits when QEMU disconnects; stopping the scope stops both anyway.
    TPM_WRAPPER = ('t=$1; shift; swtpm socket --tpm2 --terminate --tpmstate "dir=$t" '
                   '--ctrl "type=unixio,path=$t/swtpm.sock" --log "file=$t/swtpm.log" & '
                   'i=0; until [ -S "$t/swtpm.sock" ]; do i=$((i+1)); '
                   '[ $i -lt 100 ] || { echo "swtpm did not start" >&2; exit 1; }; sleep 0.05; done; exec "$@"')

    def __init__(self, workdir, vm_dir, golden, key, name='windows', mem_mb=6144, cpus=4, ssh_port=None, vnc=None,
                 acpi_tables=(), owner=None, fresh=False, settle_s=180):
        super().__init__(workdir, vm_dir, name, mem_mb, cpus, disk_gb=None, hostname=None, owner=owner, fresh=fresh)
        self.golden, self.key, self.fixed_port, self.vnc = os.path.abspath(golden), key, ssh_port, vnc
        self.acpi_tables, self.settle_s = list(acpi_tables), settle_s

    def _check(self):
        for f in ('disk.qcow2', 'vars.fd', 'tpm'):
            if not os.path.exists(os.path.join(self.golden, f)):
                raise RuntimeError(f'no {f} in the golden image {self.golden} (see WindowsVM)')
        if not shutil.which('swtpm') or not os.path.exists(self.OVMF_CODE):
            raise RuntimeError('needs swtpm and ovmf (apt install swtpm ovmf)')

    def _kind(self):
        # Files by size and mtime only: the ACPI tables (the OEM licence key) are never read here.
        files = [os.path.join(self.golden, f) for f in ('disk.qcow2', 'vars.fd')] + sorted(
            glob.glob(os.path.join(self.golden, 'tpm', '*'))) + self.acpi_tables
        sig = [(os.path.basename(f), (st := os.stat(f)).st_size, st.st_mtime_ns) for f in files]
        return [WINDOWS_LAYOUT, self.golden, sig, *host_identity(), self.mem_mb, self.cpus]

    def _machine_files(self, src, d):
        """d gets an overlay disk on src's disk and copies of its firmware vars and TPM state."""
        disk = os.path.join(d, 'disk.qcow2')
        _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', os.path.join(src, 'disk.qcow2'), disk])
        shutil.copyfile(os.path.join(src, 'vars.fd'), os.path.join(d, 'vars.fd'))
        os.chmod(os.path.join(d, 'vars.fd'), 0o600)
        shutil.rmtree(os.path.join(d, 'tpm'), ignore_errors=True)
        shutil.copytree(os.path.join(src, 'tpm'), os.path.join(d, 'tpm'))
        return disk

    def _fresh_boot(self, timeout):
        self._start(self._machine_files(self.golden, self.dir), self.dir)
        self._wait_ssh(timeout)

    def _overlay(self, snap, d):
        return self._machine_files(snap, d)

    def _prepare_snapshot(self, tmp, timeout):
        # The RAM is a file from the start: saving the snapshot then only writes the device state, and resuming maps
        # the file instead of loading ~5 GiB.
        self._start(self._machine_files(self.golden, tmp), tmp, ram=(os.path.join(tmp, 'ram'), True))
        self._wait_ssh(timeout)
        end = time.time() + timeout
        while self.sh('if (Get-Process explorer -EA 0) { exit 0 } else { exit 1 }', timeout=30)[0] != 0:
            if time.time() > end:
                raise RuntimeError('no desktop (explorer.exe) after boot')
            time.sleep(1)
        # Startup work (services, scheduled tasks, Defender) goes on for a while after logon. Save once the VM's
        # CPU use stays low, so a resumed VM does not redo it at the start of every test.
        t0, last = time.time(), self.stats()['cpu_s']
        while time.time() - t0 < self.settle_s:
            time.sleep(5)
            now = self.stats()['cpu_s']
            # Under half a CPU for 5 s. A cold-booted Windows here idles at ~0.4 CPU (QEMU included) with bursts.
            if time.time() - t0 >= 20 and now - last < 5 * 0.5:
                break
            last = now
        log(f'saving after {time.time() - t0:.0f} s of settling')

    def _seal_snapshot(self, tmp):
        # state holds the guest RAM (with the auto-logon password) and the ACPI tables: owner-only.
        for f in ('disk.qcow2', 'vars.fd', 'state', 'ram'):
            os.chmod(os.path.join(tmp, f), 0o400)
        for f in ('qemu.log', 'swtpm.log'):
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(tmp, f))

    # Prints the guest clock, reads the host's correction from stdin and applies it: one PowerShell start (~1.5 s
    # each over SSH) both shows that SSH works and sets the clock, to within the time the line takes to arrive.
    CLOCK_PS = ('[Console]::Out.WriteLine([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()); [Console]::Out.Flush(); '
                '$lag = [Console]::In.ReadLine(); Set-Date -Adjust ([TimeSpan]::FromMilliseconds([long]$lag)) | Out-Null')

    def _ready(self, timeout):
        end = time.time() + timeout
        while not self._set_clock():
            if time.time() > end or self.proc.poll() is not None:
                raise RuntimeError(f'VM did not come up (see {self.dir}/qemu.log)')
            time.sleep(0.5)

    def _set_clock(self):
        """True once the clock is set; False if SSH does not answer yet."""
        p = subprocess.Popen([*self.ssh_argv()[:-1], '-o', 'ConnectTimeout=5', 'tester@127.0.0.1', self.CLOCK_PS],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            ready, _, _ = select.select([p.stdout], [], [], 20)
            line = p.stdout.readline() if ready else ''
            if not line.strip().isdigit():
                p.kill()
                p.communicate()
                return False
            p.stdin.write(f'{int(time.time() * 1000) - int(line)}\n')
            p.stdin.close()
            out = p.communicate(timeout=30)[0]
        except BaseException:
            p.kill()
            p.wait()
            raise
        if p.returncode != 0:
            raise RuntimeError(f'setting the guest clock: {out}')
        return True

    def _qemu_argv(self, disk, d, seed_port=None):
        qemu = ['qemu-system-x86_64', '-name', 'win-test', '-enable-kvm',
                '-machine', 'q35,smm=on', '-global', 'driver=cfi.pflash01,property=secure,value=on',
                '-cpu', 'host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time',
                '-smp', str(self.cpus), '-m', str(self.mem_mb),
                '-drive', f'if=pflash,format=raw,readonly=on,file={self.OVMF_CODE}',
                '-drive', f'if=pflash,format=raw,file={d}/vars.fd',
                '-chardev', f'socket,id=chrtpm,path={_tpm_live(d)}/swtpm.sock',
                '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm', '-device', 'tpm-tis,tpmdev=tpm0',
                '-device', 'ahci,id=ahci', '-drive', f'id=disk,file={disk},if=none,format=qcow2',
                '-device', 'ide-hd,drive=disk,bus=ahci.0,bootindex=1',
                '-nic', f'user,model=e1000e,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22',
                '-device', 'qemu-xhci', '-device', 'usb-tablet',
                '-device', 'vmgenid',            # Windows reseeds its RNG when the generation ID changes (resume)
                '-display', 'none', '-monitor', 'none', '-qmp', f'unix:{_qmp_path(d)},server=on,wait=off']
        for t in self.acpi_tables:
            qemu += ['-acpitable', f'file={t}']
        if self.vnc is not None:
            qemu += ['-vnc', f'127.0.0.1:{self.vnc}']      # for looking at the screen when debugging
        return qemu

    def _scope_argv(self, qemu, d):
        return ['sh', '-c', self.TPM_WRAPPER, 'throwvm-tpm', _tpm_live(d), *qemu]

    def _start(self, disk, d, seed_port=None, incoming=False, ram=None):
        # swtpm's AppArmor profile only lets it write below $HOME and /tmp: its live state sits in ~/.cache.
        live = _tpm_live(d)
        shutil.rmtree(live, ignore_errors=True)
        shutil.copytree(os.path.join(d, 'tpm'), live)
        super()._start(disk, d, seed_port, incoming, ram)

    def sh(self, command, input=None, timeout=120, root=False):
        """Run a PowerShell command in the VM as tester (an administrator; the SSH session is elevated)."""
        if root:
            raise ValueError('Windows: tester is already an administrator')
        return super().sh(command, input, timeout)

    def offline(self):
        raise NotImplementedError('offline() is Ubuntu-only')

    def stop(self, failed=False, remove=False):
        self._stop_unit()
        for f in ('disk.qcow2', 'vars.fd'):
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(self.dir, f))
        shutil.rmtree(os.path.join(self.dir, 'tpm'), ignore_errors=True)
        if remove and not failed:
            shutil.rmtree(self.dir, ignore_errors=True)
        elif failed:
            log(f'logs kept in {self.dir} (qemu.log, swtpm.log)')

    def _stop_unit(self):
        super()._stop_unit()
        for d in (self.dir, *glob.glob(os.path.join(self.vm_dir, 'snapshots', f'*.tmp-{os.getpid()}'))):
            live = _tpm_live(d)
            with contextlib.suppress(FileNotFoundError):
                shutil.copyfile(os.path.join(live, 'swtpm.log'), os.path.join(d, 'swtpm.log'))
            shutil.rmtree(live, ignore_errors=True)


def _tpm_live(d):
    """Live swtpm state of the VM in directory d (also short enough for the socket path)."""
    return os.path.join(os.path.expanduser('~/.cache/throwvm-tpm'), hashlib.sha256(os.path.abspath(d).encode())
                        .hexdigest()[:16])


def discard(snap):
    """Delete a snapshot (under its lock). VMs running from it keep their open files."""
    with open(snap + '.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _discard_locked(snap)


def _discard_locked(snap):
    if os.path.isdir(snap):
        bad = f'{snap}.discarded-{os.getpid()}'
        os.rename(snap, bad)                         # gone at once for other runs, then deleted
        shutil.rmtree(bad, ignore_errors=True)


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


# --- VMs on a Mac (Apple Silicon), driven over SSH ------------------------------------------------------------------

class MacVM:
    """A throwaway Tart VM (macOS or Linux, arm64) on a Mac reachable as `ssh HOST`: an APFS clone of a local Tart VM
    (`base`), so it starts in seconds and costs no disk until written. Needs Tart on the Mac's PATH and a base image
    with Tart's guest agent (the cirruslabs images have it): the SSH key goes in through `tart exec`, no password.
    SSH reaches the VM through the Mac (-J HOST). workdir (on this machine) holds vm.json and, unless given, the key."""

    KIND = 'mac'
    SAVED = ('host', 'base', 'vm', 'user', 'key', 'ip')

    def __init__(self, workdir, host, base, key=None, user='admin', owner=None):
        self.dir, self.host, self.base, self.user = os.path.abspath(workdir), host, base, user
        self.key = os.path.abspath(key) if key else os.path.join(self.dir, 'id_test')
        self.vm = 'throwvm-' + os.path.basename(self.dir)
        self.owner = os.getpid() if owner is None else owner
        self.ip = None
        self.ssh_port, self.unit = 22, self.vm

    def _save(self):
        with open(os.path.join(self.dir, 'vm.json'), 'w') as f:
            json.dump({'kind': self.KIND, **{k: getattr(self, k) for k in self.SAVED}}, f)

    def mac(self, command, input=None, timeout=120, check=True):
        """Run a shell command on the Mac. Returns its stdout (text)."""
        r = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', self.host, command],
                           input=input, capture_output=True, timeout=timeout)
        if check and r.returncode:
            raise RuntimeError(f'{self.host}: {command!r} failed: {r.stderr.decode(errors="replace").strip()}')
        return r.stdout.decode(errors='replace').strip()

    def ssh_argv(self):
        return ['ssh', '-q', '-J', self.host, '-i', self.key, '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes',
                '-o', 'ServerAliveInterval=15', f'{self.user}@{self.ip}']

    def boot(self, timeout=300):
        os.makedirs(self.dir, exist_ok=True)
        if not os.path.exists(self.key):
            _keygen(self.key)
        q = shlex.quote
        if self.base not in self.mac('tart list -q --source local').split():
            raise RuntimeError(f'no Tart VM {self.base!r} on {self.host}')
        self.mac(f'tart delete {q(self.vm)} >/dev/null 2>&1; tart clone {q(self.base)} {q(self.vm)}')
        self._save()
        _watch(self.owner, self.dir)
        self.mac(f'(nohup tart run --no-graphics {q(self.vm)} > /tmp/{self.vm}.log 2>&1 < /dev/null &)')
        end = time.time() + timeout
        while subprocess.run(['ssh', '-o', 'BatchMode=yes', self.host, f'tart exec {q(self.vm)} true'],
                             capture_output=True, timeout=60).returncode:
            if time.time() > end:
                raise RuntimeError(f'guest agent of {self.vm} did not answer (log: ssh {self.host} cat /tmp/{self.vm}.log)')
            time.sleep(2)
        add = 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
        self.mac(f'tart exec -i {q(self.vm)} sh -c {q(add)}', input=open(self.key + '.pub', 'rb').read())
        self.ip = self.mac(f'tart ip {q(self.vm)}')
        self._save()
        while self.sh('exit 0', timeout=15)[0] != 0:
            if time.time() > end:
                raise RuntimeError(f'no SSH to {self.vm} at {self.ip}')
            time.sleep(1)
        return self

    def sh(self, command, input=None, timeout=120, root=False):
        cmd = f'sudo -n bash -c {shlex.quote(command)}' if root else command
        try:
            r = subprocess.run([*self.ssh_argv(), cmd], input=input, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, f'[timed out after {timeout} s]'
        return r.returncode, (r.stdout + r.stderr).decode(errors='replace')

    def stats(self):
        return {'mem_current_mb': None, 'mem_peak_mb': None, 'cpu_s': None}

    def offline(self):
        raise RuntimeError('offline is not supported for VMs on a Mac')

    def stop(self, failed=False, remove=False):
        q = shlex.quote(self.vm)
        self.mac(f'tart stop {q} >/dev/null 2>&1; tart delete {q} >/dev/null 2>&1; true', check=False)
        if failed:
            log(f'Tart log: ssh {self.host} cat /tmp/{self.vm}.log')
        elif remove:
            shutil.rmtree(self.dir, ignore_errors=True)


class MacWindowsVM(MacVM):
    """A throwaway copy of a Windows on Arm golden image on the Mac, run by the QEMU bundled in UTM.app with Apple's
    hypervisor. The golden directory on the Mac holds disk.raw, vars.fd and code.fd (AAVMF firmware; made by an
    unattended install, e.g. dotfiles' vm/windows-arm/build.sh); the copy is an APFS clone (cp -c). The display is
    ramfb: Windows 11 26H2's boot manager draws straight to the framebuffer, which virtio-gpu doesn't provide. UTM's own launcher only runs inside UTM, so
    `qemu-launch` (QEMU_LAUNCH_C below, compiled on the Mac and signed for the hypervisor) loads UTM's QEMU library.
    SSH: tester@127.0.0.1 on the Mac's ssh_port (QEMU user networking), through the Mac."""

    KIND = 'mac-windows'
    SAVED = ('host', 'golden', 'vm', 'user', 'key', 'ssh_port', 'mem_mb', 'cpus', 'vnc')
    UTM = '$HOME/Applications/UTM.app/Contents'

    def __init__(self, workdir, host, golden, key, mem_mb=6144, cpus=4, ssh_port=2232, vnc=None, owner=None):
        super().__init__(workdir, host, None, key, 'tester', owner)
        self.golden, self.mem_mb, self.cpus, self.ssh_port, self.vnc = golden, mem_mb, cpus, ssh_port, vnc
        self.run = f'VMs/throwvm/{self.vm}'          # on the Mac, under its home
        self.ip = '127.0.0.1'

    def ssh_argv(self):
        return [*super().ssh_argv()[:-1], '-p', str(self.ssh_port), 'tester@127.0.0.1']

    def qemu_args(self):
        u, r = self.UTM, self.run
        return [f'{u}/Frameworks/qemu-aarch64-softmmu.framework/qemu-aarch64-softmmu', '-L', f'{u}/Resources/qemu',
                '-name', self.vm, '-machine', 'virt,highmem=on', '-accel', 'hvf', '-cpu', 'host',
                '-smp', str(self.cpus), '-m', str(self.mem_mb),
                '-drive', f'if=pflash,format=raw,readonly=on,file={r}/code.fd',
                '-drive', f'if=pflash,format=raw,file={r}/vars.fd',
                '-device', 'ramfb', '-device', 'qemu-xhci', '-device', 'usb-kbd', '-device', 'usb-tablet',
                '-drive', f'id=disk,if=none,format=raw,file={r}/disk.raw,discard=unmap',
                '-device', 'nvme,drive=disk,serial=windisk,bootindex=1',
                '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22',
                '-device', 'virtio-net-pci,netdev=n0', '-display', 'none',
                *(['-vnc', f'127.0.0.1:{self.vnc}'] if self.vnc is not None else []),
                '-monitor', f'unix:{r}/mon.sock,server,nowait']

    def ensure_launcher(self):
        if self.mac('test -x ~/bin/qemu-launch && echo ok', check=False) == 'ok':
            return
        self.mac('cat > /tmp/qemu-launch.c', input=QEMU_LAUNCH_C.encode())
        self.mac('cat > /tmp/qemu-launch.plist', input=QEMU_LAUNCH_ENTITLEMENTS.encode())
        self.mac(f'mkdir -p ~/bin && cc -O2 -Wall -Wl,-rpath,{self.UTM}/Frameworks -o ~/bin/qemu-launch '
                 '/tmp/qemu-launch.c && codesign -s - -f --entitlements /tmp/qemu-launch.plist ~/bin/qemu-launch')

    def boot(self, timeout=600):
        os.makedirs(self.dir, exist_ok=True)
        g, r = shlex.quote(self.golden), self.run
        if self.mac(f'test -d {self.UTM} && test -f {g}/disk.raw && echo ok', check=False) != 'ok':
            raise RuntimeError(f'need UTM.app in ~/Applications and {self.golden}/disk.raw on {self.host}')
        self.ensure_launcher()
        self.mac(f'rm -rf {r} && mkdir -p {r} && cp -c {g}/disk.raw {g}/vars.fd {g}/code.fd {r}/')
        self._save()
        _watch(self.owner, self.dir)
        # double quotes: the Mac's shell expands $HOME in the UTM paths; no argument contains " $ ` or \ otherwise
        cmd = ' '.join(f'"{x}"' for x in self.qemu_args())
        self.mac(f'cd ~ && (nohup ~/bin/qemu-launch {cmd} > {r}/qemu.log 2>&1 < /dev/null & echo $! > {r}/qemu.pid)')
        end = time.time() + timeout
        while self.sh('exit 0', timeout=15)[0] != 0:
            if time.time() > end or self.mac(f'kill -0 $(cat {r}/qemu.pid) 2>/dev/null && echo up', check=False) != 'up':
                raise RuntimeError(f'Windows did not answer over SSH (log: ssh {self.host} cat {r}/qemu.log)')
            time.sleep(5)
        return self

    def monitor(self, command):
        return self.mac(f'echo {shlex.quote(command)} | nc -U -w 2 {self.run}/mon.sock', check=False)

    def sh(self, command, input=None, timeout=120, root=False):
        try:
            r = subprocess.run([*self.ssh_argv(), command], input=input, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, f'[timed out after {timeout} s]'
        return r.returncode, (r.stdout + r.stderr).decode(errors='replace')

    def stop(self, failed=False, remove=False):
        r = self.run
        self.monitor('quit')
        self.mac(f'for i in $(seq 20); do kill -0 $(cat {r}/qemu.pid 2>/dev/null) 2>/dev/null || break; sleep 1; done; '
                 f'kill $(cat {r}/qemu.pid 2>/dev/null) 2>/dev/null; '
                 + (f'rm -f {r}/disk.raw' if failed else f'rm -rf {r}'), check=False)
        if failed:
            log(f'QEMU log kept on {self.host}: {r}/qemu.log')
        elif remove:
            shutil.rmtree(self.dir, ignore_errors=True)


def _watch(owner, workdir):
    """A detached process that stops the VM in workdir when the owner process exits (owner 0: nobody)."""
    if owner:
        subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), '_watch', str(owner), workdir],
                         start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)


def _watch_main(owner, workdir):
    try:
        fd = os.pidfd_open(owner)
        select.select([fd], [], [])
    except ProcessLookupError:
        pass
    if os.path.exists(os.path.join(workdir, 'vm.json')):
        VM.load(workdir).stop()


QEMU_LAUNCH_C = r"""// Runs the QEMU bundled in UTM.app from a shell: qemu-launch <qemu-*-softmmu dylib> <qemu arguments...>
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <qemu dylib> <qemu arguments...>\n", argv[0]); return 2; }
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    void (*init)(int, char **) = (void (*)(int, char **))dlsym(lib, "qemu_init");
    int (*loop)(void) = (int (*)(void))dlsym(lib, "qemu_main_loop");
    void (*cleanup)(int) = (void (*)(int))dlsym(lib, "qemu_cleanup");
    if (!init || !loop || !cleanup) { fprintf(stderr, "missing qemu entry points\n"); return 1; }
    argv[1] = argv[0];   /* QEMU sees its arguments as if it were the program */
    init(argc - 1, argv + 1);
    int status = loop();
    cleanup(status);
    return status;
}
"""
QEMU_LAUNCH_ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>
"""


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
    up.add_argument('--disk-gb', type=int, default=40, help='virtual size; the disk only grows as written')
    up.add_argument('--hostname', default='testbox')
    up.add_argument('--owner', type=int, required=True,
                    help='stop the VM when this PID exits (bash: $$, not the $(...) subshell); 0 = keep running')
    up.add_argument('--provision', metavar='SCRIPT',
                    help='bash script run once as root with network on top of the base snapshot; saved as a '
                         'second snapshot layer, rebuilt when the script changes')
    up.add_argument('--max-age-days', type=float, default=7,
                    help='make the provision layer again once it is older than this (0: never; default 7)')
    up.add_argument('--fresh', action='store_true', help='boot through cloud-init instead of the snapshot')
    up.add_argument('--timeout', type=int, default=300)
    win = sub.add_parser('up-windows', help='start a throwaway copy of a Windows golden image in DIR')
    win.add_argument('dir')
    win.add_argument('--vm-dir', default=os.environ.get('VM_DIR'), required='VM_DIR' not in os.environ,
                     help='where the snapshots go (default: $VM_DIR)')
    win.add_argument('--golden', required=True, help='directory with disk.qcow2, vars.fd and tpm/')
    win.add_argument('--key', required=True, help='SSH private key that the image accepts')
    win.add_argument('--name', default='windows')
    win.add_argument('--mem', type=int, default=6144, help='MiB')
    win.add_argument('--cpus', type=int, default=4)
    win.add_argument('--ssh-port', type=int, help='fixed host port for SSH (default: a free one)')
    win.add_argument('--vnc', type=int, help='VNC display on 127.0.0.1')
    win.add_argument('--acpi-table', action='append', default=[],
                     help="extra ACPI table file, e.g. the host's MSDM (OEM licence key)")
    win.add_argument('--owner', type=int, required=True, help='as for up')
    win.add_argument('--fresh', action='store_true', help='cold-boot the golden image instead of the snapshot')
    win.add_argument('--timeout', type=int, default=600)
    mac = sub.add_parser('up-mac', help='start a throwaway Tart VM (macOS / Linux arm64) on a Mac over SSH')
    mac.add_argument('dir', help='local folder for vm.json (and the key, unless --key)')
    mac.add_argument('--host', required=True, help='ssh host of the Mac')
    mac.add_argument('--base', required=True, help='local Tart VM on the Mac to clone')
    mac.add_argument('--key', help='SSH private key to install in the VM (default: DIR/id_test, made if missing)')
    mac.add_argument('--user', default='admin')
    mac.add_argument('--owner', type=int, required=True, help='as for up')
    mac.add_argument('--timeout', type=int, default=300)
    mw = sub.add_parser('up-mac-windows', help='start a throwaway copy of a Windows on Arm golden image on a Mac')
    mw.add_argument('dir', help='local folder for vm.json')
    mw.add_argument('--host', required=True, help='ssh host of the Mac')
    mw.add_argument('--golden', required=True, help='folder on the Mac (relative to its home) with disk.raw, vars.fd, code.fd')
    mw.add_argument('--key', required=True, help='SSH private key that the image accepts')
    mw.add_argument('--mem', type=int, default=6144, help='MiB')
    mw.add_argument('--cpus', type=int, default=4)
    mw.add_argument('--ssh-port', type=int, default=2232, help="port on the Mac's 127.0.0.1")
    mw.add_argument('--vnc', type=int, help="VNC display on the Mac's 127.0.0.1")
    mw.add_argument('--owner', type=int, required=True, help='as for up')
    mw.add_argument('--timeout', type=int, default=600)
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
    w = sub.add_parser('_watch')
    w.add_argument('owner', type=int)
    w.add_argument('dir')
    g = sub.add_parser('_guard')
    g.add_argument('owner', type=int)
    g.add_argument('qemu', nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)

    if a.cmd == '_guard':
        return guard(a.owner, a.qemu[1:] if a.qemu[:1] == ['--'] else a.qemu)
    if a.cmd == '_watch':
        return _watch_main(a.owner, a.dir)
    if a.cmd in ('up', 'up-windows', 'up-mac', 'up-mac-windows'):
        if a.cmd == 'up-mac':
            vm = MacVM(a.dir, a.host, a.base, a.key, a.user, owner=a.owner)
        elif a.cmd == 'up-mac-windows':
            vm = MacWindowsVM(a.dir, a.host, a.golden, a.key, a.mem, a.cpus, a.ssh_port, a.vnc, owner=a.owner)
        elif a.cmd == 'up':
            vm = VM(a.dir, a.vm_dir, a.name, a.mem, a.cpus, a.disk_gb, a.hostname, owner=a.owner, fresh=a.fresh,
                    provision=a.provision, max_age_days=a.max_age_days)
        else:
            vm = WindowsVM(a.dir, a.vm_dir, a.golden, os.path.abspath(a.key), a.name, a.mem, a.cpus, a.ssh_port, a.vnc,
                           [os.path.abspath(t) for t in a.acpi_table], owner=a.owner, fresh=a.fresh)
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
