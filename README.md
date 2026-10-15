# throwvm

Throwaway QEMU/KVM virtual machines for end-to-end tests, reachable over SSH in about a second.

- One Python file, standard library only. Usable from Python (`import throwvm`) and from bash (a small CLI).
- No root needed: VMs run as your user, each in its own memory-limited systemd scope.
- Ubuntu 26.04 guests (cloud image, checksum and signature checked) and, optionally, Windows golden images you
  build yourself.

## Why

Booting a cloud image through cloud-init takes ~25 s, and installing test tools in it takes minutes. throwvm does
both once and saves the running VM (disk and RAM) as a snapshot. Every later VM resumes that snapshot from a
copy-on-write overlay: SSH answers in ~1 s, and the VM is deleted afterwards.

## Needs

- Linux x86_64 with KVM (`/dev/kvm` readable and writable by you)
- QEMU 8.2 or newer (tested with 10.2): `qemu-system-x86`, `qemu-utils`
- A systemd user session (`systemd-run --user`), with the memory controller delegated (the default on current
  distributions); `curl`, `gpgv`, `ssh`, `ssh-keygen`
- Python 3.9+
- On Debian/Ubuntu hosts: `ubuntu-keyring` provides the cloud image signing key
  (`/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg`)
- Disk space in a folder of your choice (`vm_dir`): ~1 GB for the cloud image, ~1-2 GB per snapshot

## Use from bash

```bash
VM_ENV=$(./throwvm.py up /tmp/myvm --vm-dir ~/vms --mem 4096 --cpus 4 --owner $$)   # an assignment: set -e sees failures
eval "$VM_ENV"                      # VM_SSH (array), VM_SSH_PORT, VM_KEY, VM_UNIT
"${VM_SSH[@]}" 'uname -a'
./throwvm.py down /tmp/myvm --rm    # or --failed: keep console.log, qemu.log and the guest journal
```

`--owner $$` stops the VM when your script exits (also when it is killed); `--owner 0` leaves it running.
`./throwvm.py --help` lists the rest: `offline` (block the guest's outgoing traffic), `stats`, `status`, `prune`.

## Use from Python

```python
import throwvm
vm = throwvm.VM('/tmp/myvm', vm_dir='/data/vms', mem_mb=4096, cpus=4, provision='tests/provision.sh').boot()
rc, out = vm.sh('apt list --installed 2>/dev/null | wc -l')
vm.stop(failed=rc != 0, remove=rc == 0)
```

## Snapshot layers

| Layer | Made from | Key (rebuilt when it changes) | Directory in `vm_dir/snapshots` |
|---|---|---|---|
| base | the cloud image, booted through cloud-init | image checksum, QEMU version, host CPU, RAM, CPUs, disk size | `ubuntu-<hash>` |
| provisioned | the base, plus your `--provision` script run as root with network | base + sha256 of the script; made again after 7 days | `<name>-<hash>` |

A VM resumes the top layer. Its clock and hostname are set on resume. Projects with different provision scripts
share the base. Snapshots are made under a lock, so parallel runs wait for the first one instead of building twice.
`throwvm.py prune --days 14` deletes snapshots not used for 14 days.

- **Host:** a saved RAM state only resumes on the QEMU version and CPU it was made on (VMs run with `-cpu host`),
  so both are part of the key: after a QEMU upgrade, or on another machine, the snapshots are made again.
- **Failed resume:** if resuming a snapshot made earlier fails anyway, throwvm logs it, discards that snapshot,
  makes it again and retries once, instead of failing the test.
- **Age:** a provision layer freezes the package versions it installed. It is made again on the first use after 7
  days (`--max-age-days` / `max_age_days`; 0 = never), so tests follow current packages. The base follows the
  cloud image: a new image release changes its checksum and with it the key.

VMs resumed from one snapshot are identical twins: same machine-id, SSH host keys and SSH key. Each VM has its own
isolated user-mode network (reachable only through its forwarded port on 127.0.0.1), so this is harmless for
single-VM tests; it matters only for tests where several VMs talk to each other. The guest's random number
generator is reseeded on resume (vmgenid, virtio-rng).

## Memory and CPU

- Each VM runs in a `systemd-run --user --scope` unit with `MemoryMax` = RAM + 1 GiB and `MemoryHigh` = RAM + 512 MiB.
  Stopping the scope stops everything in it. `throwvm.py status` and `stats` read memory and CPU from the cgroup.
- A VM only starts when `MemAvailable` minus what running VMs may still grow into, minus its own limit, leaves a
  reserve free (4 GiB; `THROWVM_RESERVE_MB`). Otherwise it waits (up to 30 min), so parallel test runs queue
  instead of pushing the host into swap.

## Logs

The guest's journal is forwarded to its serial console, so `console.log` in the VM's directory shows what happened
even when SSH drops. `stop(failed=True)` / `down --failed` also saves `journalctl -b` as `journal.log` and keeps the
directory; only the disk overlay is deleted.

## Windows

`WindowsVM` / `up-windows` runs throwaway copies of a Windows golden image: a directory with `disk.qcow2`,
`vars.fd` (OVMF NVRAM vars) and `tpm/` (swtpm state), installed with OpenSSH Server accepting a key for an
administrator `tester` and auto-logon. It needs `ovmf` and `swtpm`. The snapshot is taken once the desktop is idle;
its RAM is a file that VMs map copy-on-write, so a 6 GiB Windows resumes in ~3 s. The snapshot holds the guest RAM
(with the auto-logon password) and is readable by you only. You need a Windows licence for every copy you run.

## Pinning a version in another project

Fetch a tagged `throwvm.py` and check it against a pinned sha256, so a project's test does not depend on anything
outside it:

```bash
THROWVM_VERSION=v0.1.0 THROWVM_SHA256=<sha256 of throwvm.py at that tag>
if [ -z "${THROWVM:-}" ]; then                         # THROWVM=/path/to/throwvm.py: use a local copy
    THROWVM="${XDG_CACHE_HOME:-$HOME/.cache}/throwvm/$THROWVM_VERSION/throwvm.py"
    if ! echo "$THROWVM_SHA256  $THROWVM" | sha256sum -c --status 2>/dev/null; then
        mkdir -p "$(dirname "$THROWVM")"
        curl -fsSL --retry 3 --max-time 60 -o "$THROWVM.new" \
            "https://raw.githubusercontent.com/delirious6423/throwvm/$THROWVM_VERSION/throwvm.py"
        echo "$THROWVM_SHA256  $THROWVM.new" | sha256sum -c --status || { echo "throwvm.py: checksum mismatch" >&2; exit 1; }
        mv "$THROWVM.new" "$THROWVM"
    fi
fi
python3 -I "$THROWVM" up ...
```

## Tests

```bash
python3 -I -m unittest discover -s tests -p 'test_*.py'   # offline, no VM started
```

## Licence

MIT, see `LICENSE`.
