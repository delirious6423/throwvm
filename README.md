# throwvm

Throwaway QEMU/KVM virtual machines for end-to-end tests, reachable over SSH in about a second.

<h1 align="center">🤡</h1>

## Read this first: you probably want an established tool

> [!CAUTION]
> **Built by Claude, an AI coding agent, without checking what already existed.**
>
> | | |
> |---|---|
> | ⏱️ **Time spent** | two days |
> | 📄 **Code written** | ~800 lines, plus four throwaway predecessors |
> | 🔍 **Prior-art search** | none, until the owner asked |
> | 🪞 **Self-review** | graded far more gently than anyone else's work, then recommended publishing it |
>
> Its owner noticed. This section is the result.

**Mature open source tools already do this job:**

| Tool | Use it if you want | Why it is probably better than throwvm |
|---|---|---|
| [Incus](https://linuxcontainers.org/incus/) | throwaway VMs and system containers with snapshots, cloud-init, limits, `exec` without SSH | a maintained project with a team, docs, an API and years of use |
| [openQA](https://open.qa/) | GUI testing in VMs by screenshot matching | what openSUSE and Fedora use to test whole desktops |
| [NixOS test driver](https://nixos.org/manual/nixos/stable/#sec-nixos-tests) | scripted multi-VM tests, OCR included | reproducible by design, widely used |
| libvirt + virt-install + guestfs-tools | the standard building blocks | everything above (and throwvm) reinvents parts of them |

What I got wrong, in the words I would use on someone else's pull request:

- **No prior-art search.** Ten minutes would have turned up Incus, which covers most of this file.
- **Unbenchmarked claims.** "SSH in about a second" is measured against throwvm's own earlier cold boot (~21 s),
  never against Incus stateful snapshots or anything else. It may or may not be faster than the alternatives.
- **"No root needed" was a weak argument.** It came from the sandbox I happened to run in, not from what tests need;
  installing QEMU needed root anyway, and so would a one-time install of Incus.
- **Fragility found late.** Resuming saved RAM only works on the same QEMU version and host CPU. I only noticed when
  asked to review the design; the snapshot key now includes both, and a failed resume rebuilds once.
- **Maintenance.** One owner who does not write code, so every fix depends on an AI agent. Judge accordingly.

Reasons you might still use it: a single standard-library Python file, no daemon, runs entirely as your user, and it
works today for the tests it was written for. If that fits, welcome; if not, use one of the tools above.

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

## Arm64 VMs on a Mac

On an Apple Silicon Mac you reach as `ssh HOST` (key login), throwvm runs VMs there and gives you SSH to them through
the Mac (`-J HOST`). No snapshots or cgroups: each VM is an APFS clone, so it starts in seconds and costs no disk
until written. `--owner` works as on Linux.

- `up-mac DIR --host imac --base BASE`: a [Tart](https://tart.run) VM (macOS or Linux) cloned from the local Tart
  VM `BASE`; the key goes in through Tart's guest agent (`tart exec`), so no password. Needs Tart on the Mac's PATH.
- `up-mac-windows DIR --host imac --golden DIR_ON_MAC --key KEY`: a copy of a Windows on Arm golden image
  (`disk.raw`, `vars.fd`, `code.fd` = Ubuntu's AAVMF firmware) run by the QEMU in UTM.app with Apple's hypervisor.
  UTM's own launcher only runs inside the app, so throwvm compiles a small `~/bin/qemu-launch` on the Mac and signs
  it for the hypervisor (needs the Xcode command line tools). The display is ramfb: Windows 11 26H2's boot manager
  draws straight to the framebuffer, which virtio-gpu lacks. Building the golden image is up to you (an unattended
  install, e.g. [dotfiles' vm/windows-arm](https://github.com/delirious6423/dotfiles/tree/main/vm/windows-arm)).

## Pinning a version in another project

Fetch a tagged `throwvm.py` and check it against a pinned sha256, so a project's test does not depend on anything
outside it:

```bash
THROWVM_VERSION=v0.1.0 THROWVM_SHA256=<sha256 of throwvm.py at that tag>
if [ -z "${THROWVM:-}" ]; then                         # THROWVM=/path/to/throwvm.py: use a local copy
    THROWVM="${XDG_CACHE_HOME:-$HOME/.cache}/throwvm/$THROWVM_VERSION/throwvm.py"
    if ! { [ -f "$THROWVM" ] && echo "$THROWVM_SHA256  $THROWVM" | sha256sum -c --status; }; then
        mkdir -p "$(dirname "$THROWVM")"
        new=$(mktemp "$THROWVM.XXXXXX")                 # parallel runs each download their own copy
        curl -fsSL --retry 3 --max-time 60 -o "$new" \
            "https://raw.githubusercontent.com/delirious6423/throwvm/$THROWVM_VERSION/throwvm.py"
        echo "$THROWVM_SHA256  $new" | sha256sum -c --status \
            || { echo "throwvm.py $THROWVM_VERSION: checksum mismatch" >&2; rm -f "$new"; exit 1; }
        mv "$new" "$THROWVM"
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
