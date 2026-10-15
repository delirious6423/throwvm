# Changelog

## v0.1.1

- `up-mac`: throwaway arm64 macOS or Ubuntu VMs on an Apple Silicon Mac over SSH, via Tart (e.g. the
  `ghcr.io/cirruslabs/macos-tahoe-base` and `ghcr.io/cirruslabs/ubuntu` images). Each VM is an APFS clone
  of a local Tart VM, so it starts in seconds and uses no disk until written. The key goes in through `tart exec`,
  with no password.
- `up-mac-windows`: throwaway copies of a Windows on Arm golden image, run by UTM.app's QEMU with Apple's
  hypervisor. throwvm compiles a small `qemu-launch` on the Mac, because UTM's own launcher only runs inside the
  app. The display is ramfb: Windows 11 26H2's boot manager draws straight to the framebuffer and hangs with
  virtio-gpu.
- Both are reached through the Mac (`ssh -J`) and stop when `--owner` exits. `down` deletes them.

## v0.1.0

- First release: Ubuntu 26.04 VMs and Windows golden images on Linux/KVM, with copy-on-write snapshots, a
  per-VM memory cap and cleanup when the owner process exits.
