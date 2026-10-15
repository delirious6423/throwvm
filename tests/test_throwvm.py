"""Offline tests for throwvm.py (no VM is started). Run: python3 -I -m unittest discover -s tests -p 'test_*.py'"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

LIB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LIB))
import throwvm  # noqa: E402

GIB = 2**30


class Headroom(unittest.TestCase):
    def test_counts_what_running_vms_may_still_grow_into(self):
        usage = {"a.scope": {"MemoryMax": 7 * GIB, "MemoryCurrent": 2 * GIB}}
        # 20 GiB free - 5 GiB the running VM may still take - 4 GiB new VM - 1 GiB reserve
        self.assertEqual(throwvm.headroom_mb(20 * 1024, usage, 4 * 1024, reserve_mb=1024), 10 * 1024)

    def test_refuses_when_short(self):
        self.assertLess(throwvm.headroom_mb(6 * 1024, {}, 4 * 1024, reserve_mb=4096), 0)

    def test_vm_over_its_max_counts_as_zero(self):
        usage = {"a.scope": {"MemoryMax": GIB, "MemoryCurrent": 2 * GIB}}
        self.assertEqual(throwvm.headroom_mb(10 * 1024, usage, 0, reserve_mb=0), 10 * 1024)

    def test_unlimited_scope_counts_as_zero(self):
        usage = {"a.scope": {"MemoryMax": None, "MemoryCurrent": GIB}}
        self.assertEqual(throwvm.headroom_mb(10 * 1024, usage, 0, reserve_mb=0), 10 * 1024)


class Guard(unittest.TestCase):
    def guard(self, owner, child):
        return subprocess.Popen([sys.executable, "-I", str(LIB / "throwvm.py"), "_guard", str(owner), "--", *child])

    def test_stops_child_when_owner_exits(self):
        owner = subprocess.Popen(["sleep", "30"])
        g = self.guard(owner.pid, ["sleep", "30"])
        time.sleep(0.5)
        owner.kill()
        owner.wait()
        self.assertEqual(g.wait(15), 128 + 15)  # child got SIGTERM

    def test_passes_child_exit_code(self):
        self.assertEqual(self.guard(0, ["sh", "-c", "exit 3"]).wait(15), 3)


class WindowsMachine(unittest.TestCase):
    def vm(self, d):
        return throwvm.WindowsVM(d, "/vms", "/golden", "/key", ssh_port=2224, vnc=24, acpi_tables=["/w/MSDM.bin"])

    def test_resume_maps_the_snapshot_ram_copy_on_write_and_keeps_it_unwritten(self):
        vm = self.vm("/data/run")
        vm.ssh_port = 2224
        argv = vm._qemu_argv("/data/run/disk.qcow2", "/data/run")
        self.assertIn("tcp:127.0.0.1:2224-:22", " ".join(argv))
        self.assertIn("file=/w/MSDM.bin", argv)
        self.assertIn("127.0.0.1:24", argv)
        # swtpm is started by the scope's wrapper, which then becomes QEMU
        wrapped = vm._scope_argv(argv, "/data/run")
        self.assertEqual(wrapped[:2], ["sh", "-c"])
        self.assertEqual(wrapped[-len(argv):], argv)

    def test_tpm_socket_path_fits_a_unix_socket(self):
        live = throwvm._tpm_live("/a/very/long/" + "x" * 200)
        self.assertLess(len(live + "/swtpm.sock"), 108)
        self.assertNotEqual(live, throwvm._tpm_live("/other"))

    def test_load_returns_the_windows_class(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as d:
            vm = self.vm(d)
            vm.ssh_port, vm.unit = 2224, "u.scope"
            vm._save()
            loaded = throwvm.VM.load(d)
            self.assertIsInstance(loaded, throwvm.WindowsVM)
            self.assertEqual((loaded.golden, loaded.key, loaded.unit), ("/golden", "/key", "u.scope"))
            # vm.json from before the kind field still loads as Ubuntu
            j = json.load(open(f"{d}/vm.json"))
            del j["kind"], j["golden"]
            json.dump(j, open(f"{d}/vm.json", "w"))
            self.assertIs(type(throwvm.VM.load(d)), throwvm.VM)


class MacMachines(unittest.TestCase):
    def test_load_round_trips_both_mac_kinds(self):
        with tempfile.TemporaryDirectory() as d:
            vm = throwvm.MacVM(d, "imac", "ubuntu-base", "/key")
            vm.ip = "192.168.64.5"
            vm._save()
            loaded = throwvm.VM.load(d)
            self.assertIs(type(loaded), throwvm.MacVM)
            self.assertEqual((loaded.host, loaded.base, loaded.key, loaded.user, loaded.ip, loaded.owner),
                             ("imac", "ubuntu-base", "/key", "admin", "192.168.64.5", 0))
            win = throwvm.MacWindowsVM(d, "imac", "VMs/windows-arm/golden", "/key", ssh_port=2240, vnc=40)
            win._save()
            loaded = throwvm.VM.load(d)
            self.assertIs(type(loaded), throwvm.MacWindowsVM)
            self.assertEqual((loaded.golden, loaded.ssh_port, loaded.vnc), ("VMs/windows-arm/golden", 2240, 40))

    def test_ssh_goes_through_the_mac(self):
        vm = throwvm.MacVM("/w/run1", "imac", "base", "/key")
        vm.ip = "192.168.64.5"
        argv = vm.ssh_argv()
        self.assertEqual(argv[argv.index("-J") + 1], "imac")
        self.assertEqual(argv[-1], "admin@192.168.64.5")
        self.assertEqual(vm.vm, "throwvm-run1")
        win = throwvm.MacWindowsVM("/w/run1", "imac", "g", "/key", ssh_port=2240).ssh_argv()
        self.assertEqual(win[-3:], ["-p", "2240", "tester@127.0.0.1"])

    def test_windows_boots_from_its_own_firmware_copy_with_a_linear_framebuffer(self):
        args = throwvm.MacWindowsVM("/w/run1", "imac", "g", "/key", ssh_port=2240).qemu_args()
        r = "VMs/throwvm/throwvm-run1"
        self.assertIn(f"if=pflash,format=raw,readonly=on,file={r}/code.fd", args)
        self.assertIn(f"if=pflash,format=raw,file={r}/vars.fd", args)
        # Windows 11 26H2's boot manager writes to the framebuffer directly; virtio-gpu has none
        self.assertIn("ramfb", args)
        self.assertNotIn("virtio-gpu-pci", args)
        self.assertIn("user,id=n0,hostfwd=tcp:127.0.0.1:2240-:22", args)
        self.assertNotIn("-vnc", args)
        for a in args:   # boot() wraps each argument in double quotes for the Mac's shell
            self.assertFalse(set(a) & set('"`\\'), a)

    def test_stop_deletes_the_copy_and_keeps_the_log_on_failure(self):
        vm = throwvm.MacVM("/w/run1", "imac", "base", "/key")
        with mock.patch.object(vm, "mac") as mac:
            vm.stop()
        self.assertIn("tart stop throwvm-run1", mac.call_args[0][0])
        self.assertIn("tart delete throwvm-run1", mac.call_args[0][0])
        win = throwvm.MacWindowsVM("/w/run1", "imac", "g", "/key")
        with mock.patch.object(win, "mac") as mac, mock.patch.object(win, "monitor"):
            win.stop(failed=True)
        self.assertIn("rm -f VMs/throwvm/throwvm-run1/disk.raw", mac.call_args[0][0])
        self.assertNotIn("rm -rf", mac.call_args[0][0])


class SnapshotKey(unittest.TestCase):
    def kind(self, identity):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(throwvm, "host_identity", return_value=identity):
            Path(d, "SHA256SUMS").write_text(f"abc *{throwvm.IMG}\n")
            vm = throwvm.VM(d, d)
            vm.image = os.path.join(d, throwvm.IMG)
            return vm._kind()

    def test_qemu_version_and_host_cpu_are_part_of_the_key(self):
        a = self.kind(["QEMU emulator version 10.2.1", "CPU A", "flags1"])
        self.assertNotEqual(a, self.kind(["QEMU emulator version 10.3.0", "CPU A", "flags1"]))
        self.assertNotEqual(a, self.kind(["QEMU emulator version 10.2.1", "CPU B", "flags1"]))
        self.assertNotEqual(a, self.kind(["QEMU emulator version 10.2.1", "CPU A", "flags2"]))
        self.assertEqual(a, self.kind(["QEMU emulator version 10.2.1", "CPU A", "flags1"]))

    def test_host_identity_reads_this_host(self):
        qemu, model, flags = throwvm.host_identity()
        self.assertIn("QEMU", qemu)
        self.assertTrue(model and len(flags) == 16)


class FakeVM(throwvm.VM):
    """Snapshots are directories with a state file; resuming fails while resume_failures > 0."""

    def __init__(self, d):
        super().__init__(os.path.join(d, "work"), d, name="t", owner=0)
        self.made_count, self.resume_failures, self.resumed = 0, 0, []

    def _base(self, timeout):
        return self._layer("base", ["k"], "test", self._prepare, lambda tmp: None, timeout)

    def _prepare(self, tmp, timeout):
        self.made_count += 1

    def _save_state(self, d, path):
        Path(path).write_text("state")

    def _stop_unit(self):
        pass

    def _resume_in(self, snap, d, timeout):
        if self.resume_failures:
            self.resume_failures -= 1
            raise RuntimeError("load of migration failed")
        self.resumed.append(snap)


class ResumeFallback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def vm(self):
        return FakeVM(self.tmp.name)

    def test_old_snapshot_that_fails_to_resume_is_made_again_once(self):
        self.vm()._base(10)                       # made by an earlier run
        vm = self.vm()
        vm.resume_failures = 1
        snap = vm._resume_copy(lambda: vm._base(10), vm.dir, 10)
        self.assertEqual(vm.made_count, 1)        # discarded and made again
        self.assertEqual(vm.resumed, [snap])
        self.assertTrue(os.path.exists(os.path.join(snap, "state")))

    def test_gives_up_when_the_new_snapshot_fails_too(self):
        self.vm()._base(10)
        vm = self.vm()
        vm.resume_failures = 2
        with self.assertRaises(RuntimeError):
            vm._resume_copy(lambda: vm._base(10), vm.dir, 10)
        self.assertEqual(vm.made_count, 1)

    def test_snapshot_made_by_this_run_is_not_made_twice(self):
        vm = self.vm()
        vm.resume_failures = 1
        with self.assertRaises(RuntimeError):
            vm._resume_copy(lambda: vm._base(10), vm.dir, 10)
        self.assertEqual(vm.made_count, 1)


class MaxAge(unittest.TestCase):
    def test_layer_older_than_max_age_is_made_again(self):
        with tempfile.TemporaryDirectory() as d:
            vm = FakeVM(d)
            layer = lambda age: vm._layer("p", ["k"], "test", vm._prepare, lambda tmp: None, 10, max_age_s=age)
            snap = layer(86400)
            old = time.time() - 2 * 86400
            os.utime(os.path.join(snap, "state"), (old, old))
            layer(None)                           # no max age: kept
            self.assertEqual(vm.made_count, 1)
            layer(86400)                          # older than a day: made again
            self.assertEqual(vm.made_count, 2)
            layer(86400)                          # fresh again
            self.assertEqual(vm.made_count, 2)


if __name__ == "__main__":
    unittest.main()
