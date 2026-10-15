"""Offline tests for throwvm.py (no VM is started). Run: python3 -I -m unittest discover -s tests -p 'test_*.py'"""
import subprocess
import sys
import time
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
