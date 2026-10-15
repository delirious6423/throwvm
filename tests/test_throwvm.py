"""Offline tests for lib/throwvm.py (no VM is started). Run: python3 -I -m unittest discover -s tests -p 'test_*.py'"""
import subprocess
import sys
import time
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parent.parent / "lib"
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


if __name__ == "__main__":
    unittest.main()
