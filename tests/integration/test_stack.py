"""Run the two lifted entry contracts on Apple Silicon, including isolated runtime traps."""
from pathlib import Path
import json
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import unittest

FORGE, IMAGE, OPT, LLC, HARNESS, STATE_HARNESS, *LINKER = sys.argv[1:]
BASE = 0x70000000
TOP = BASE + 4096
RSP = TOP - 40
MASK = (1 << 64) - 1


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=30, **kwargs).stdout


class StackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.work = Path(directory.name)
        report = json.loads(run(FORGE, "inspect", IMAGE, "--format", "json"))
        cls.exports = {name: int(row["rva"], 16) for row in report["modules"][0]["exports"] for name in row["names"]}

    def variants(self, name, *, state=False):
        rva = self.exports[name]
        ir = self.work / f"{name}.ll"
        signature = [] if state else ["--signature", "i64(i64,i64)"]
        run(FORGE, "lift", IMAGE, "--rva", hex(rva), "--output", ir, *signature)
        if state:
            # A test-local forwarding entry can call the retained internal LLVM symbol.
            with ir.open("a") as out:
                out.write(f"\ndefine void @probe(ptr %p) {{\n  call void @forge_lifted_{rva:x}(ptr %p)\n  ret void\n}}\n")
        optimized = self.work / f"{name}.o2.ll"
        run(OPT, "-passes=verify", "-disable-output", ir)
        run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
        run(OPT, "-passes=verify", "-disable-output", optimized)
        for source in (ir, optimized):
            obj, exe = source.with_suffix(".o"), source.with_suffix(".exe")
            run(LLC, "-filetype=obj", source, "-o", obj)
            run(*LINKER, STATE_HARNESS if state else HARNESS, obj, "-o", exe)
            yield exe

    def expect(self, exe, a, b, value):
        output = run(exe, input=f"{a & MASK:x} {b & MASK:x}\n".encode())
        self.assertEqual(output, f"{value & MASK:x}\n".encode(), (exe.name, a, b))

    def trap(self, exe, pairs):
        data = "".join(f"{a & MASK:x} {b & MASK:x}\n" for a, b in pairs).encode()
        child = subprocess.run([exe], input=data, capture_output=True, timeout=15)
        self.assertEqual(child.returncode, -signal.SIGTRAP, (exe.name, pairs, child.stderr))

    def test_boundaries(self):
        value = 0x876543210fedcba9
        for width, suffix in ((1, "b"), (2, "w"), (4, "l"), (8, "q")):
            for exe in self.variants("access_" + suffix):
                for address in (BASE, BASE + 1, RSP - width, RSP + 8, TOP - width):
                    self.expect(exe, address, value, value % (1 << (width * 8)))
                for address in (BASE - 1, TOP - width + 1, RSP - width + 1, RSP + 7, MASK):
                    self.trap(exe, [(address, value)])

    def test_reads_and_lifetime(self):
        for exe in self.variants("checked_read"):
            self.expect(exe, RSP + 8, 73, 73)
            for address in (RSP + 9, BASE, BASE - 1, TOP - 7, RSP - 7, RSP + 7):
                self.trap(exe, [(address, 73)])
        for exe in self.variants("conditional_read"):
            self.expect(exe, 1, 17, 0x1111)
            self.trap(exe, [(0, 31)])
            self.trap(exe, [(1, 17), (0, 31)])
        for exe in self.variants("entry_memory_loop"):
            self.expect(exe, 1, 92, 92)
            self.trap(exe, [(0, 7)])

    def test_rsp_and_address_arithmetic(self):
        for exe in self.variants("shifted_rsp"):
            self.expect(exe, 0, 81, 81)
            self.trap(exe, [(16, 81)])
        for exe in self.variants("restore_rsp"):
            self.expect(exe, -97, 0, -97)
        for exe in self.variants("moved_rsp_slot"):
            self.expect(exe, 0, 88, 88)
            self.trap(exe, [(16, 88)])
        for exe in self.variants("wrap_index"):
            self.expect(exe, 1 << 61, 123, 123)
            self.trap(exe, [(-1, 123)])
        for exe in self.variants("parallel_memory_edges"):
            self.expect(exe, 1, 4, 6)
            self.expect(exe, 4, 4, 8)
        for exe in self.variants("store_immediates"):
            self.expect(exe, 0, 0, 0xffff12347878ffff)

    def test_register_state(self):
        exposed = ("ax", "cx", "dx", "r8", "r9", "r10", "r11")
        private = ("sp", "bp", "bx", "si", "di", "r12", "r13", "r14", "r15")
        for parent in (*exposed, *private, "high_bytes"):
            name = parent if parent == "high_bytes" else "alias_" + parent
            for exe in self.variants(name, state=True):
                expected = b""
                for invocation in range(2):
                    slots = [0xabcdef0123456000 + invocation * 0x1000 + i * 0x101 for i in range(7)]
                    if parent == "high_bytes":
                        slots[6] = ((slots[2] >> 8 & 255) << 8) | (slots[1] >> 8 & 255)
                        slots[0] = 0x76540010 | (slots[0] & 0xff00)
                    else:
                        if parent in exposed:
                            slots[exposed.index(parent)] = 0x87654321
                        slots[3] = 0x123456789abccd21
                        slots[4] = 0x87654321
                    expected += struct.pack("<I7QI", 0x01234567, *slots, 0x89abcdef)
                self.assertEqual(run(exe), expected, exe.name)


if __name__ == "__main__":
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        sys.exit(77)
    unittest.main(argv=[sys.argv[0]])
