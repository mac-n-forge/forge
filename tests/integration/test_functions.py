"""Exercise discovery and lift diagnostics through their CLI entry points."""
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import sys
import unicodedata
import unittest

from cli_case import Case, FIXTURES, SUITE
from pe_layout import Layout


class Discovery(Case):
    def analyze(self, image, *args, code=0):
        p = self.invoke("analyze", image, "--functions", "--format", "json", *args, code=code)
        return json.loads(p.stdout)

    def test_metadata_and_gaps(self):
        # Missing imports leave root-only analysis usable.
        image = self.copy("metadata.exe")
        r = self.analyze(image, "--strict")
        f, = r["functions"]
        self.assertTrue(f["contains_tls_callback"] and f["contains_entry_point"])
        self.assertEqual((f["size"], f["source"], f["status"]), (9, "exception_directory", "valid"))
        self.assertEqual(r["unknown_executable_ranges"], [])
        self.assertEqual(self.invoke("analyze", image, "--functions", "--strict").stdout,
                         b"Functions (1), source: PE exception directory\n"
                         b"  0x1000..0x1009 (9 bytes) unwind 0x210c valid records 0 entry TLS callback\n")
        r = self.analyze(FIXTURES / "minimal.exe", "--strict")
        self.assertEqual(r["functions"], [])
        self.assertEqual(r["unknown_executable_ranges"], [{"start_rva": "0x1000", "end_rva": "0x1001"}])
        self.assertNotIn("name", self.analyze(FIXTURES / "arithmetic.exe")["functions"][0])

    def test_dwarf_and_section_alignment(self):
        exe = FIXTURES / "add.exe"
        f, = self.analyze(exe)["functions"]
        self.assertEqual(f["name"], "entry")
        self.assertEqual(f["location"]["file"].split("/")[-1], "add.c")
        self.assertGreater(f["location"]["line"], 0)
        lines = self.invoke("inspect", exe).stdout.decode().splitlines()
        column, = [line.index("RVA") for line in lines if "Permissions" in line]
        rows = [line for line in lines if line.startswith("    .")]
        self.assertTrue(any(".debug_abbrev" in row for row in rows))
        self.assertTrue(all(row.index("0x") == column for row in rows))

    def test_enclosing_dwarf_function(self):
        f, = self.analyze(FIXTURES / "inlined.exe", "--strict")["functions"]
        self.assertEqual(f["name"], "entry")
        self.assertEqual(f["location"]["file"].split("/")[-1], "inlined.c")
        source = Path(__file__).resolve().parents[1] / "fixtures/inlined.c"
        call_line, = (i for i, line in enumerate(source.read_text().splitlines(), 1)
                      if "return step(a) + b;" in line)
        self.assertEqual(f["location"]["line"], call_line)

    def test_unicode_section_columns(self):
        image = FIXTURES / "unicode.exe"
        for flags in ((), ("--verbose",)):
            lines = self.invoke("inspect", image, *flags).stdout.decode().splitlines()
            column, = [line.index("RVA") for line in lines if "Permissions" in line]
            for section in (".donnée", ".界区"):
                row, = [line for line in lines if line.lstrip().startswith(section)]
                prefix = row[:row.index("0x")]
                self.assertEqual(sum(2 if unicodedata.east_asian_width(c) == "W" else 1
                                     for c in prefix), column)
        self.assertEqual(self.invoke("inspect", image, "--format", "json").stdout,
                         self.invoke("inspect", image, "--format", "json", "--verbose").stdout)

    def test_chained_fragment_and_gap(self):
        image = FIXTURES / "chained.exe"
        oracle = self.readobj("chained.exe", "--unwind")
        self.assertIn("ChainInfo (0x4)", oracle)
        self.assertIn("Chained {\n        StartAddress: (0x140001000)", oracle)
        a = self.analyze(image, "--strict")
        primary, fragment, unrelated = a["functions"]
        self.assertTrue(primary["liftable"] and unrelated["liftable"])
        self.assertEqual((fragment["start_rva"], fragment["chained_fragment"], fragment["status"],
                          fragment["liftable"]), ("0x1010", True, "valid", False))
        self.assertEqual(a["diagnostics"], [])
        self.assertEqual(a["unknown_executable_ranges"],
                         [{"start_rva": primary["end_rva"], "end_rva": fragment["start_rva"]}])
        self.assertIn(b"chained fragment", self.invoke("analyze", image, "--functions").stdout)
        output = self.dir / "function.ll"
        for signature in ((), ("--signature", "i64(i64,i64)")):
            p = self.invoke("lift", image, "--rva", fragment["start_rva"], "--output", output,
                            *signature, code=1)
            self.assertIn(b"0x1010: chained unwind fragment", p.stderr)
            self.assertFalse(output.exists())
        self.invoke("lift", image, "--rva", unrelated["start_rva"], "--output", output)

        data = bytearray(image.read_bytes())
        layout = Layout(data)
        table = layout.file_offset(layout.directory(3)[0])
        struct.pack_into("<I", data, table+12, int(primary["end_rva"], 16)-1)
        image = self.dir / "overlap.exe"
        image.write_bytes(data)
        rows = self.analyze(image, "--strict", code=3)["functions"]
        self.assertEqual([row["status"] for row in rows], ["conflicting", "conflicting", "valid"])
        self.assertTrue(rows[1]["chained_fragment"])

    def test_unwind_header_and_trailer(self):
        original = FIXTURES / "chained.exe"
        fragment = self.analyze(original)["functions"][1]
        data = bytearray(original.read_bytes())
        offset = Layout(data).file_offset(int(fragment["unwind_rva"], 16))
        image = self.dir / "unwind.exe"
        output = self.dir / "fragment.ll"
        for version_flags, slots, status, exit_code, reason in [
                (0x22, 0, "valid", 0, None),       # version 2 chained header
                (0x27, 0, "unsupported", 0, None),
                (0x21, 1, "invalid", 3, "truncated chained runtime function"),
                (0x29, 0, "invalid", 3, "also declares a handler")]:
            with self.subTest(version_flags=version_flags, slots=slots):
                data[offset] = version_flags
                data[offset+2] = slots
                image.write_bytes(data)
                a = self.analyze(image, "--strict", code=exit_code)
                row = a["functions"][1]
                self.assertEqual((row["status"], row["liftable"]), (status, False))
                if reason:
                    self.assertIn(reason, a["diagnostics"][0]["message"])
                if status == "unsupported":
                    self.assertEqual(row["unwind_version"], 7)
                    p = self.invoke("lift", image, "--rva", row["start_rva"], "--output", output, code=1)
                    self.assertIn(b"unsupported unwind version 7", p.stderr)
                self.invoke("inspect", image, "--strict")

    def test_recover_readable_conflicts(self):
        data = bytearray((FIXTURES / "arithmetic.exe").read_bytes())
        info = Layout(data)
        table, size = info.directory(3)
        offset = info.file_offset(table)
        first, second, third = [struct.unpack_from("<III", data, offset + 12*i) for i in range(3)]
        for kind, record in [
            ("partial", (first[1]-1, second[1], second[2])),
            ("nested", (first[0]+1, first[1], second[2])),
            ("equal_conflict", (*first[:2], second[2])),
            ("duplicate", first)]:
            with self.subTest(kind=kind):
                # Original indices deliberately differ from RVA order.
                struct.pack_into("<III", data, offset, *third)
                struct.pack_into("<III", data, offset+12, *record)
                struct.pack_into("<III", data, offset+24, *first)
                image = self.dir / "records.exe"
                image.write_bytes(data)
                code = 0 if kind == "duplicate" else 3
                a = self.analyze(image, "--strict", code=code)
                self.assertEqual(a, self.analyze(image))
                functions = a["functions"]
                self.assertEqual([int(f["start_rva"],16) for f in functions],
                                 sorted(int(f["start_rva"],16) for f in functions))
                if kind == "duplicate":
                    self.assertEqual(functions[0]["record_indices"], [1, 2])
                    self.assertTrue(functions[0]["liftable"])
                    self.assertFalse(a["diagnostics"])
                else:
                    self.assertEqual([f["status"] for f in functions[:2]], ["conflicting"]*2)
                    self.assertFalse(any(f["liftable"] for f in functions[:2]))
                    self.assertCountEqual(a["diagnostics"][0]["record_indices"], [1, 2])
                    self.assertEqual(a["diagnostics"][0]["code"], "FUNCTION_RANGE_OVERLAP")
                    args = ("lift", image, "--rva", hex(first[0]), "--output", self.dir/"bad.ll")
                    self.assertIn(b"expected an exact, valid, unambiguous", self.invoke(*args, code=1).stderr)
                    diagnostic = json.loads(self.invoke(*args, "--diagnostics-format", "json", code=1).stderr)
                    self.assertEqual(diagnostic["code"], "ENTRY_INVALID_START")
                    self.assertEqual(diagnostic["context"], dict(input=str(image), entry_rva=hex(first[0]), signature="register-state"))
                self.invoke("lift", image, "--rva", hex(third[0]), "--output", self.dir/"ok.ll")
                self.assertTrue(all(f["status"] == "valid" for f in functions if int(f["start_rva"],16) >= third[0]))

    def test_exact_range_diagnostics(self):
        original = (FIXTURES / "add.exe").read_bytes()
        layout = Layout(original)
        off = layout.file_offset(layout.directory(3)[0])
        start, end, unwind = struct.unpack_from("<III", original, off)
        image = self.dir / "entry.exe"
        output = self.dir / "entry.ll"
        for requested, stop, code in (
                (start + 1, end, "ENTRY_INVALID_START"),
                (start, start, "ENTRY_INVALID_START"),
                (start, end + 0x100, "ENTRY_UNMAPPED_CODE")):
            with self.subTest(requested=requested, end=stop):
                data = bytearray(original)
                struct.pack_into("<III", data, off, start, stop, unwind)
                image.write_bytes(data)
                args = ("lift", image, "--rva", hex(requested), "--output", output)
                reason = "expected an exact, valid, unambiguous discovered function start"
                self.assertEqual(self.invoke(*args, code=1).stderr,
                                 f"{image}: LIFT_ERROR: {requested:#x}: {reason}\n".encode())
                failure = json.loads(self.invoke(*args, "--diagnostics-format", "json", code=1).stderr)
                context = dict(input=str(image), entry_rva=hex(requested), signature="register-state")
                if code == "ENTRY_UNMAPPED_CODE":
                    context["end_rva"] = hex(stop)
                self.assertEqual((failure["category"], failure["code"], failure["context"]),
                                 ("invalid_input", code, context))
                self.assertFalse(output.exists())

    def test_empty_range_at_valid_start(self):
        data = bytearray((FIXTURES / "arithmetic.exe").read_bytes())
        info = Layout(data)
        off = info.file_offset(info.directory(3)[0])
        begin, end, unwind = struct.unpack_from("<III", data, off)
        struct.pack_into("<III", data, off+12, begin, begin, unwind)
        image = self.dir/"empty.exe"
        image.write_bytes(data)
        rows = self.analyze(image, "--strict", code=3)["functions"][:2]
        self.assertEqual([(f["status"], f["liftable"]) for f in rows],
                         [("invalid", False), ("valid", True)])
        self.invoke("lift", image, "--rva", hex(begin), "--output", self.dir/"ok.ll")

    def test_bad_dwarf_is_optional(self):
        image = FIXTURES/"add.exe"
        data = bytearray(image.read_bytes())
        debug = next(s for s in self.report(image)["modules"][0]["sections"] if s["name"] == ".debug_info")
        struct.pack_into("<I", data, debug["file_offset"], 0xfffffff1)
        image = self.dir/"bad-debug.exe"
        image.write_bytes(data)
        f, = self.analyze(image, "--strict")["functions"]
        self.assertTrue(f["liftable"])
        self.assertNotIn("name", f)

    def test_invalid_and_partial(self):
        original = (FIXTURES / "arithmetic.exe").read_bytes()
        info = Layout(original)
        table, size = info.directory(3)
        off = info.file_offset(table)
        for begin, end, unwind in [(0x1000, 0x1000, 0), (0x1008, 0x1000, 0),
                                   (0x2000, 0x2008, 0x2000), (0xfffffff0, 0xffffffff, 0),
                                   (0x1000, 0x1007, 0x7001), (0x1000, 0x1007, 0x8000)]:
            data = bytearray(original)
            struct.pack_into("<III", data, off, begin, end, unwind)
            image = self.dir/"invalid.exe"
            image.write_bytes(data)
            a = self.analyze(image, "--strict", code=3)
            f, = [f for f in a["functions"] if f["record_indices"] == [0]]
            self.assertEqual((f["status"], f["liftable"]), ("invalid", False))
            self.assertEqual(f["size"], end-begin if end >= begin else None)
            self.assertEqual(len(a["functions"]), size//12)
        data = bytearray(original)
        struct.pack_into("<I", data, info.directories + 3*8 + 4, size-1)
        image.write_bytes(data)
        a = self.analyze(image, "--strict", code=3)
        self.assertEqual(a["diagnostics"][0]["record_indices"], [size//12 - 1])
        self.assertEqual(len(a["functions"]), size//12-1)
        self.assertEqual(a["diagnostics"][0]["code"], "PARTIAL_RUNTIME_FUNCTION")
        self.invoke("inspect", image, code=1)
        struct.pack_into("<I", data, info.directories + 3*8, 0xfffffff0)
        image.write_bytes(data)
        self.assertEqual(self.invoke("analyze", image, "--functions", code=1).stdout, b"")


class Lift(Case):
    def test_signatureless_state_alignment(self):
        output = self.dir / "state.ll"
        self.invoke("lift", FIXTURES / "arithmetic.exe", "--rva", "0x1000", "--output", output)
        module = output.read_text()
        self.assertIn('target triple = "arm64-apple-macosx11.0.0"', module)
        for instruction in ("load i64", "store i64"):
            accesses = [line for line in module.splitlines() if instruction in line]
            self.assertTrue(accesses, instruction)
            for line in accesses:
                self.assertIn(", align 4", line)

    def test_usage_and_invalid_rva(self):
        exe = FIXTURES / "arithmetic.exe"
        output = self.dir/"existing.ll"
        output.write_text("keep me")
        # The uncovered leaf is the last byte of .text.
        text = next(s for s in self.report(exe)["modules"][0]["sections"] if s["name"] == ".text")
        leaf = int(text["rva"], 16) + text["virtual_size"] - 1
        for rva in ("0x1001", hex(leaf), "0x2000", "0xffffffff"):
            p = self.invoke("lift", exe, "--rva", rva, "--output", output, code=1)
            self.assertIn(b"exact, valid", p.stderr)
        for args in [("--rva", "0x100000000"), ("--rva", "-1"), ("--rva", "0x12z"),
                     ("--signature", "i32()"), ("--rva", "0x"), ("--strict",)]:
            self.invoke("lift", exe, *args, "--output", output, code=2)
        self.invoke("analyze", exe, code=2)
        self.invoke("lift", FIXTURES/"Physics.DLL", "--rva", "0x1000", "--output", output, code=1)
        fifo = self.dir/"pipe"
        os.mkfifo(fifo)
        self.invoke("lift", fifo, "--rva", "0", "--output", output, code=1)
        self.assertEqual(output.read_text(), "keep me")

    def test_json_diagnostics(self):
        good = FIXTURES / "add.exe"
        corrupt = self.dir / "malformed.exe"
        corrupt.write_bytes(b"not a PE")
        missing = self.dir / "missing.exe"
        output = self.dir / "result.ll"
        invalid_output = self.dir / "absent" / "result.ll"
        unsupported = self.copy("arithmetic.exe", 'encoded "name".exe')
        data = bytearray(unsupported.read_bytes())
        offset = Layout(data).file_offset(0x1000)
        # The first MOV is accepted. Memory-source PUSH at the next instruction is unsupported.
        data[offset:offset + 7] = bytes.fromhex("48 89 c8 ff 31 c3 cc")
        unsupported.write_bytes(data)

        for image, dest, start, expected in (
            (corrupt, output, "0x1000", ("pe", "invalid_input", "INVALID_PE")),
            (missing, output, "0x1000", ("input", "io", "INPUT_OPEN")),
            (FIXTURES / "i386.exe", output, "0x1000", ("pe", "unsupported", "UNSUPPORTED_ARCHITECTURE")),
            (good, output, "0x1001", ("entry", "invalid_input", "ENTRY_INVALID_START")),
            (unsupported, output, "0x1000", ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION")),
            (good, invalid_output, "0x1000", ("publication", "io", "OUTPUT_CREATE")),
        ):
            with self.subTest(code=expected[-1]):
                args = ("lift", image, "--rva", start, "--output", dest)
                result = self.invoke(*args, "--diagnostics-format", "json", code=1)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr.endswith(b"\n"))
                self.assertEqual(result.stderr.count(b"\n"), 1)
                doc = json.loads(result.stderr.decode("utf-8"))
                self.assertEqual(set(doc), {"schema_version", "stage", "category", "code", "message", "context"})
                self.assertIs(type(doc["schema_version"]), int)
                self.assertEqual(doc["schema_version"], 1)
                self.assertTrue(doc["message"])
                self.assertEqual((doc["stage"], doc["category"], doc["code"]), expected)
                context = doc["context"]
                self.assertEqual((context["input"], context["entry_rva"]), (str(image), start))
                if image == unsupported:
                    self.assertEqual((context["instruction_rva"], context["end_rva"], context["bytes"]),
                                     ("0x1003", "0x1007", "ff31"))
                    self.assertIn("PUSH", context["opcode"])
                if image.name == "i386.exe":
                    self.assertEqual(context["architecture"], "i386")
                if expected[0] == "publication":
                    self.assertEqual(context["output"], str(dest))
                self.assertEqual(self.invoke(*args, code=1).stderr,
                                 self.invoke(*args, "--diagnostics-format", "text", code=1).stderr)
                self.assertFalse(dest.exists())

        result = self.invoke("lift", good, "--rva", "0x1000", "--output", output,
                             "--diagnostics-format", "json")
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertIn("forge_lifted_1000", output.read_text())

    def test_json_usage_and_output_aliases(self):
        image = self.copy("add.exe")
        before = image.read_bytes()
        hard = self.dir / "hard"
        os.link(image, hard)
        sym = self.dir / "sym"
        sym.symlink_to(image)
        for alias in (image, hard, sym):
            args = ("lift", image, "--rva", "0x1001", "--output", alias)
            default = self.invoke(*args, code=2)
            requested = self.invoke(*args, "--diagnostics-format", "json", code=2)
            self.assertEqual(requested.stderr, default.stderr)
            self.assertTrue(requested.stderr.startswith(b"forge: --output must differ"))
            self.assertEqual(alias.read_bytes(), before)
        for args in (("lift", "--diagnostics-format", "JSON"),
                     ("lift", "--diagnostics-format", "json", "--rva", "bad"),
                     ("lift", "--diagnostics-format"),
                     ("inspect", image, "--diagnostics-format", "json"),
                     ("analyze", image, "--functions", "--diagnostics-format", "json")):
            result = self.invoke(*args, code=2)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr.startswith(b"forge: "))
            self.assertIn(b"Usage: forge", result.stderr)

    def test_reject_unsupported_and_unproven(self):
        original = (FIXTURES / "arithmetic.exe").read_bytes()
        info = Layout(original)
        offset = info.file_offset(0x1000)
        output = self.dir/"existing.ll"
        output.write_text("sentinel")
        for code, expected in [
                ("88 c8 c3", "undefined RAX"), ("66 89 c8 c3", "undefined RAX"), ("48 03 01 c3", "operand form"),
                ("48 8b 45 00 c3", "undefined incoming RBP"), ("48 8d 05 00 00 00 00", "RIP"),
                ("f3 c3", "prefix"), ("48 48 89 c8 c3", "prefix"),
                ("ff d0 c3", "unsupported"), ("ff e0", "unsupported"),
                ("b8 01 00 00 00 31 c0", "outside"), ("eb 05", "outside"), ("74 01 48 89 c8 c3", "enters an instruction"),
                ("75 02 31 c0 c3", "flags"), ("e8 00 00 00 00", "unsupported"),
                ("4c 89 c0 c3", "undefined incoming R8"), ("c3", "undefined RAX"),
                ("48 29 c8 c3", "undefined incoming RAX"), ("44 29 c1 c3", "undefined incoming R8"),
                ("48 39 d1 74 01 c3 c3", "undefined RAX"),
                ("09 c0 c3", "undefined incoming RAX"), ("f7 f1 c3", "unsupported"),
                ("48 19 c0 c3", "condition flags: CF"), ("39 c0 18 c0 c3", "undefined RAX"),
                ("39 c0 c3", "undefined RAX"), ("38 e0 c3", "undefined incoming RAX"),
                ("39 c0 18 e0 c3", "undefined incoming RAX"),
                ("31 c0 9f c3", "AF"), ("0f af ca 0f 94 c0 c3", "ZF"),
                ("66 66 89 c8 c3", "prefix"), ("14 00 c3", "undefined incoming RAX"),
                ("39 d1 0f 94 c0 c3", "undefined RAX"), ("c0 e9 08 0f 92 c0", "CF"),
                ("83 d1 00 c3", "CF"), ("d2 e1 0f 90 c0 c3", "OF"), ("48 89 c8 48 89 c8 40", "invalid or truncated"),
                ("31 c0 31 c0 31 c0 90", "unsupported")]:
            with self.subTest(code=code):
                body = bytes.fromhex(code)
                self.assertLessEqual(len(body), 7)
                data = bytearray(original)
                data[offset:offset+7] = body.ljust(7, b"\xcc")
                image = self.dir/"changed.exe"
                image.write_bytes(data)
                p = self.invoke("lift", image, "--rva", "0x1000", "--signature", "i64(i64,i64)",
                                "--output", output, code=1)
                self.assertIn(expected.encode(), p.stderr)
                self.assertIn(b"LIFT_ERROR: 0x100", p.stderr)
                self.assertEqual(output.read_text(), "sentinel")
        self.assertFalse(list(self.dir.glob("*.tmp-*")))

    def test_cyclic_state_and_reachability(self):
        original = (FIXTURES / "cfg.exe").read_bytes()
        layout = Layout(original)
        record = layout.file_offset(layout.directory(3)[0])
        entry = 0x1000
        image, output = self.dir / "graph.exe", self.dir / "graph.ll"

        def lift(code, failure=None, reason=None, category="unsupported"):
            body = bytes.fromhex(code)
            data = bytearray(original)
            pos = layout.file_offset(entry)
            data[pos:pos + len(body)] = body
            struct.pack_into("<I", data, record + 4, entry + len(body))
            image.write_bytes(data)
            args = ("lift", image, "--rva", hex(entry), "--signature", "i64(i64,i64)",
                    "--diagnostics-format", "json", "--output", output)
            if failure:
                output.write_text("previous IR")
            result = self.invoke(*args, code=1 if failure else 0)
            if failure:
                diagnostic = json.loads(result.stderr)
                self.assertEqual((diagnostic["stage"], diagnostic["category"], diagnostic["code"]),
                                 ("lifting", category, failure))
                if reason:
                    self.assertTrue(diagnostic["message"].endswith(reason), diagnostic)
                context = diagnostic["context"]
                self.assertEqual((context["signature"], context["entry_rva"], context["input"]),
                                 ("i64(i64,i64)", hex(entry), str(image)))
                self.assertLessEqual(int(context["block_rva"], 16), int(context["instruction_rva"], 16))
                self.assertEqual(output.read_text(), "previous IR")
                return context
            return output.read_text()

        # A skipped prefix does not impose another instruction interpretation.
        for code in ("eb 01 48 89 c8 c3", "89 c8 c3 0f", "eb fe", "e9 fb ff ff ff",
                     "ff c9 0f 85 f8 ff ff ff 89 c8 c3", "ff c9 75 fc 89 c8 c3",
                     "39 d1 74 00 0f 94 c0 0f b6 c0 c3"):
            with self.subTest(code=code):
                lift(code)

        lift("68 ff ff", "LIFT_INVALID_ENCODING", category="invalid_input")

        # The RIZ spelling in a SIB with a redundant scale has no index.
        lift("48 89 4c 64 08 48 8b 44 64 08 c3")
        lift("48 89 e0 c3")
        for code, failure in (
                ("66 50 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("66 c9 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("8f 01 c3", "LIFT_UNSUPPORTED_INSTRUCTION"),
                ("c2 08 00", "LIFT_UNSUPPORTED_CONTROL_FLOW"),
                ("cb", "LIFT_UNSUPPORTED_CONTROL_FLOW"),
                ("67 48 8b 01 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("65 48 8b 01 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("48 8b 05 00 00 00 00 c3", "LIFT_UNSUPPORTED_REGISTER"),
                ("48 8b 04 25 08 00 00 00 c3", "LIFT_UNSUPPORTED_INSTRUCTION"),
                ("48 a1 00 00 00 70 00 00 00 00 c3", "LIFT_UNSUPPORTED_INSTRUCTION"),
                ("48 8b 04 9c c3", "LIFT_UNDEFINED_REGISTER"),
                ("b7 ff 48 8b 03 c3", "LIFT_UNDEFINED_REGISTER"),
                ("41 b2 01 4c 89 d0 c3", "LIFT_UNDEFINED_REGISTER")):  # R10B alone cannot define R10
            with self.subTest(code=code):
                lift(code, failure)

        # LEA defines R8. MOVSX defines AX and MOVZX supplies the full RAX for ADC.
        lift("39 d1 4c 8d 04 11 eb 00 66 0f be c2 eb 00 0f b7 c0 4c 11 c0 c3")
        # INC, DEC and NOT preserve CMP's CF through CMOV and into the next block.
        lift("89 c8 39 d1 ff c0 ff ca f7 d2 0f 42 c2 eb 00 48 11 d0 c3")

        register, flag = "LIFT_UNDEFINED_REGISTER", "LIFT_UNDEFINED_FLAG"
        for code, diagnostic, reason, block, instruction, opcode, encoded in (
                # First arrival cannot borrow RAX or CF from a later iteration.
                ("48 01 c8 48 89 d0 eb f8", register, "incoming RAX", 0, 0, "ADD64rr", "4801c8"),
                ("11 d1 eb fc", flag, "flags: CF", 0, 0, "ADC32rr", "11d1"),
                # Carry invalidated only on the backedge.
                ("39 d1 72 05 c0 e1 08 eb f9 89 c8 c3", flag, "flags: CF", 2, 2, "JCC_1", "7205"),
                # Exactly one incoming path defines all of R8. The join reads it after a MOV.
                ("39 d1 74 03 49 89 c8 89 d0 4c 01 c0 c3", register, "incoming R8", 7, 9, "ADD64rr", "4c01c0"),
                # One arm writes AH and the other AL. Neither defines all of AX.
                ("39 d1 74 04 88 cc eb 02 88 c8 0f b7 c0 c3", register, "incoming RAX", 10, 10, "MOVZX32rr16", "0fb7c0"),
                # TEST leaves AF undefined. Only the CMP path supplies it to LAHF.
                ("85 d1 74 02 39 d1 9f c3", flag, "flags: AF", 6, 6, "LAHF", "9f"),
                # Self-CMP can set flags on undefined scratch without defining that register.
                ("45 39 c0 eb 00 4c 89 c0 c3", register, "incoming R8", 5, 5, "MOV64rr", "4c89c0"),
                # Even with a known-true condition, CMOV reads its old destination.
                ("39 c9 eb 00 0f 44 c2 c3", register, "incoming RAX", 4, 4, "CMOV32rr", "0f44c2"),
                # A possible zero count requires a prior ZF. Large logical byte shifts lose CF.
                ("48 d3 fa eb 00 0f 94 c0 c3", flag, "flags: ZF", 5, 5, "SETCCr", "0f94c0"),
                ("39 d1 d2 ea eb 00 0f 92 c0 c3", flag, "flags: CF", 6, 6, "SETCCr", "0f92c0"),
                ("39 d1 48 d3 fa eb 00 0f 90 c0 c3", flag, "flags: OF", 7, 7, "SETCCr", "0f90c0")):
            with self.subTest(code=code):
                context = lift(code, diagnostic, reason)
                self.assertEqual((context["block_rva"], context["instruction_rva"], context["opcode"], context["bytes"]),
                                 (hex(entry + block), hex(entry + instruction), opcode, encoded))

        # Discover a target inside an instruction before and after the containing decode.
        for code, origin, target in (
                ("39 d1 74 01 48 89 c8 c3", 2, 5),
                ("48 89 c8 eb fc", 3, 1),
                ("39 d1 74 05 eb 04 0f 0f 0f 48 89 c8 c3", 4, 10),
                ("e9 00 00 00 80", 0, 5 - (1 << 31)),
                ("eb 00", 0, 2)):
            with self.subTest(code=code):
                context = lift(code, "LIFT_UNSUPPORTED_CONTROL_FLOW")
                self.assertEqual((context["instruction_rva"], context["branch_target"]),
                                 (hex(entry + origin), entry + target))
        self.assertEqual(lift("eb 01 cc 0f", "LIFT_INVALID_ENCODING", category="invalid_input")["bytes"], "0f")
        self.assertEqual(lift("ff e0", "LIFT_UNSUPPORTED_CONTROL_FLOW")["bytes"], "ffe0")

    def test_flag_missing_at_forward_join(self):
        image = FIXTURES / "arithmetic.exe"
        export = next(e for e in self.report(image)["modules"][0]["exports"] if "immediates" in e["names"])
        rva = int(export["rva"], 16)
        data = bytearray(image.read_bytes())
        start = Layout(data).file_offset(rva)
        # CMP defines AF. Only the fallthrough XOR invalidates it before LAHF.
        body = bytes.fromhex("39 d1 74 02 31 c0 9f c3")
        data[start:start + len(body)] = body
        changed = self.dir / "join.exe"
        changed.write_bytes(data)
        for signature in ([], ["--signature", "i64(i64,i64)"]):
            failure = self.invoke("lift", changed, "--rva", hex(rva), *signature,
                                  "--output", self.dir / "join.ll", code=1)
            self.assertIn(f"{hex(rva+6)}: LAHF [9f]".encode(), failure.stderr)
            self.assertIn(b"undefined condition flags: AF", failure.stderr)

    def test_atomic_publication(self):
        image = FIXTURES / "add.exe"
        output = self.dir / "function.ll"
        args = ("lift", image, "--rva", "0x1000", "--output", output)
        output.write_bytes(b"old contents")
        previous = self.dir / "previous.ll"
        os.link(output, previous)

        def limit_file_size():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))

        p = self.invoke(*args, code=1, preexec_fn=limit_file_size)
        self.assertIn(b"OUTPUT_ERROR", p.stderr)
        self.assertEqual(output.read_bytes(), b"old contents")
        self.assertEqual(list(self.dir.glob("*.tmp-*")), [])

        self.invoke(*args, preexec_fn=lambda: os.close(0))
        self.assertIn("define internal void @forge_lifted_1000(", output.read_text())
        self.assertEqual(previous.read_bytes(), b"old contents")
        output.unlink()
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_bytes(b"keep")
        p = self.invoke(*args, code=1)
        self.assertIn(b"OUTPUT_ERROR", p.stderr)
        self.assertEqual(sentinel.read_bytes(), b"keep")
        self.assertEqual(list(self.dir.glob("*.tmp-*")), [])

    def assert_published_at(self, output):
        self.invoke("lift", FIXTURES / "add.exe", "--rva", "0x1000", "--output", output,
                    umask=0o027)
        self.assertEqual(list(output.parent.iterdir()), [output])
        self.assertIn("define internal void @forge_lifted_1000(", output.read_text())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    def test_publication_in_percent_directory(self):
        parent = self.dir / "100%"
        parent.mkdir()
        self.assert_published_at(parent / "function.ll")

    def test_publication_at_name_max(self):
        name_max = os.pathconf(self.dir, "PC_NAME_MAX")
        self.assertGreater(name_max, 1)
        self.assert_published_at(self.dir / ("." + "x" * (name_max - 1)))

    def test_publication_descriptor_transfer_failure(self):
        output = self.dir / "function.ll"
        output.write_bytes(b"old contents")

        def only_stdin_slot_available():
            os.close(0)
            resource.setrlimit(resource.RLIMIT_NOFILE, (3, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))

        p = self.invoke("lift", FIXTURES / "add.exe", "--rva", "0x1000", "--output", output,
                        code=1, preexec_fn=only_stdin_slot_available)
        self.assertIn(b"OUTPUT_ERROR", p.stderr)
        self.assertEqual(output.read_bytes(), b"old contents")
        self.assertEqual(list(self.dir.glob("*.tmp-*")), [])

    def test_relocation_overlaps_instruction(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        info = Layout(data)
        reloc = info.file_offset(info.directory(5)[0])
        struct.pack_into("<I", data, reloc, 0x1000)
        struct.pack_into("<H", data, reloc+8, 0xa000)
        exe = self.dir/"relocated.exe"
        exe.write_bytes(data)
        p = self.invoke("lift", exe, "--rva", "0x1000", "--output", self.dir/"rel.ll", code=1)
        self.assertIn(b"base relocation at 0x1000", p.stderr)


if __name__ == "__main__":
    suite = {"discovery": Discovery, "lift": Lift}[SUITE]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite))
    sys.exit(not result.wasSuccessful())
