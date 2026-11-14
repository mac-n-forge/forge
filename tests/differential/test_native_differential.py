"""Native regression runs using the genuine PE, Wine publication, Forge and native build."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import differential as diff
from calculate_driver_cases import CASES as CALCULATE_INPUTS

CASE = "arithmetic/add_i64"
WEIGHTED = "arithmetic/weighted_pair_i64"
OUTPUT = diff.OUTPUT.parent / "negative-tests"


class NativeDifferentialTests(unittest.TestCase):
    forge = diff.DEFAULT_FORGE

    def setUp(self):
        self.tmp = diff.BUILD / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def test_calculate_driver(self):
        fixture = "frames/calculate"
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp)
            for config in diff.CONFIGS:
                self.assertEqual(diff.run(config, fixture, output=output, forge=self.forge), 0)
                for variant in diff.VARIANTS:
                    exe = output / config / fixture / variant / "native/bin/differential_calculate_pairs"
                    for args, status, stdout in CALCULATE_INPUTS:
                        with self.subTest(config=config, variant=variant, args=args):
                            result = subprocess.run([exe, *args], capture_output=True, timeout=10)
                            self.assertEqual((result.returncode, result.stdout, result.stderr), (status, stdout, b""))

    def negative(self, name, category, *, fixture=CASE, binaries=diff.BINARIES):
        output = OUTPUT / name
        self.assertEqual(diff.run("debug", fixture, binaries=binaries, output=output, forge=self.forge), 1)
        report = diff.read_json(output / "debug" / fixture / "result.json")
        self.assertEqual(report["failure_categories"], [category])
        return report

    def modified_ir(self, fixture, name, category, mutate, only=None):
        compile_native = diff.native.build

        def compile_copy(ir, harness, work, config, variant):
            if only and only != variant:
                return compile_native(ir, harness, work, config, variant)
            changed = work / (name + ".ll")
            changed.write_text(mutate(ir.read_text()))
            return compile_native(changed, harness, work, config, variant)

        with patch.object(diff.native, "build", compile_copy):
            return self.negative(name, category, fixture=fixture)

    def test_real_unsupported_instruction_diagnostic(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == CASE)
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            work = Path(tmp).resolve()
            image = work / manifest.case["binary"]
            data = bytearray((diff.BINARIES / "debug" / image.name).read_bytes())
            image.write_bytes(data)
            entry = diff.analyze(self.forge, image, "add_i64", work)
            length = entry.end - entry.start
            # PUSH [RCX], RET and padding preserve every PE table and the discovered extent.
            self.assertGreaterEqual(length, 3)
            data[entry.file_offset:entry.file_offset + length] = b"\xff\x31\xc3".ljust(length, b"\xcc")
            image.write_bytes(data)
            selected = diff.analyze(self.forge, image, "add_i64", work)
            ir = work / diff.CANONICAL_IR
            ir.parent.mkdir()
            with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNSUPPORTED_INSTRUCTION"):
                diff.lift(self.forge, image, {"signature": "i64(i64,i64)"}, selected, ir)
            failure = diff.read_json(work / "lifting.log")
            self.assertEqual((failure["context"]["instruction_rva"], failure["context"]["file_offset"],
                              failure["context"]["bytes"]), (hex(selected.start), entry.file_offset, "ff31"))
            self.assertFalse(ir.exists())

    def test_changed_return(self):
        def change_return(source):
            changed, count = re.subn(r"^  ret i64 (%\w+)$",
                                     r"  %nonzero = icmp ne i64 \1, 0\n  %delta = zext i1 %nonzero to i64\n"
                                     r"  %changed = add i64 \1, %delta\n  ret i64 %changed",
                                     source, flags=re.MULTILINE)
            self.assertEqual(count, 1, "expected one return in the native wrapper")
            return changed

        for fixture, pair_index, variant in ((CASE, 0, "baseline"), (WEIGHTED, 1, "o2")):
            with self.subTest(fixture=fixture):
                report = self.modified_ir(fixture, "changed-return", "stdout_mismatch", change_return, only=variant)
                other = "baseline" if variant == "o2" else "o2"
                self.assertEqual(report["variants"][other]["status"], "passed")
                self.assertEqual(report["status"], "behavioral_failure")
                self.assertEqual(report["stages"]["native_execution"], "passed")
                self.assertEqual(report["stages"]["comparison"], "failed")
                mismatch, = report["variants"][variant]["differences"]
                self.assertEqual(mismatch["field"], "stdout")
                manifest = next(m for m in diff.load_catalog() if m.case["id"] == fixture)
                self.assertEqual(mismatch["operands"], manifest.case["args"][2 * pair_index:2 * pair_index + 2])

    def test_signed_comparison_with_truncated_right_operand(self):
        def truncate_right(source):
            # Change the incoming RDX bits once. The weighted term already uses
            # only EDX, so the only behavior affected is the signed comparison.
            pattern = r"^(  store i64 )%1(, ptr %\w+, align \d+)$"
            changed, count = re.subn(pattern, r"  %low = trunc i64 %1 to i32\n"
                                     r"  %right = sext i32 %low to i64\n\1%right\2", source,
                                     flags=re.MULTILINE)
            self.assertEqual(count, 1, "expected the wrapper to initialize RDX once")
            return changed

        report = self.modified_ir(WEIGHTED, "truncated-right", "stdout_mismatch", truncate_right)
        self.assertEqual(report["stages"]["native_execution"], "passed")
        self.assertEqual(report["stages"]["comparison"], "failed")
        for evidence in report["variants"].values():
            mismatch, = evidence["differences"]
            self.assertEqual(mismatch["operands"], ["1", "4294967295"])

    def test_stack_index_scale(self):
        def use_byte_stride(source):
            changed, count = re.subn(r"(\bmul i64 %\w+, )4\b", r"\g<1>1", source)
            self.assertEqual(count, 1, "expected one four-byte index scale")
            return changed

        report = self.modified_ir("memory/indexed", "byte-stride", "stdout_mismatch", use_byte_stride)
        for variant in diff.VARIANTS:
            evidence = report["variants"][variant]
            self.assertEqual(evidence["stages"]["native_execution"], "passed")
            self.assertEqual(evidence["failure_categories"], ["stdout_mismatch"])

    def test_word_sign_extension(self):
        def zero_extend(source):
            changed, count = re.subn(r"\bsext i16 (%\w+) to i64\b", r"zext i16 \1 to i64", source)
            self.assertEqual(count, 1, "expected one signed word-to-quadword extension")
            return changed

        report = self.modified_ir("arithmetic/extensions", "unsigned-word", "stdout_mismatch", zero_extend)
        for variant in diff.VARIANTS:
            self.assertEqual(report["variants"][variant]["failure_categories"], ["stdout_mismatch"])

    def test_native_build_failures(self):
        def missing_wrapper(source):
            self.assertEqual(source.count("@forge_lifted("), 1)
            return source.replace("@forge_lifted(", "@missing_wrapper(")

        def invalid_ir(source):
            return source + "\ninvalid IR for the native build regression\n"

        for fixture, name, mutate, phase in (
                (CASE, "invalid-ir", invalid_ir, "object compilation"),
                (WEIGHTED, "invalid-ir", invalid_ir, "object compilation"),
                (WEIGHTED, "missing-wrapper", missing_wrapper, "linking")):
            with self.subTest(fixture=fixture, name=name):
                report = self.modified_ir(fixture, name, "native_compilation_failure", mutate)
                self.assertEqual(report["status"], "infrastructure_failure")
                self.assertIn(f"native {phase} failed", report["diagnostic"])
                if name == "missing-wrapper":
                    self.assertIn("_forge_lifted", report["diagnostic"])
                self.assertEqual(report["stages"]["native_execution"], "not_run")
                self.assertEqual(report["stages"]["comparison"], "not_run")

    def test_instrumented_harness_link(self):
        for generator in ("Unix Makefiles", "Xcode"):
            with self.subTest(generator=generator), tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
                output = Path(tmp).resolve()
                flags = "-fsanitize=undefined"
                link_map = output / "harness.map"
                # The Xcode generator takes link options separately from CXXFLAGS.
                ldflags = f'{flags} -Xlinker -map -Xlinker "{link_map}"' if generator == "Xcode" else ""
                with patch.dict(os.environ, CMAKE_GENERATOR=generator, CXXFLAGS=flags, LDFLAGS=ldflags,
                                CMAKE_TOOLCHAIN_FILE=str(output / "unavailable-conan-toolchain.cmake")):
                    self.assertEqual(diff.run("debug", WEIGHTED, output=output, forge=self.forge), 0)
                for variant in diff.VARIANTS:
                    cache = (output / "debug" / WEIGHTED / variant / "native/CMakeCache.txt").read_text()
                    self.assertIn("FORGE_BUILD_CLI:BOOL=OFF", cache)
                    self.assertNotIn("CLI11_DIR:", cache)
                if generator == "Xcode":
                    self.assertIn("_forge_lifted", link_map.read_text())

    def test_suite_build_isolates_native_link_failures(self):
        catalog = diff.load_catalog()
        selected = [m for m in catalog if m.case["id"] in (CASE, WEIGHTED)]
        definitions = diff.case_definitions(catalog, diff.SUITE / "cases.json")
        original = diff.lift

        def broken_wrapper(forge, image, case, entry, ir):
            original(forge, image, case, entry, ir)
            if case["fixture_id"] == CASE:
                source = ir.read_text()
                self.assertIn("@forge_lifted(", source)
                ir.write_text(source.replace("@forge_lifted(", "@missing_wrapper("))

        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            output = Path(tmp).resolve()
            with patch.object(diff, "lift", broken_wrapper), patch.object(diff, "load_catalog", return_value=selected), \
                    patch.object(diff, "case_definitions", return_value=definitions):
                self.assertEqual(diff.run("release", output=output, forge=self.forge), 1)
            suite = diff.read_json(output / "release/suite.json")
            self.assertEqual((suite["passed"], suite["executed"]), (1, 1))
            folder = output / "release"
            failed = diff.read_json(folder / CASE / "result.json")
            passed = diff.read_json(folder / WEIGHTED / "result.json")
            self.assertEqual(set(failed["variants"]), set(diff.VARIANTS))
            for variant in diff.VARIANTS:
                self.assertIn("native linking failed", failed["variants"][variant]["diagnostic"])
                self.assertEqual(passed["variants"][variant]["status"], "passed")
            self.assertEqual(len(list((folder / "cmake-workers").rglob("CMakeCache.txt"))), 1)

    def test_weighted_repeatability(self):
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            observations = []
            for run in ("first", "second"):
                output = Path(tmp).resolve() / run
                self.assertEqual(diff.run("debug", WEIGHTED, output=output, forge=self.forge), 0)
                work = output / "debug" / WEIGHTED
                report = diff.read_json(work / "result.json")
                self.assertEqual(report["status"], "passed")
                observations.append((report["binary_sha256"], report["forge_sha256"], report["reference"],
                                     (work / "generated/lifted.ll").read_bytes(), report["variants"],
                                     [(work / v / file).read_bytes() for v in diff.VARIANTS
                                      for file in ("stdout.bin", "stderr.bin")]))
            self.assertEqual(observations[0], observations[1])

    def test_nonterminating_lifted_loop(self):
        # Force the taken backedge of the existing guest loop in the baseline IR.
        def close_loop(source):
            latch = re.compile(r"^rva_([0-9a-f]+):[^\n]*\n(?:  [^\n]*\n)*?"
                               r"  br i1 (%\w+), label %rva_([0-9a-f]+), label %rva_([0-9a-f]+)$",
                               re.MULTILINE)
            backedges = [match for match in latch.finditer(source)
                         if int(match[3], 16) <= int(match[1], 16) < int(match[4], 16)]
            self.assertEqual(len(backedges), 1)
            start, end = backedges[0].span(2)
            return source[:start] + "true" + source[end:]

        execute = diff.native.execute
        with patch.object(diff.native, "execute", lambda exe, args, work: execute(exe, args, work, timeout=1)):
            report = self.modified_ir("control_flow/counted_sum", "closed-loop", "native_execution_failure",
                                      close_loop, only="baseline")
        self.assertEqual(report["variants"]["baseline"]["execution_outcome"], "timeout")
        self.assertEqual(report["variants"]["o2"]["status"], "passed")

    def test_harness_failure(self):
        execute = diff.native.execute
        with patch.object(diff.native, "execute", lambda exe, args, work: execute(exe, ["invalid", "1"], work)):
            report = self.negative("invalid-operands", "native_execution_failure")
        self.assertIn("exited 2", report["diagnostic"])
        for evidence in report["variants"].values():
            self.assertEqual((evidence["execution_outcome"], evidence["native_process_status"]), ("harness_error", 2))
        self.assertEqual(report["stages"]["comparison"], "not_run")

    def test_stale_reference(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == CASE)
        binary = manifest.case["binary"]
        with tempfile.TemporaryDirectory(dir=self.tmp) as tmp:
            root = Path(tmp).resolve()
            (root / "debug").mkdir()
            release = (diff.BINARIES / "release" / binary).read_bytes()
            (root / "debug" / binary).write_bytes(release)
            (root / "debug/SHA256SUMS").write_text(f"{diff.sha256(release)}  {binary}\n")
            report = self.negative("stale-pe", "reference_validation_failure", binaries=root)
        self.assertIn("binary_sha256 mismatch", report["diagnostic"])
        self.assertEqual(report["stages"]["analysis"], "not_run")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--forge", type=Path, default=diff.DEFAULT_FORGE)
    args, tests = parser.parse_known_args()
    NativeDifferentialTests.forge = args.forge.resolve()
    unittest.main(argv=[sys.argv[0], *tests])
