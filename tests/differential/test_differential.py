"""Wine-free tests of the reference consumer, native supervisor, and suite outcomes."""
import contextlib
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import differential as diff
import lift_diagnostics
from artifacts import TASK3_PUBLISHER, reference
from comparison import Observation, differences
from protocol import Capture
from run import publish, runner_version, sha256


class ComparisonTests(unittest.TestCase):
    def test_matching_bytes(self):
        for data in (b"", b"\xff\0 \r\n"):
            observation = Observation(0, data, data)
            self.assertEqual(differences(observation, observation), [])

    def test_exact_fields_and_offsets(self):
        for wanted, got, offset in ((b"x\r\n", b"x\n", 1), (b"x ", b"x", 1),
                                    (b"\xff", b"\xfe", 0), (b"", b"\n", 0)):
            for field in ("stdout", "stderr"):
                with self.subTest(field=field, wanted=wanted):
                    streams = {"stdout": b"", "stderr": b""}
                    before = Observation(0, **dict(streams, **{field: wanted}))
                    after = Observation(0, **dict(streams, **{field: got}))
                    self.assertEqual(differences(before, after),
                                     [dict(field=field, offset=offset, expected=repr(wanted),
                                           actual=repr(got), expected_size=len(wanted), actual_size=len(got))])
        errors = differences(Observation(4660, b"a", b"b"), Observation(52, b"A", b"B"))
        self.assertEqual([e["field"] for e in errors], ["exit_code", "stdout", "stderr"])
        self.assertEqual(errors[0], dict(field="exit_code", expected=4660, actual=52))

    def test_decimal_pair_at_first_differing_expected_byte(self):
        args = ["0", "0", "0", "7"]
        wanted = Observation(0, b"0\n-7\n", b"")
        for stdout, operands in ((b"1\n-7\n", args[:2]), (b"0\n", args[2:]), (b"0\n-7\n0\n", None)):
            for harness in ("decimal_pairs", "calculate_pairs"):
                with self.subTest(harness=harness, stdout=stdout):
                    mismatch, = diff.native_differences(wanted, Observation(0, stdout, b""), harness, args)
                    self.assertEqual(mismatch.get("operands"), operands)


class ArtifactSetup(unittest.TestCase):
    def setUp(self):
        self.selected = diff.SelectedFunction(0x1234, 0x1239, 0, "exe", False)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.config = "debug"
        self.suite = self.root / "suite"
        (self.suite / "manifests").mkdir(parents=True)
        (self.suite / "fixtures").mkdir()
        for name, code in (("enabled", 0), ("uncovered", 4660)):
            source = f"fixtures/{name}.c"
            (self.suite / source).touch()
            diff.write_json(self.suite / "manifests" / f"{name}.json", dict(
                schema_version=1, id=f"unit/{name}", description=name, source=source,
                binary=f"{name}.exe", args=["2", "3"], expected=dict(exit_code=code, stdout="5\n", stderr="")))
        self.case = dict(fixture_id="unit/enabled", scope="function", export="sum",
                         signature="i64(i64,i64)", harness="decimal_pairs")
        diff.write_json(self.suite / "cases.json", [self.case])
        self.catalog = diff.load_catalog(self.suite)
        self.manifest = next(m for m in self.catalog if m.case["id"] == self.case["fixture_id"])
        self.forge = self.root / "selected forge"
        self.forge.write_bytes(b"unit test Forge")
        self.binaries = self.root / "binaries"
        self.references = self.root / "references"
        self.prepare_exports(self.config)
        self.image = self.binaries / self.config / self.manifest.case["binary"]
        self.digest = sha256(self.image.read_bytes())
        self.folder = self.references / self.config / self.manifest.case["id"]
        self.record = self.folder / "result.json"
        self.wanted = Observation.from_manifest(self.manifest.case["expected"])

    @staticmethod
    def lift_fixture(forge, image, case, rva, ir):
        ir.write_bytes(b"IR for " + image.read_bytes())

    @staticmethod
    def build_fixture(ir, harness, work, config, variant):
        compiler_input = ir
        if variant == "o2":
            compiler_input = work / diff.native.OPTIMIZED_IR
            compiler_input.parent.mkdir(parents=True)
            compiler_input.write_bytes(b"optimized " + ir.read_bytes())
        return work / "harness", compiler_input

    def execute_fixture(self, exe, args, work):
        (work / "stdout.bin").write_bytes(self.wanted.stdout)
        (work / "stderr.bin").write_bytes(self.wanted.stderr)
        return self.wanted

    def prepare_exports(self, config):
        bins = self.binaries / config
        bins.mkdir(parents=True)
        sums = []
        for manifest in self.catalog:
            case = manifest.case
            data = f"{config} {case['id']} PE".encode()
            (bins / case["binary"]).write_bytes(data)
            digest = sha256(data)
            sums.append(f"{digest}  {case['binary']}\n")
            wanted = Observation.from_manifest(case["expected"])
            capture = Capture(wanted.exit_code, wanted.stdout, wanted.stderr, "wine-test")
            publish(self.root, self.references / config / case["id"], manifest, config, capture, digest,
                    dict(runner_version=runner_version(), container_image_id="sha256:" + "a" * 64,
                         container_platform="linux/amd64", docker_host_arch="x86_64"))
        checksums = "".join(sums).encode()
        (bins / "SHA256SUMS").write_bytes(checksums)
        diff.write_json(bins / "build.json", dict(schema_version=1, build_config=config, reproducible=True,
                        toolchain_image_id="sha256:" + "b" * 64, checksums_sha256=sha256(checksums)))


class ArtifactTests(ArtifactSetup):
    def reference(self):
        return reference(self.references, self.manifest, self.config, self.digest)

    def test_reference_identity(self):
        # Fingerprint recorded in preserved references from before the Conan migration.
        previous = "1+sha256.9ed4d6519816d3404fc547c0310f8e8aeeb422b8742d54101f39b6b89d10200b"
        for version in (runner_version(), TASK3_PUBLISHER, previous):
            meta = diff.read_json(self.record)
            diff.write_json(self.record, dict(meta, runner_version=version))
            observed, identity = self.reference()
            self.assertEqual(observed, self.wanted)
            self.assertEqual(identity["runner_version"], version)
            self.assertEqual(identity["result_sha256"], sha256(self.record.read_bytes()))

        (self.folder / "stdout.bin").write_bytes(b"changed legacy stream")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.reference()

    def test_invalid_metadata(self):
        meta = diff.read_json(self.record)
        for field, value in (("schema_version", True), ("status", "failed"), ("build_config", "release"),
                             ("fixture_id", "other/case"), ("manifest_file", "moved"),
                             ("manifest_sha256", "0" * 64), ("binary_sha256", "0" * 64),
                             ("execution_backend", "other"), ("container_platform", "linux/arm64"),
                             ("runner_version", "1+sha256." + "1" * 64), ("container_image_id", "latest"),
                             ("docker_host_arch", ""), ("wine_version", ""), ("exit_code", 1 << 32),
                             ("exit_code", 1), ("stdout_size", True), ("stderr_size", 4),
                             ("stdout_file", "../stdout.bin"), ("stderr_sha256", "1" * 64)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                diff.write_json(self.record, dict(meta, **{field: value}))
                self.reference()
        self.record.write_text('{"status":"passed","status":"failed"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.reference()
        self.record.unlink()
        with self.assertRaises(FileNotFoundError):
            self.reference()

    def test_substituted_payload(self):
        path = self.folder / "stdout.bin"
        path.write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.reference()
        diff.write_json(self.record, dict(diff.read_json(self.record), stdout_sha256=sha256(path.read_bytes()),
                                          stdout_size=path.stat().st_size))
        with self.assertRaisesRegex(ValueError, "stdout mismatch"):
            self.reference()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.reference()
        path.symlink_to(self.image)
        with self.assertRaises(OSError):
            self.reference()
        parent = self.folder.parent
        parent.rename(parent.with_name("moved"))
        parent.symlink_to(parent.with_name("moved"), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.reference()

    def test_directory_record_releases_descriptor(self):
        self.record.unlink()
        self.record.mkdir()
        for _ in range(8):
            fd = os.open(self.record, os.O_RDONLY)
            with patch("artifacts.os.open", return_value=fd), self.assertRaisesRegex(ValueError, "artifact type"):
                self.reference()
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def invoke(self, selection=None, *, forge=None, jobs=1):
        output = self.root / "output"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = diff.run(self.config, selection, binaries=self.binaries, references=self.references,
                              output=output, forge=self.forge if forge is None else forge, suite=self.suite, jobs=jobs)
        return status, diff.read_json(output / self.config / "suite.json")

    def test_statuses_and_stale_pass_rejection(self):
        name = self.manifest.case["id"]
        report = self.root / "output" / self.config / name / "result.json"
        with patch.object(diff, "analyze", return_value=self.selected) as analyze, patch.object(diff, "lift", side_effect=self.lift_fixture) as lift, \
                patch.object(diff.native, "build", side_effect=self.build_fixture) as build, patch.object(diff.native, "execute") as execute:
            execute.return_value = self.wanted
            status, suite = self.invoke()
            self.assertEqual((status, suite["executed"], suite["uncovered"]), (0, 1, 1))
            self.assertEqual((lift.call_count, build.call_count, execute.call_count), (1, 2, 2))
            self.assertEqual([call.args[-1] for call in build.call_args_list], list(diff.VARIANTS))
            passed = diff.read_json(report)
            self.assertEqual(passed["scope"], "function")
            self.assertEqual(passed["forge_sha256"], sha256(self.forge.read_bytes()))
            self.assertEqual(analyze.call_args.args[0], self.forge)
            self.assertEqual(lift.call_args.args[0], self.forge)
            self.assertEqual(execute.call_args.args[1], self.manifest.case["args"])
            execute.return_value = Observation(0, b"divergent", b"")
            status, suite = self.invoke(name)
            self.assertEqual((status, suite["executed"]), (1, 1))
            self.assertEqual(diff.read_json(report)["failure_categories"], ["stdout_mismatch"])
            for mock, error, category in (
                    (execute, ValueError("harness failed"), "native_execution_failure"),
                    (build, ValueError("compiler failed"), "native_compilation_failure"),
                    (analyze, ValueError("ambiguous export"), "analysis_failure"),
                    (lift, ValueError("write failed"), "lifting_failure"),
                    (lift, diff.Unsupported("unsupported opcode"), "unsupported_lifting_capability")):
                previous = mock.side_effect
                mock.side_effect = error
                status, suite = self.invoke(name)
                result = diff.read_json(report)
                self.assertEqual((status, suite["executed"], result["stages"]["comparison"]), (1, 0, "not_run"))
                self.assertEqual(result["failure_categories"], [category])
                self.assertEqual(result["status"], "infrastructure_failure")
                mock.side_effect = previous
        self.image.write_bytes(b"stale")
        status, suite = self.invoke(name)
        self.assertEqual((status, suite["passed"]), (1, 0))
        self.assertEqual(diff.read_json(report)["failure_categories"], ["reference_validation_failure"])
        self.assertFalse((report.parent / "generated").exists())

    def test_parallel_failure_keeps_catalog_order_and_other_results(self):
        last = threading.Event()
        completion = []

        def run_case(manifest, *args):
            name = manifest.case["id"]
            if name == "unit/enabled":
                self.assertTrue(last.wait(5))
                completion.append(name)
                return dict(status="infrastructure_failure", scope="function")
            completion.append(name)
            last.set()
            return dict(status="uncovered", scope=None)

        with patch.object(diff, "run_case", side_effect=run_case):
            status, suite = self.invoke(jobs=2)
        self.assertEqual(status, 1)
        self.assertEqual(completion, ["unit/uncovered", "unit/enabled"])
        self.assertEqual([row["fixture_id"] for row in suite["cases"]], list(reversed(completion)))
        self.assertEqual(suite["uncovered"], 1)
        for name in completion:
            self.assertTrue((self.root / "output/debug" / name / "result.json").is_file())

    def test_invalid_worker_count_keeps_previous_evidence(self):
        _, suite = self.invoke()
        with self.assertRaisesRegex(ValueError, "jobs"):
            self.invoke(jobs=0)
        self.assertEqual(suite, diff.read_json(self.root / "output/debug/suite.json"))

    def test_zero_coverage(self):
        status, suite = self.invoke("unit/uncovered")
        self.assertEqual((status, suite["executed"], suite["uncovered"]), (1, 0, 1))
        self.assertIn("zero differential cases", suite["diagnostic"])
        path = self.root / "empty.json"
        diff.write_json(path, [])
        self.assertEqual(diff.case_definitions(self.catalog, path), {})
        diff.write_json(path, [self.case, self.case])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            diff.case_definitions(self.catalog, path)

    def test_capability_diagnostic_fails_enabled_case(self):
        def reject(args, output, errors):
            diagnostic = dict(schema_version=1, stage="lifting", category="unsupported",
                              code="LIFT_UNSUPPORTED_CONTROL_FLOW", message="changed wording",
                              context=dict(input=str(args[2]), entry_rva=args[args.index("--rva") + 1]))
            errors.write((json.dumps(diagnostic) + "\n").encode())
            return 1

        with patch.object(diff, "analyze", return_value=self.selected), \
                patch.object(diff.native, "command_status", side_effect=reject):
            status, suite = self.invoke(self.case["fixture_id"])
        self.assertEqual((status, suite["blocked"], suite["executed"]), (1, 0, 0))
        result = diff.read_json(self.root / "output/debug/unit/enabled/result.json")
        self.assertEqual(result["status"], "infrastructure_failure")
        self.assertEqual(result["failure_categories"], ["unsupported_lifting_capability"])
        self.assertEqual(result["stages"]["lifting"], "failed")

    def test_preflight_errors_do_not_launch_lift(self):
        missing_rows = dict(schema_version=1, functions=[])
        inspection = dict(schema_version=1, inspection=dict(status="completed", root_module=0),
                          modules=[dict(machine="AMD64", image_kind="exe", exports=[dict(names=["sum"], rva="0x10")])])
        for name, preflight in (
                ("enabled", lambda *args: diff.resolve_export(inspection, missing_rows, "sum")),
                ("uncovered", lambda *args: self.selected)):
            with self.subTest(name=name), patch.object(diff, "analyze", side_effect=preflight), patch.object(diff, "lift") as lift:
                fixture_id = "unit/" + name
                diff.write_json(self.suite / "cases.json", [dict(self.case, fixture_id=fixture_id)])
                status, _ = self.invoke(fixture_id)
                result = diff.read_json(self.root / "output/debug" / fixture_id / "result.json")
                stage = "analysis" if name == "enabled" else "lifting"
                self.assertEqual((status, result["failure_categories"]), (1, [stage + "_failure"]))
                self.assertEqual(result["stages"][stage], "failed")
                self.assertEqual(result["stages"]["native_compilation"], "not_run")
                lift.assert_not_called()

    def test_input_root_cannot_be_used_as_output(self):
        original = self.record.read_bytes()
        with self.assertRaisesRegex(ValueError, "overlaps input"):
            diff.run(self.config, binaries=self.binaries, references=self.references,
                     output=self.references, suite=self.suite)
        self.assertEqual(self.record.read_bytes(), original)

    def test_overlap_through_case_alias_preserves_inputs_and_report(self):
        if not (self.root / "SUITE").exists() or not (self.root / "SUITE").samefile(self.suite):
            self.skipTest("requires a case-insensitive volume")
        for kind in ("binaries", "references"):
            for input_inside_output in (True, False):
                with self.subTest(kind=kind, input_inside_output=input_inside_output):
                    base = self.root / f"{kind}-{input_inside_output}"
                    (base / "debug").mkdir(parents=True)
                    nested = base / "DEBUG" / "nested"
                    source, output = (nested, base) if input_inside_output else (base, nested)
                    inputs = dict(binaries=self.binaries, references=self.references)
                    inputs[kind] = source
                    if kind == "references" and input_inside_output:
                        nested.mkdir()
                        downloads = self.root / "downloads"
                        downloads.symlink_to(nested, target_is_directory=True)
                        source = nested / "wine"
                        inputs[kind] = downloads / "wine"
                    marker = source / "debug/input.bin"
                    summary = output / "debug/suite.json"
                    for path, data in ((marker, b"input"), (summary, b"previous report")):
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "overlaps input"):
                        diff.run("debug", output=output, suite=self.suite, **inputs)
                    self.assertEqual(marker.read_bytes(), b"input")
                    self.assertEqual(summary.read_bytes(), b"previous report")

    def test_cli_selects_forge(self):
        args = ["--all", "--config", self.config]
        with patch.object(diff, "run", return_value=0) as run:
            self.assertEqual(diff.main(args), 0)
            self.assertEqual(run.call_args.kwargs["forge"], diff.DEFAULT_FORGE)
            relative = os.path.relpath(self.forge)
            self.assertEqual(diff.main([*args, "--forge", relative]), 0)
            self.assertEqual(run.call_args.kwargs["forge"], self.forge)
        absent = self.root / "missing forge"
        status, _ = self.invoke(self.case["fixture_id"], forge=absent)
        report = diff.read_json(self.root / "output/debug/unit/enabled/result.json")
        self.assertEqual(status, 1)
        self.assertEqual(report["failure_categories"], ["analysis_failure"])
        self.assertIn(str(absent), report["diagnostic"])
        self.assertEqual(report["stages"]["lifting"], "not_run")

    def test_cleanup_preserves_selected_forge(self):
        output = self.root / "output"
        folder = output / self.config
        folder.mkdir(parents=True)
        selected = folder / "custom-forge"
        selected.write_bytes(b"selected executable")
        with self.assertRaisesRegex(ValueError, "overlaps selected Forge"):
            self.invoke(forge=selected)
        self.assertEqual(selected.read_bytes(), b"selected executable")

    def test_successful_commands_without_product_fail_compilation(self):
        with patch.object(diff, "analyze", return_value=self.selected), patch.object(diff, "lift", side_effect=self.lift_fixture), \
                patch.object(diff.native, "command"), patch.object(diff.platform, "system", return_value="Darwin"), \
                patch.object(diff.platform, "machine", return_value="arm64"):
            status, _ = self.invoke(self.case["fixture_id"])
        report = diff.read_json(self.root / "output/debug/unit/enabled/result.json")
        self.assertEqual(status, 1)
        self.assertEqual(report["failure_categories"], ["native_compilation_failure"])
        self.assertIn("executable harness", report["diagnostic"])
        self.assertEqual(report["stages"]["native_execution"], "not_run")
        self.assertEqual(report["stages"]["comparison"], "not_run")


class LiftDiagnosticTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.ir = self.work / diff.CANONICAL_IR
        self.ir.parent.mkdir()
        self.image = self.work / "source.exe"
        self.image.write_bytes(b"MZ\x90\x55\xc3\xcc\xcc")
        self.selected = diff.SelectedFunction(0x10, 0x15, 2, "exe", False)
        self.rva = "0x10"
        self.forge = self.work / "forge"
        self.diagnostic = dict(schema_version=1, stage="lifting", category="unsupported",
                               code="LIFT_UNSUPPORTED_INSTRUCTION", message="explanation",
                               context=dict(input=str(self.image), entry_rva=self.rva, end_rva="0x15",
                                            instruction_rva="0x11", opcode="PUSH64r", bytes="55",
                                            signature="i64(i64,i64)", block_rva="0x10"))
        self.raw = self.encode(self.diagnostic)

    @staticmethod
    def encode(record):
        return (json.dumps(record) + "\n").encode("utf-8")

    def lift(self, status, stderr, *, stdout=b"", produce=False):
        self.forge.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\nfrom pathlib import Path\n"
            "assert sys.argv[-2:] == ['--diagnostics-format', 'json']\n"
            f"if {produce}: Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(b'IR')\n"
            f"os.write(1, {stdout!r})\nos.write(2, {stderr!r})\n"
            f"if {status} < 0: os.kill(os.getpid(), {-status})\n"
            f"sys.exit({status})\n")
        self.forge.chmod(0o755)
        diff.lift(self.forge, self.image, {"signature": "i64(i64,i64)"}, self.selected, self.ir)

    def test_full_diagnostic_and_prose_independence(self):
        for category, stage, code, kind in (
                ("unsupported", "lifting", "LIFT_UNSUPPORTED_INSTRUCTION", diff.Unsupported),
                ("internal", "verification", "IR_VERIFICATION_FAILED", ValueError),
                ("invalid_input", "pe", "INVALID_PE", ValueError),
                ("io", "publication", "OUTPUT_WRITE", ValueError)):
            with self.subTest(code=code):
                context = dict(input=str(self.image), entry_rva=self.rva)
                if stage == "publication":
                    context["output"] = str(self.ir)
                diagnostic = dict(self.diagnostic, category=category, stage=stage, code=code, context=context,
                                  message="m" * 5000 + ": unsupported instruction or operand width")
                raw = self.encode(diagnostic)
                with self.assertRaises(ValueError) as error:
                    self.lift(1, raw)
                self.assertIs(type(error.exception), kind)
                self.assertIn(code, str(error.exception))
                self.assertEqual((self.work / "lifting.log").read_bytes(), raw)

    def test_invalid_diagnostic(self):
        def changed(**values):
            return self.encode(dict(self.diagnostic, **values))

        def context(**values):
            return changed(context=dict(self.diagnostic["context"], **values))

        for raw in (
                b"", b"\xff\n", b"not json\n", b"{}\n", self.raw[:-1], self.raw[:-7] + b"\n",
                self.raw + b"\n", self.raw + self.raw, b"forge: " + self.raw, self.raw + b"trailing",
                self.raw.replace(b'"code":', b'"code":"duplicate","code":'),
                self.raw.replace(b'"input":', b'"input":"duplicate","input":'),
                changed(schema_version=True), changed(schema_version=2), changed(extra=True),
                changed(stage=[]), changed(category="unknown"), changed(code="UNKNOWN"),
                changed(category="internal"), changed(stage="analysis"), changed(code=None),
                changed(context=None), changed(message=""), changed(message=1), changed(message=chr(0xd800)),
                changed(stage="pe", category="invalid_input", code="NOT_DLL"),
                changed(stage="publication", category="invalid_input", code="OUTPUT_ALIAS"),
                changed(stage="publication", category="io", code="OUTPUT_CLOSE"),
                context(input="another.exe"), context(output="other.ll"), context(entry_rva="0x11"),
                context(instruction_rva="0x15"), context(end_rva="0x10"), context(end_rva=0x14),
                context(instruction_rva="0x100000000"), context(opcode=3), context(architecture=""),
                context(bytes="xyz"), context(file_offset=True), context(file_offset=-1),
                context(signature="register-state"), context(block_rva="0x12"),
                context(block_rva="0xf"), context(branch_target=15), context(unknown="field")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                lift_diagnostics.parse_diagnostic(raw, self.image, self.selected, self.ir)

    def test_control_flow_diagnostic_target(self):
        self.image.write_bytes(b"MZ\xeb\x80")
        context = dict(self.diagnostic["context"], instruction_rva=self.rva, opcode="JMP_1",
                       bytes="eb80", branch_target=-110)
        record = dict(self.diagnostic, code="LIFT_UNSUPPORTED_CONTROL_FLOW", context=context)
        self.assertEqual(lift_diagnostics.parse_diagnostic(self.encode(record), self.image,
                         self.selected, self.ir)["context"]["branch_target"], -110)
        for target in (True, "0xffffffff", -(1 << 32), 1 << 33):
            with self.subTest(target=target), self.assertRaises(ValueError):
                invalid = dict(record, context=dict(context, branch_target=target))
                lift_diagnostics.parse_diagnostic(self.encode(invalid), self.image, self.selected, self.ir)

    def test_context_agrees_with_code_and_source(self):
        request = dict(input=str(self.image), entry_rva=self.rva)
        location = dict(self.diagnostic["context"], file_offset=3)

        def parse(stage, category, code, context):
            record = dict(self.diagnostic, stage=stage, category=category, code=code, context=context)
            return lift_diagnostics.parse_diagnostic(self.encode(record), self.image, self.selected, self.ir)

        parse("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", location)
        parse("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", self.diagnostic["context"])
        for stage, category, code, context in (
                ("pe", "unsupported", "UNSUPPORTED_ARCHITECTURE", dict(request, architecture="i386")),
                ("entry", "unsupported", "ENTRY_DLL", request),
                ("entry", "unsupported", "ENTRY_UNWIND_VERSION", request),
                ("entry", "unsupported", "ENTRY_CHAINED_FRAGMENT", request),
                ("entry", "unsupported", "ENTRY_RELOCATION_OVERLAP", request),
                ("lifting", "unsupported", "LIFT_FUNCTION_SIZE", request),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(location, end_rva="0x2000")),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(location, bytes="4d5a", file_offset=0)),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(request, instruction_rva="0x15")),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(request, instruction_rva="0x10", bytes="4d5a")),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(location, bytes="90")),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(location, file_offset=5)),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(request, instruction_rva="0x11", file_offset=5)),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(location, bytes="55555555")),
                ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION", dict(location, output=str(self.ir))),
                ("lifting", "unsupported", "LIFT_FUNCTION_SIZE", location),
                ("lifting", "invalid_input", "LIFT_INVALID_ENCODING", location),
                ("publication", "io", "OUTPUT_WRITE", dict(location, output=str(self.ir))),
                ("entry", "unsupported", "ENTRY_DLL", location),
                ("pe", "unsupported", "UNSUPPORTED_ARCHITECTURE", request),
                ("pe", "unsupported", "UNSUPPORTED_ARCHITECTURE", dict(request, architecture="amd64")),
                ("pe", "invalid_input", "INVALID_PE", dict(request, architecture="arm64"))):
            with self.subTest(code=code, context=context), self.assertRaises(ValueError):
                parse(stage, category, code, context)

    def test_size_limit_uses_discovered_extent(self):
        context = dict(input=str(self.image), entry_rva=self.rva)
        diagnostic = dict(self.diagnostic, code="LIFT_FUNCTION_SIZE", context=context)
        for size in (5, 65536, 65537):
            selected = diff.SelectedFunction(0x10, 0x10 + size, 2, "exe", False)
            raw = self.encode(diagnostic)
            if size <= 65536:
                with self.assertRaisesRegex(ValueError, "contradicts"):
                    lift_diagnostics.parse_diagnostic(raw, self.image, selected, self.ir)
            else:
                self.assertEqual(lift_diagnostics.parse_diagnostic(raw, self.image, selected, self.ir), diagnostic)

    def test_command_status_and_artifact_must_agree(self):
        for status, stderr, stdout, produce in (
                (0, self.raw, b"", True), (0, b"", b"", False), (0, b"", b"prose", True),
                (1, self.raw, b"", True), (1, b"", self.raw, False), (1, b"", b"", False),
                (1, b"forge: " + self.raw, b"", False), (2, self.raw, b"", False),
                (-signal.SIGTERM, self.raw, b"", False)):
            with self.subTest(status=status, stderr=stderr, stdout=stdout, produce=produce):
                self.ir.unlink(missing_ok=True)
                with self.assertRaises(ValueError) as error:
                    self.lift(status, stderr, stdout=stdout, produce=produce)
                self.assertNotIsInstance(error.exception, diff.Unsupported)
                self.assertEqual((self.work / "lifting.log").read_bytes(), stderr)
                self.assertEqual((self.work / "lifting.stdout").read_bytes(), stdout)
        self.lift(0, b"", produce=True)
        with self.assertRaisesRegex(ValueError, "fresh output"):
            self.lift(0, b"")

    def test_recognized_execution_codes_match_forge(self):
        catalog = (diff.SUITE.parents[1] / "src/diagnostics.def").read_text()
        expected = set()
        row = r'FORGE_FAILURE\(\w+,\s*"(\w+)",\s*"(\w+)",\s*"(\w+)",\s*"\w+"\)'
        for line in catalog.splitlines():
            if not line.strip() or line.lstrip().startswith("//"):
                continue
            match = re.fullmatch(row, line.strip())
            self.assertIsNotNone(match, line)
            code, stage, category = match.groups()
            if code not in ("OUTPUT_ALIAS", "NOT_DLL"):
                expected.add((stage, category, code))
        actual = {(stage, category, code) for (stage, category), codes in lift_diagnostics.FAILURE_KINDS.items()
                  for code in codes}
        self.assertEqual(actual, expected)


class AnalysisTests(unittest.TestCase):
    def test_range_and_export_identity(self):
        item = dict(names=["sum"], rva="0x10")
        row = dict(start_rva="0x10", end_rva="0x14", status="valid", liftable=True)
        section = dict(rva="0xc", virtual_size=8, raw_size=12, file_offset=16, permissions="r-x")
        def resolve(exports, rows, image_kind="exe", relocations=()):
            module = dict(exports=exports, sections=[section], machine="AMD64", image_kind=image_kind,
                          relocations=[dict(entries=list(relocations))])
            inspection = dict(schema_version=1, inspection=dict(status="completed", root_module=0), modules=[module])
            return diff.resolve_export(inspection, dict(schema_version=1, functions=rows), "sum")
        self.assertEqual(resolve([item], [row]), diff.SelectedFunction(0x10, 0x14, 20, "exe", False))
        before = dict(rva="0xf", type=3)
        for kind, relocs, expected in (("exe", [before], "ENTRY_RELOCATION_OVERLAP"),
                                       ("exe", [dict(rva="0xc", type=3), dict(rva="0x10", type=0)], None),
                                       ("dll", [before], "ENTRY_DLL")):
            self.assertEqual(resolve([item], [row], kind, relocs).entry_restriction(), expected)
        for exports, rows in (([], [row]), ([item, item], [row]), ([dict(item, forwarder="other")], [row]),
                              ([item], [row, row]), ([item], [dict(row, status="invalid")])):
            with self.assertRaises(ValueError) as failure:
                resolve(exports, rows)
            self.assertNotIsInstance(failure.exception, diff.Unsupported)
        for rows in ([], [dict(row, liftable=False, status="unsupported")]):
            with self.assertRaises(ValueError) as failure:
                resolve([item], rows)
            self.assertNotIsInstance(failure.exception, diff.Unsupported)


class NativeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name).resolve()

    def python(self, code, **options):
        return diff.native.execute(sys.executable, ["-c", code], self.work, **options)

    def test_command_stops_descendants_before_returning(self):
        # The child holds a lock until exit. Opening the gate after command returns
        # would let a surviving writer modify the next build's output.
        child = """
import fcntl, os, signal, sys, time
from pathlib import Path
work = Path(sys.argv[1])
with (work / 'ready').open('w') as locked:
    fcntl.flock(locked, fcntl.LOCK_EX)
    print('ready', flush=True)
    if sys.argv[2] == 'interrupt':
        os.kill(int(sys.argv[3]), signal.SIGUSR1)
    for _ in range(500):
        if (work / 'gate').exists():
            (work / 'late').touch()
            break
        time.sleep(0.01)
"""
        parent = "import subprocess, sys; subprocess.run([sys.executable, '-c', *sys.argv[1:]], check=True)"
        previous = signal.signal(signal.SIGUSR1, diff.interrupt)
        self.addCleanup(signal.signal, signal.SIGUSR1, previous)
        for mode, error in (("timeout", subprocess.TimeoutExpired), ("interrupt", KeyboardInterrupt)):
            with self.subTest(mode=mode):
                work = self.work / mode
                work.mkdir()
                log = work / "build.log"
                args = [sys.executable, "-c", parent, child, str(work), mode, str(os.getpid())]
                with self.assertRaises(error):
                    diff.native.command(args, log, timeout=1 if mode == "timeout" else 5)
                self.assertIn("ready", log.read_text())
                (work / "gate").touch()
                with (work / "ready").open() as lock:
                    fcntl.flock(lock, fcntl.LOCK_SH)
                    self.assertFalse((work / "late").exists())

    def test_shared_graph_rejects_other_inputs_before_building(self):
        tree = self.work / "cmake-workers/1"
        case = self.work / "unit/name"
        work = case / "baseline"
        work.mkdir(parents=True)
        ir = case / diff.CANONICAL_IR
        harness = "decimal_pairs"
        worker = diff.native.SuiteBuild(tree, "debug", self.work, [dict(fixture_id="unit/name", harness=harness)],
                                        diff.native.ActiveProcesses(), {})
        for args in ((ir, harness, work, "release", "baseline"),
                     (ir, "other_harness", work, "debug", "baseline"),
                     (ir, harness, work, "debug", "o2"),
                     (self.work / "different.ll", harness, work, "debug", "baseline")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                worker.build(*args)
        self.assertFalse(tree.exists())

    def test_cancelled_workers_reap_active_and_racing_launches(self):
        processes = diff.native.ActiveProcesses()
        worker = diff.native.SuiteBuild(self.work, "debug", self.work, [], processes, {})
        token = diff.native.current_worker.set(worker)
        self.addCleanup(diff.native.current_worker.reset, token)
        with diff.native.supervised([sys.executable, "-c", "import time; time.sleep(60)"]) as active:
            processes.cancel()
            self.assertEqual(active.wait(timeout=5), -signal.SIGKILL)
        with self.assertRaises(KeyboardInterrupt), diff.native.supervised(
                [sys.executable, "-c", "import time; time.sleep(60)"]):
            self.fail("a cancelled worker launched a new command")
        self.assertFalse(processes.processes)

    def test_normal_exit_stops_descendant_writers(self):
        parent = """
import fcntl, os, sys, time
from pathlib import Path
work = Path(sys.argv[1])
ready, notify = os.pipe()
if os.fork():
    os.close(notify)
    assert os.read(ready, 1) == b'1'
    os._exit(int(sys.argv[2]))
os.close(ready)
with (work / 'lock').open('w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    os.write(notify, b'1')
    for _ in range(500):
        if (work / 'gate').exists():
            os.write(1, b'late output')
            os.write(2, b'late diagnostic')
            break
        time.sleep(0.01)
"""
        for status in (0, 1):
            with self.subTest(status=status):
                work = self.work / str(status)
                work.mkdir()
                log, stdout = work / "lifting.log", work / "lifting.stdout"
                with log.open("wb") as errors, stdout.open("wb") as output:
                    actual = diff.native.command_status([sys.executable, "-c", parent, work, str(status)],
                                                        output, errors, timeout=5)
                self.assertEqual(actual, status)
                (work / "gate").touch()
                with (work / "lock").open() as lock:
                    fcntl.flock(lock, fcntl.LOCK_SH)
                self.assertEqual((log.read_bytes(), stdout.read_bytes()), (b"", b""))

    def test_streams_and_execution_failures(self):
        actual = self.python(r'import sys; print(len(sys.stdin.buffer.read())); sys.stderr.buffer.write(b"\xff\0")')
        self.assertEqual(actual, Observation(0, b"0\n", b"\xff\0"))
        for code, message in (("raise SystemExit(7)", "exited 7"), ("import os; os.kill(os.getpid(), 15)", "signal")):
            with self.assertRaisesRegex(ValueError, message):
                self.python(code)
        with self.assertRaises(FileNotFoundError):
            diff.native.execute(self.work / "absent", [], self.work)

    def test_output_limits_and_timeout(self):
        for fd, name in ((1, "stdout"), (2, "stderr")):
            self.python(f"import os; os.write({fd}, b'x' * 32)", limit=32)
            with self.assertRaisesRegex(ValueError, name + " output-size limit"):
                self.python(f"import os; os.write({fd}, b'x' * 33)", limit=32)
            self.assertEqual((self.work / (name + ".bin")).read_bytes(), b"x" * 32)
        # The original process exits while its sleeping child retains the pipes.
        code = "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])"
        with self.assertRaisesRegex(ValueError, "timeout"):
            self.python(code, timeout=0.3)

    def test_output_limit_survives_macos_group_cleanup(self):
        def signal_group(pid, sig):
            self.assertEqual(sig, signal.SIGKILL)
            if killpg.call_count == 1:
                raise PermissionError(errno.EPERM, "group leader exiting")
            # The retry must follow reaping, even if the child has already exited.
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
            raise ProcessLookupError(errno.ESRCH, "group has disappeared")

        with patch.object(diff.native.platform, "system", return_value="Darwin"), \
                patch.object(os, "killpg", side_effect=signal_group) as killpg:
            with self.assertRaises(diff.native.ExecutionFailure) as failure:
                self.python("import os; os.write(2, b'x' * 33); os._exit(0)", limit=32)
        self.assertEqual(killpg.call_count, 2)
        self.assertEqual(killpg.call_args_list[0], killpg.call_args_list[1])
        self.assertEqual(failure.exception.outcome, "output_limit")
        self.assertEqual((self.work / "stderr.bin").read_bytes(), b"x" * 32)

    def test_persistent_group_permission_error(self):
        denied = PermissionError(errno.EPERM, "cannot signal group")
        with patch.object(diff.native.platform, "system", return_value="Darwin"), \
                patch.object(os, "killpg", side_effect=denied) as killpg:
            with self.assertRaises(PermissionError) as failure:
                self.python("pass")
        self.assertIs(failure.exception, denied)
        self.assertEqual(killpg.call_count, 2)


if __name__ == "__main__":
    unittest.main()
