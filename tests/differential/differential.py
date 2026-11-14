"""Compare function-level native executions with validated Windows observations."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from comparison import describe, differences
from lift_diagnostics import SelectedFunction, parse_diagnostic
from manifests import FIXTURE_ID, SUITE, field, load_catalog, unique_keys

sys.path.insert(0, str(SUITE / "reference"))
from artifacts import directory, file_sha256, reference
from run import BINARIES, BUILD, REFERENCES, interrupt, sha256, snapshot, verified_export
import native

OUTPUT = BUILD / "differential/windows-x64"
DEFAULT_FORGE = BUILD / "dev/forge"
STAGES = ("reference_validation", "analysis", "lifting", "native_compilation",
          "native_execution", "comparison")
VARIANTS = ("baseline", "o2")
CANONICAL_IR = Path("generated/lifted.ll")
NATIVE_STAGES = STAGES[3:]
CONFIGS = ("debug", "release")
TARGET = "macos-arm64"


class Unsupported(ValueError):
    pass


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)


def write_json(path, data):
    stream = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False)
    temporary = Path(stream.name)
    try:
        with stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def case_definitions(catalog, path):
    cases = read_json(path)
    if not isinstance(cases, list):
        raise ValueError("differential cases must be a list")
    ids = {m.case["id"] for m in catalog}
    definitions = {}
    for case in cases:
        name = field(case, "fixture_id", str)
        if name not in ids:
            raise ValueError(f"unknown differential fixture {name!r}")
        configs = case.get("configs", list(CONFIGS))
        if (not isinstance(configs, list) or not configs or any(c not in CONFIGS for c in configs)
                or len(set(configs)) != len(configs)):
            raise ValueError(f"invalid differential configs for {name}")
        keys = set(case) - {"configs"}
        if keys == {"fixture_id", "blocked_reason"}:
            if not field(case, "blocked_reason", str).strip():
                raise ValueError(f"empty blocking reason for {name}")
        elif (keys != {"fixture_id", "scope", "export", "signature", "harness"}
                or case.get("scope") != "function" or case.get("signature") != "i64(i64,i64)"
                or not re.fullmatch(r"[A-Za-z_]\w*", field(case, "export", str), flags=re.ASCII)
                or not re.fullmatch(r"[a-z][a-z0-9_]*", field(case, "harness", str))):
            raise ValueError(f"invalid differential function contract for {name}")
        for config in configs:
            if (name, config) in definitions:
                raise ValueError(f"duplicate differential fixture {name!r} for {config}")
            definitions[name, config] = case
    return definitions


def resolve_export(inspection, analysis, name):
    if (field(inspection, "schema_version", int) != 1 or field(analysis, "schema_version", int) != 1
            or inspection["inspection"] != {"status": "completed", "root_module": 0}):
        raise ValueError("unsupported or incomplete Forge analysis report")
    module = inspection["modules"][0]
    if module["machine"] != "AMD64" or module["image_kind"] not in ("dll", "exe"):
        raise ValueError("expected an inspected AMD64 executable image")
    exports = [entry for entry in module["exports"] if name in entry["names"]]
    if len(exports) != 1 or "forwarder" in exports[0]:
        raise ValueError(f"expected one local export named {name}, found {exports!r}")
    rva = int(exports[0]["rva"], 16)
    rows = [row for row in analysis["functions"] if int(row["start_rva"], 16) == rva]
    if not rows:
        raise ValueError(f"export {name} at {rva:#x} has no discovered function range")
    if len(rows) != 1 or "overlap_diagnostic" in rows[0]:
        raise ValueError(f"ambiguous or invalid function range for {name} at {rva:#x}")
    if (rows[0]["liftable"] is not True or rows[0]["status"] != "valid"
            or rows[0].get("chained_fragment") or "unwind_version" in rows[0]):
        raise ValueError(f"export {name} at {rva:#x} is ineligible for lifting: {rows[0]}")
    end = int(field(rows[0], "end_rva", str), 16)
    if not 0 <= rva < end <= 0xffffffff:
        raise ValueError("invalid discovered function extent")
    offsets = []
    for section in field(module, "sections", list):
        start = int(field(section, "rva", str), 16)
        extent = min(field(section, "virtual_size", int), field(section, "raw_size", int))
        if start <= rva and end <= start + extent and field(section, "permissions", str).endswith("x"):
            offsets.append(field(section, "file_offset", int) + rva - start)
    if len(offsets) != 1 or offsets[0] < 0:
        raise ValueError("function range requires one executable file-backed section")

    # PE base relocations can start before the selected function and still touch it.
    def overlaps(reloc):
        address = int(field(reloc, "rva", str), 16)
        width = {0: 0, 1: 2, 2: 2, 3: 4, 4: 2}.get(field(reloc, "type", int), 8)
        return width > 0 and address < end and address + width > rva

    relocated = any(overlaps(reloc) for block in field(module, "relocations", list)
                    for reloc in field(block, "entries", list))
    return SelectedFunction(rva, end, offsets[0], module["image_kind"], relocated)


def analyze(forge, image, symbol, work):
    inspect_path, analysis_path = work / "inspect.json", work / "analysis.json"
    native.command([forge, "inspect", image, "--format", "json"], work / "inspect.log", inspect_path)
    native.command([forge, "analyze", image, "--functions", "--format", "json"],
                   work / "analysis.log", analysis_path)
    return resolve_export(read_json(inspect_path), read_json(analysis_path), symbol)


def lift(forge, image, case, selected, ir):
    if os.path.lexists(ir):
        raise ValueError(f"lift needs a fresh output path: {ir}")
    work = ir.parent.parent
    log, stdout = work / "lifting.log", work / "lifting.stdout"
    args = [forge, "lift", image, "--rva", hex(selected.start), "--signature", case["signature"],
            "--output", ir, "--diagnostics-format", "json"]
    with stdout.open("wb") as output, log.open("wb") as errors:
        status = native.command_status(args, output, errors)

    if stdout.stat().st_size:
        raise ValueError(f"forge lift exited {status} with unexpected stdout ({stdout.name})")
    if status == 0:
        if log.stat().st_size:
            raise ValueError(f"forge lift exited 0 with unexpected diagnostics ({log.name})")
        if ir.is_symlink() or not ir.is_file() or not ir.stat().st_size:
            raise ValueError(f"forge lift exited 0 without producing IR: {ir}")
        return
    if status != 1 or os.path.lexists(ir):
        raise ValueError(f"unexpected forge lift status {status} or output after failure ({log.name})")
    try:
        diagnostic = parse_diagnostic(log.read_bytes(), image, selected, ir)
    except ValueError as error:
        raise ValueError(f"invalid forge lift diagnostic ({log.name}): {error}") from error
    detail = f"{diagnostic['stage']}/{diagnostic['code']}: {diagnostic['message']} ({log.name})"
    if diagnostic["category"] == "unsupported":
        raise Unsupported(detail)
    raise ValueError(detail)


def native_differences(wanted, actual, harness, args):
    mismatches = differences(wanted, actual)
    for mismatch in mismatches:
        if harness in ("decimal_pairs", "calculate_pairs") and mismatch["field"] == "stdout":
            offset = mismatch["offset"]
            first = 2 * wanted.stdout.count(b"\n", 0, offset)
            if offset < len(wanted.stdout) and first + 1 < len(args):
                mismatch["operands"] = args[first:first + 2]
    return mismatches


@contextmanager
def timed(timings, phase):
    start = time.monotonic()
    try:
        yield
    finally:
        timings[phase] += time.monotonic() - start


def run_variant(ir, harness, args, wanted, work, identity, variant, timings):
    stages = dict.fromkeys(NATIVE_STAGES, "not_run")
    report = dict(identity, variant=variant, stages=stages)
    stage = "native_compilation"
    try:
        work.mkdir(exist_ok=True)
        executable, compiler_input = native.build(ir, harness, work, identity["build_config"], variant)
        report["compiler_ir_sha256"] = file_sha256(compiler_input)
        stages[stage] = "passed"

        stage = "native_execution"
        with timed(timings, stage):
            actual = native.execute(executable, args, work)
        report["native_exit_code"] = actual.exit_code
        report["execution_outcome"] = "completed"
        stages[stage] = "passed"

        stage = "comparison"
        with timed(timings, stage):
            mismatches = native_differences(wanted, actual, harness, args)
        if mismatches:
            report.update(status="behavioral_failure", differences=mismatches,
                          failure_categories=[e["field"] + "_mismatch" for e in mismatches])
            stages[stage] = "failed"
        else:
            report["status"] = stages[stage] = "passed"
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, native.ExecutionFailure):
            report["execution_outcome"] = error.outcome
            if error.status is not None:
                report["native_process_status"] = error.status
        report.update(status="infrastructure_failure", diagnostic=str(error),
                      failure_categories=[stage + "_failure"])
        stages[stage] = "failed"
    return report


def run_case(manifest, case, config, binaries, references, forge, work, timings):
    report = dict(schema_version=1, fixture_id=manifest.case["id"], build_config=config,
                  status="uncovered", scope=None)
    enabled = case is not None and "blocked_reason" not in case
    report.update(run_id=os.environ.get("FORGE_TEST_RUN_ID"), stages={"reference_validation": "not_run"})
    if enabled:
        report.update(scope=case["scope"], function=case["export"], signature=case["signature"],
                      native_target=f"{platform.system()}/{platform.machine()}",
                      stages=dict.fromkeys(STAGES, "not_run"))
    stage = "reference_validation"
    stages = report["stages"]
    try:
        with timed(timings, stage):
            directory(binaries, config)
            if enabled:
                image, digest = snapshot(binaries, config, manifest.case["binary"], work)
            else:
                _, digest = verified_export(binaries, config, manifest.case["binary"])
            report["binary_sha256"] = digest
            wanted, report["reference"] = reference(references, manifest, config, digest)
        stages[stage] = "passed"

        if not enabled:
            if case:
                report.update(status="blocked", diagnostic=case["blocked_reason"])
            return report

        stage = "analysis"
        with timed(timings, stage):
            report["forge_sha256"] = sha256(forge.read_bytes())
            selected = analyze(forge, image, case["export"], work)
        report["function_rva"] = hex(selected.start)
        stages[stage] = "passed"

        stage = "lifting"
        if wanted.exit_code:
            raise ValueError(f"function harness cannot convey Windows termination status {wanted.exit_code}")
        ir = work / CANONICAL_IR
        ir.parent.mkdir(exist_ok=True)
        with timed(timings, stage):
            lift(forge, image, case, selected, ir)
        identity = {key: report[key] for key in ("fixture_id", "build_config", "binary_sha256", "run_id")}
        identity["canonical_ir_sha256"] = file_sha256(ir)
        stages[stage] = "passed"

        variants = {}
        for variant in VARIANTS:
            variant_work = work / variant
            variants[variant] = run_variant(ir, case["harness"], manifest.case["args"], wanted,
                                            variant_work, identity, variant, timings)
        report["variants"] = variants
        for name in NATIVE_STAGES:
            states = [r["stages"][name] for r in variants.values()]
            stages[name] = "failed" if "failed" in states else "not_run" if "not_run" in states else "passed"
        failures = {v: r for v, r in variants.items() if r["status"] != "passed"}
        if failures:
            report["status"] = ("infrastructure_failure" if any(r["status"] == "infrastructure_failure"
                                for r in failures.values()) else "behavioral_failure")
            report["failure_categories"] = sorted({c for r in failures.values() for c in r["failure_categories"]})
            report["diagnostic"] = "\n".join(f"{v}: {r.get('diagnostic', r['status'])}" for v, r in failures.items())
        else:
            report["status"] = "passed"
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
        capability = isinstance(error, Unsupported)
        report.update(status="infrastructure_failure", diagnostic=str(error),
                      failure_categories=["unsupported_lifting_capability" if capability else stage + "_failure"])
        stages[stage] = "failed"
    return report


def contains_path(parent, path):
    resolved = path.resolve()
    if resolved.is_relative_to(parent.resolve()):
        return True
    try:
        identity = parent.stat()
    except FileNotFoundError:
        return False
    # A case-insensitive volume can retain two spellings for the same directory.
    # Inspect the resolved ancestry as well as the path used to reach a symlink.
    for ancestor in dict.fromkeys((resolved, *resolved.parents, *path.absolute().parents)):
        try:
            if os.path.samestat(identity, ancestor.stat()):
                return True
        except FileNotFoundError:
            continue
    return False


def run_selection(selected, definitions, config, binaries, references, forge, folder, jobs, full_suite, step_summary):
    workers = min(jobs, len(selected))
    stop = native.ActiveProcesses()
    started = time.monotonic()

    def run_group(index):
        group = selected[index::workers]
        cases = [definitions[m.case["id"], config] for m in group
                 if (m.case["id"], config) in definitions and "blocked_reason" not in definitions[m.case["id"], config]]
        timings = Counter()
        compiler = native.SuiteBuild(folder / "cmake-workers" / str(index + 1), config, folder, cases, stop, timings)
        token = native.current_worker.set(compiler if full_suite else None)
        try:
            for manifest in group:
                name = manifest.case["id"]
                work = folder / name
                work.mkdir(parents=True, exist_ok=True)
                result = run_case(manifest, definitions.get((name, config)), config, binaries, references,
                                  forge, work, timings)
                write_json(work / "result.json", result)
            return timings
        finally:
            native.current_worker.reset(token)

    if workers == 1:
        timings = run_group(0)
    else:
        timings = Counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            try:
                futures = [pool.submit(run_group, i) for i in range(workers)]
                for future in as_completed(futures):
                    timings.update(future.result())
            except BaseException:
                stop.cancel()
                raise
    elapsed = time.monotonic() - started
    details = ", ".join(f"{name}={value:.2f}s" for name, value in sorted(timings.items()))
    line = f"Differential {config}: {elapsed:.2f}s wall, {workers} worker(s). {details} (summed across workers)."
    print(line)
    if full_suite and step_summary:
        with Path(step_summary).open("a") as stream:
            print(f"- {line}", file=stream)


def run(config, fixture=None, *, binaries=BINARIES, references=REFERENCES, output=OUTPUT,
        forge=DEFAULT_FORGE, suite=SUITE, jobs=1, step_summary=None):
    if config not in ("debug", "release") or (fixture is not None and not FIXTURE_ID.fullmatch(fixture)):
        raise ValueError("invalid configuration or fixture ID")
    if jobs < 1:
        raise ValueError("jobs must be positive")
    folder = output / config
    output.mkdir(parents=True, exist_ok=True)
    with (output / ("." + config + ".lock")).open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for source in (binaries / config, references / config):
            if contains_path(folder, source) or contains_path(source, folder):
                raise ValueError(f"differential output overlaps input artifacts: {source}")
        target = folder / fixture if fixture else folder
        if target.absolute() != target.resolve():
            raise ValueError(f"refusing symbolic link in output path: {target}")
        summary_path = folder / "suite.json"
        if contains_path(target, forge) or contains_path(summary_path, forge):
            raise ValueError(f"differential output overlaps selected Forge executable: {forge}")
        folder.mkdir(exist_ok=True)
        summary_path.unlink(missing_ok=True)
        if target.exists():
            shutil.rmtree(target)
        folder.mkdir(exist_ok=True)
        summary = dict(schema_version=1, build_config=config, selection=fixture or "all",
                       status="failed", executed=0, passed=0, uncovered=0, blocked=0, cases=[],
                       run_id=os.environ.get("FORGE_TEST_RUN_ID"))
        try:
            catalog = load_catalog(suite)
            cases = case_definitions(catalog, suite / "cases.json")
            selected = [m for m in catalog if fixture is None or m.case["id"] == fixture]
            if not selected:
                raise ValueError(f"unknown fixture {fixture!r}")
            run_selection(selected, cases, config, binaries, references, forge, folder, jobs, fixture is None, step_summary)
            for manifest in selected:
                name = manifest.case["id"]
                result = read_json(folder / name / "result.json")
                status = result["status"]
                summary["cases"].append(dict(fixture_id=name, status=status, scope=result["scope"],
                                             report=name + "/result.json"))
                summary["passed"] += status == "passed"
                summary["uncovered"] += status == "uncovered"
                summary["blocked"] += status == "blocked"
                summary["executed"] += any(v.get("execution_outcome") == "completed"
                                           for v in result.get("variants", {}).values())
                label = f"{status.upper()} {name} [{config}]"
                print(f"{label} {result['scope']}" if result["scope"] else label)
                if "stages" in result:
                    print("  " + ", ".join(f"{k}={v}" for k, v in result["stages"].items()))
                if "reference" in result and result["scope"]:
                    print(f"  {result['reference']['wine_version']} -> {result['native_target']}, "
                          f"{result['function']} {result.get('function_rva', '(unresolved)')} {result['signature']}")
                if "diagnostic" in result:
                    print(result["diagnostic"])
                for variant, evidence in result.get("variants", {}).items():
                    print(f"  {variant}: {evidence['status']}")
                    for mismatch in evidence.get("differences", []):
                        print("  " + describe(mismatch))
                        if "operands" in mismatch:
                            print("  operands: " + ", ".join(mismatch["operands"]))
            if not summary["executed"]:
                raise ValueError("zero differential cases executed")
            if summary["passed"] + summary["uncovered"] + summary["blocked"] == len(selected):
                summary["status"] = "passed"
        except (OSError, ValueError) as error:
            summary["diagnostic"] = str(error)
            print(error, file=sys.stderr)
        write_json(summary_path, summary)
        print(f"{summary['passed']} passed, {summary['executed']} executed, "
              f"{summary['uncovered']} reference only, {summary['blocked']} blocked. Report: {summary_path}")
        return int(summary["status"] != "passed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    group.add_argument("--fixture", metavar="CATEGORY/NAME")
    parser.add_argument("--jobs", type=int, default=1, metavar="N", help="maximum concurrent fixture workers")
    parser.add_argument("--config", required=True, choices=("debug", "release"))
    parser.add_argument("--reference-root", type=Path, default=REFERENCES)
    parser.add_argument("--binary-root", type=Path, default=BINARIES)
    parser.add_argument("--forge", type=Path, default=DEFAULT_FORGE, metavar="PATH",
                        help="Forge executable (default: dev/forge under the build root)")
    options = parser.parse_args(argv)
    return run(options.config, options.fixture, references=options.reference_root,
               binaries=options.binary_root, forge=options.forge.resolve(), jobs=options.jobs,
               step_summary=os.environ.get("GITHUB_STEP_SUMMARY"))


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit(130)
