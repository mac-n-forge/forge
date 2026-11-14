"""Compile a generated module through the Forge CMake project and observe its harness."""
from contextlib import contextmanager, nullcontext, suppress
from contextvars import ContextVar
import errno
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import tempfile
import threading
import time

from comparison import Observation
from manifests import SUITE

from docker_wine import EXECUTION_TIMEOUT
from protocol import STREAM_LIMIT

current_worker = ContextVar("differential_worker", default=None)

OPTIMIZED_IR = Path("native/tests/optimized.ll")


class ExecutionFailure(ValueError):
    def __init__(self, outcome, message, status=None):
        super().__init__(message)
        self.outcome = outcome
        self.status = status


def kill_group(process):
    with suppress(ProcessLookupError):
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except PermissionError as error:
            if error.errno != errno.EPERM or platform.system() != "Darwin":
                raise
        # macOS can report EPERM when the only group member is exiting.
        # Reap it if possible, then signal the group again for any descendants.
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.1)
        os.killpg(process.pid, signal.SIGKILL)


class ActiveProcesses:
    """Let the main thread interrupt all compiler and harness process groups before joining workers."""
    def __init__(self):
        self.lock = threading.Lock()
        self.processes = set()
        self.cancelled = False

    def add(self, process):
        with self.lock:
            if self.cancelled:
                raise KeyboardInterrupt
            self.processes.add(process)

    def remove(self, process):
        with self.lock:
            self.processes.discard(process)

    def cancel(self):
        with self.lock:
            self.cancelled = True
            for process in self.processes:
                kill_group(process)


@contextmanager
def supervised(args, **options):
    worker = current_worker.get()
    stop = worker.stop if worker is not None else None
    with subprocess.Popen(args, start_new_session=True, **options) as process:
        try:
            if stop is not None:
                stop.add(process)
            yield process
        finally:
            if stop is not None:
                stop.remove(process)
            kill_group(process)
            process.wait()


def command_status(args, stdout, stderr, *, timeout=180):
    with supervised(args, stdout=stdout, stderr=stderr) as process:
        return process.wait(timeout=timeout)


def command(args, log, stdout=None, *, timeout=180):
    with log.open("ab") as errors, (stdout.open("wb") if stdout else nullcontext(errors)) as output:
        status = command_status(args, output, errors, timeout=timeout)
    if status:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 4096))
            tail = stream.read().decode("utf-8", "backslashreplace")
        raise ValueError(f"{args[0]} exited {status} ({log.name})\n{tail}")


def configure(tree, config, args):
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("native differential execution requires macOS arm64")
    return ["cmake", "-S", SUITE.parents[1], "-B", tree, "-DBUILD_TESTING=OFF", "-DFORGE_BUILD_CLI=OFF",
            "-DCMAKE_TOOLCHAIN_FILE:FILEPATH=", f"-DCMAKE_BUILD_TYPE={config.capitalize()}", *args]


def phase(name, args, log, timings=None):
    with log.open("a") as stream:
        print(f"\n--- {name} ---", file=stream)
    started = time.monotonic()
    try:
        command(args, log)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise ValueError(f"native {name} failed: {error}") from error
    finally:
        elapsed = time.monotonic() - started
        if timings is not None:
            timings[name] += elapsed
        with log.open("a") as stream:
            print(f"{name}: {elapsed:.3f}s", file=stream)


class SuiteBuild:
    """One fresh CMake project for a worker's disjoint fixture and variant targets."""
    def __init__(self, tree, config, folder, cases, stop, timings):
        self.tree = tree
        self.config = config
        self.folder = folder
        self.harnesses = {case["fixture_id"]: case["harness"] for case in cases}
        self.stop = stop
        self.timings = timings
        self.configured = False
        self.error = None

    def build(self, ir, harness, work, config, variant):
        case_id = work.parent.relative_to(self.folder)
        if config != self.config or self.harnesses.get(case_id.as_posix()) != harness:
            raise ValueError(f"unknown suite build target: {case_id} [{config}] harness {harness}")
        if variant not in ("baseline", "o2") or work.name != variant:
            raise ValueError(f"suite variant {variant} disagrees with output {work}")
        if ir != work.parent / "generated/lifted.ll":
            raise ValueError(f"unexpected suite compiler input: {ir}")
        configuration_log = self.tree / "configuration.log"
        with (work / "compilation.log").open("a") as log:
            print(f"Shared configuration: {os.path.relpath(configuration_log, work)}", file=log)
        if self.error is not None:
            raise ValueError(self.error)
        if not self.configured:
            self.tree.mkdir(parents=True)
            entries = ";".join(f"{name}:{contract}" for name, contract in self.harnesses.items())
            args = [f"-DFORGE_DIFFERENTIAL_CASES={entries}", f"-DFORGE_DIFFERENTIAL_OUTPUT={self.folder}"]
            try:
                phase("configuration", configure(self.tree, self.config, args), configuration_log, self.timings)
            except (OSError, ValueError) as error:
                self.error = f"{error} ({configuration_log})"
                raise ValueError(self.error) from error
            self.configured = True

        target = "-".join(("diff", *case_id.parts, variant))
        return build_targets(self.tree, target, ir, harness, work, config, variant, self.timings)


def build(ir, harness, work, config, variant):
    worker = current_worker.get()
    if worker is not None:
        return worker.build(ir, harness, work, config, variant)
    tree = work / "native"
    args = [f"-DFORGE_DIFFERENTIAL_IR={ir}", f"-DFORGE_DIFFERENTIAL_VARIANT={variant}",
            f"-DFORGE_DIFFERENTIAL_HARNESS={harness}"]
    phase("configuration", configure(tree, config, args), work / "compilation.log")
    return build_targets(tree, "differential_" + harness, ir, harness, work, config, variant)


def build_targets(tree, target, ir, harness, work, config, variant, timings=None):
    command_line = ["cmake", "--build", tree, "--config", config.capitalize(), "--target"]
    log = work / "compilation.log"
    phase("object compilation", [*command_line, target + "_objects"], log, timings)
    phase("linking", [*command_line, target], log, timings)
    executable = work / "native/bin" / ("differential_" + harness)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError(f"native linking did not produce an executable harness: {executable} ({log.name})")
    return executable, work / OPTIMIZED_IR if variant == "o2" else ir


def execute(executable, args, work, *, timeout=EXECUTION_TIMEOUT, limit=STREAM_LIMIT):
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with tempfile.TemporaryDirectory(dir=work) as cwd, supervised(
                [executable, *args], cwd=cwd, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=dict(LC_ALL="C", TZ="UTC", HOME=cwd, TMPDIR=cwd, PATH="/usr/bin:/bin")) as process:
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as select:
                select.register(process.stdout, selectors.EVENT_READ, "stdout")
                select.register(process.stderr, selectors.EVENT_READ, "stderr")
                while select.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ExecutionFailure("timeout", "native execution timeout")
                    for key, _ in select.select(remaining):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            select.unregister(key.fd)
                            continue
                        data = streams[key.data]
                        room = limit - len(data)
                        data.extend(chunk[:room])
                        if len(chunk) > room:
                            raise ExecutionFailure("output_limit", f"{key.data} output-size limit exceeded "
                                                   f"({limit} bytes)")
            try:
                status = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise ExecutionFailure("timeout", "native execution timeout") from error
            if status < 0:
                raise ExecutionFailure("signaled", f"native harness terminated by signal {-status}", status)
            if status:
                raise ExecutionFailure("harness_error", f"native harness exited {status}", status)
    finally:
        for name, data in streams.items():
            (work / (name + ".bin")).write_bytes(data)
    return Observation(status, bytes(streams["stdout"]), bytes(streams["stderr"]))
