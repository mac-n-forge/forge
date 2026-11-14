"""Integration checks for the published matrix and the real pinned Wine launcher."""
import json
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

from docker_wine import execute
from run import BINARIES, REFERENCES, SUITE, load_catalog, reference_environment, sha256
from artifacts import reference
from calculate_driver_cases import CASES as CALCULATE_INPUTS


class WineTests(unittest.TestCase):
    def test_calculate_driver(self):
        image = reference_environment(SUITE)["container_image_id"]
        for config in ("debug", "release"):
            for args, status, stdout in CALCULATE_INPUTS:
                with self.subTest(config=config, args=args):
                    result = execute(image, BINARIES / config / "calculate.exe", args)
                    self.assertEqual((result.exit_code, result.stdout, result.stderr), (status, stdout, b""))

    def test_complete_matrix(self):
        catalog = load_catalog()
        for config in ("debug", "release"):
            root = REFERENCES / config
            self.assertEqual({path.parent.relative_to(root).as_posix()
                              for path in root.rglob("result.json")}, {m.case["id"] for m in catalog})
            for manifest in catalog:
                case = manifest.case
                with self.subTest(config=config, fixture=case["id"]):
                    digest = sha256((BINARIES / config / case["binary"]).read_bytes())
                    observed, _ = reference(REFERENCES, manifest, config, digest)
                    self.assertEqual(observed.exit_code, case["expected"]["exit_code"])
                    for stream in ("stdout", "stderr"):
                        self.assertEqual(getattr(observed, stream), case["expected"][stream].encode("utf-8"))
            for name, exit_code, stderr in (("stderr_only", 0, b"runner-error\n"), ("exit_nonzero", 7, b"")):
                runner = root / "runner" / name
                self.assertEqual(json.loads((runner / "result.json").read_bytes())["exit_code"], exit_code)
                self.assertEqual((runner / "stdout.bin").read_bytes(), b"")
                self.assertEqual((runner / "stderr.bin").read_bytes(), stderr)
            combined = root / "runner/exit_and_stderr"
            self.assertEqual(json.loads((combined / "result.json").read_bytes())["exit_code"], 4660)
            self.assertEqual((combined / "stdout.bin").read_bytes(), b"")
            self.assertEqual((combined / "stderr.bin").read_bytes(), b"runner-error\n")

    def test_capture_boundaries(self):
        image = reference_environment(SUITE)["container_image_id"]
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            binary = directory / "probe.exe"
            source = Path(__file__).with_name("test_probe.c").resolve()
            subprocess.run(["docker", "run", "--pull", "never", "--rm", "--platform", "linux/amd64", "--network", "none",
                            "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{directory}:/output",
                            "-v", f"{source}:/input/test.c:ro", "--entrypoint", "x86_64-w64-mingw32-gcc-win32",
                            image, "-std=c11", "-Wall", "-Wextra", "-Werror", "-municode", "-static",
                            "/input/test.c", "-o", "/output/probe.exe"], check=True)
            args = ["", "two words", 'embedded"quote', 'backslash\\"quote', "sp ace\\", "café", "a&b"]
            observation = execute(image, binary, args, container_env=("WINEDEBUG=-all,trace+loaddll",
                                                                     "FORGE_TEST_HOST_ONLY=sentinel"))
            self.assertEqual(observation.stdout, b"".join(arg.encode() + b"\0" for arg in args))
            self.assertEqual(observation.stderr, b"")
            self.assertEqual(observation.exit_code, 0)
            self.assertEqual(execute(image, binary, []).exit_code, 0xc0000135)
            for arg, failure in (("--flood", "output-size limit"), ("--sleep", "execution timeout")):
                with self.subTest(arg=arg), self.assertRaisesRegex(ValueError, failure):
                    execute(image, binary, [arg])
            # Only the imported DLL basename changes; the PE layout stays intact.
            data = binary.read_bytes()
            self.assertIn(b"msvcrt.dll\0", data)
            binary.write_bytes(data.replace(b"msvcrt.dll\0", b"absent.dll\0"))
            with self.assertRaisesRegex(ValueError, "missing Windows runtime dependency"):
                execute(image, binary, [])
            binary.write_bytes(b"not an executable")
            with self.assertRaisesRegex(ValueError, "invalid or unsupported PE"):
                execute(image, binary, [])


if __name__ == "__main__":
    unittest.main()
