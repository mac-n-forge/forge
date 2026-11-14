"""Exercise the build and provisioning entry points in disposable directories."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

MODE = sys.argv[1]
SOURCE, CMAKE, LLVM_DIR, LLVM_BIN, TMP_ROOT = map(Path, sys.argv[2:7])
WITH_CLI, TOOLCHAIN, CONFIG, GENERATOR = sys.argv[7:]


def read_cache(build):
    lines = (build / "CMakeCache.txt").read_text().splitlines()
    return {line.split(":", 1)[0]: line.split("=", 1)[1] for line in lines
            if line and not line.startswith(("#", "//")) and "=" in line}


class BuildCase(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=TMP_ROOT, prefix="build checks ")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.env = dict(os.environ, CMAKE_GENERATOR="Unix Makefiles")
        for key in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "LLVM_DIR", "LLVM_CONFIG", "CMAKE_ARGS", "CONFIG",
                    "BUILD_TESTING", "SANITIZE", "BUILD_DIR", "BUILD_ROOT", "FORGE_PRESET",
                    "FORGE_BUILD_ROOT", "PRESET", "WITH_CLI", "CACHE_ONLY", "CMAKE_TOOLCHAIN_FILE",
                    "CMAKE_GENERATOR_PLATFORM", "CMAKE_GENERATOR_TOOLSET"):
            self.env.pop(key, None)
        self.env["PATH"] = str(CMAKE.parent) + os.pathsep + self.env["PATH"]

    def invoke(self, *command, cwd=SOURCE, env=None, success=True):
        p = subprocess.run(command, cwd=cwd, env=env or self.env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(p.returncode == 0, success, f"{command}\n{p.stdout}")
        return p.stdout

    def copy_build_files(self, dest):
        dest.mkdir()
        for name in ("CMakeLists.txt", "CMakePresets.json", "Makefile"):
            shutil.copyfile(SOURCE / name, dest / name)
        shutil.copytree(SOURCE / "cmake", dest / "cmake")


class BuildConfig(BuildCase):
    def test_in_source_configure_preserves_makefile(self):
        for name, command in [("make", ["make", "configure", "BUILD_DIR=."]),
                              ("cmake", [CMAKE, "-S", ".", "-B", "."])]:
            with self.subTest(command=name):
                src = self.tmp / name
                self.copy_build_files(src)
                output = self.invoke(*command, cwd=src, success=False)
                self.assertRegex(output.lower(), r"out.of.source|source (directory|tree|or output root)")
                self.assertEqual((src / "Makefile").read_bytes(), (SOURCE / "Makefile").read_bytes())

    def test_container_directory_is_rejected(self):
        src = self.tmp / "source"
        self.copy_build_files(src)
        output = self.invoke(CMAKE, "-S", src, "-B", src / "build", success=False)
        self.assertIn("build", output)
        self.assertRegex(output.lower(), r"container|reserved|preset")

    def test_unprovisioned_cli_ignores_global_package(self):
        decoy = self.tmp / "global package"
        decoy.mkdir()
        (decoy / "CLI11Config.cmake").write_text('message(FATAL_ERROR "Global CLI11 loaded")\n')
        output = self.invoke(CMAKE, "-S", SOURCE, "-B", self.tmp / "cli", f"-DLLVM_DIR={LLVM_DIR}",
                             "-DBUILD_TESTING=OFF", f"-DCLI11_DIR={decoy}", success=False)
        self.assertIn("provision", output.lower())
        self.assertNotIn("Global CLI11 loaded", output)

    def run_configure(self, *options, env=None):
        return subprocess.run([CMAKE, "-S", SOURCE, "-B", self.tmp / "configure", "-DFORGE_BUILD_CLI=OFF", *options],
                              env=env or self.env, capture_output=True, text=True)

    def test_config_selector_and_invalid_explicit_package(self):
        selected = self.run_configure("-DBUILD_TESTING=OFF", f"-DLLVM_CONFIG={LLVM_BIN / 'llvm-config'}")
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertIn(f"at {LLVM_DIR}", selected.stdout)
        failed = self.run_configure(f"-DLLVM_DIR={self.tmp / 'absent'}")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Invalid LLVM_DIR", " ".join(failed.stderr.split()))

    def test_core_and_harness_without_cli(self):
        build = self.tmp / "core"
        self.invoke(CMAKE, "-S", SOURCE, "-B", build, f"-DLLVM_DIR={LLVM_DIR}", "-DBUILD_TESTING=ON",
                    "-DFORGE_BUILD_CLI=OFF", "-DCMAKE_DISABLE_FIND_PACKAGE_CLI11=TRUE")
        targets = self.invoke(CMAKE, "--build", build, "--target", "help").split()
        self.assertNotIn("forge", targets)
        self.assertIn("forge_core", targets)
        self.invoke(CMAKE, "--build", build, "--target", "forge_native_harness", "lift_command", "--parallel", "4")
        self.invoke(CMAKE.parent / "ctest", "--test-dir", build, "-R", "^lift_command$", "--output-on-failure",
                    "--no-tests=error")
        result = self.invoke(CMAKE.parent / "ctest", "--test-dir", build, "--show-only=json-v1")
        names = {test["name"] for test in json.loads(result)["tests"]}
        self.assertTrue({"fixtures", "input_lifetime", "lift_contract", "lift_command", "build_config"} <= names)
        self.assertFalse({"cli", "codegen", "native", "differential", "build_provisioning"} & names)

    @unittest.skipUnless(WITH_CLI == "1", "requires a CLI-enabled parent toolchain")
    def test_cli_selection_follows_the_toolchain(self):
        output = self.invoke(CMAKE, "-S", SOURCE, "-B", self.tmp / "conflicting", "-G", GENERATOR,
                             f"-DCMAKE_TOOLCHAIN_FILE={TOOLCHAIN}", f"-DCMAKE_BUILD_TYPE={CONFIG}",
                             f"-DLLVM_DIR={LLVM_DIR}", "-DFORGE_BUILD_CLI=OFF", success=False)
        self.assertIn("with_cli", output)

    def test_rejects_unsupported_package(self):
        package = self.tmp / "old"
        package.mkdir()
        (package / "LLVMConfig.cmake").write_text('set(LLVM_PACKAGE_VERSION "17.0.6")\n')
        failed = self.run_configure(f"-DLLVM_DIR={package}")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("requires stable LLVM 23.x", failed.stderr)
        self.assertIn("17.0.6", failed.stderr)

    def test_conflicting_selectors(self):
        other = self.tmp / "other"
        other.mkdir()
        (other / "LLVMConfig.cmake").touch()
        env = dict(self.env, LLVM_CONFIG=str(LLVM_BIN / "llvm-config"))
        for command in ([CMAKE, "-S", SOURCE, "-B", self.tmp / "configure", "-DFORGE_BUILD_CLI=OFF", f"-DLLVM_DIR={other}"],
                        ["make", "format-check", f"LLVM_DIR={other}"]):
            with self.subTest(command=command[0]):
                failed = subprocess.run(command, env=env, cwd=SOURCE, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("Conflicting LLVM_DIR", " ".join(failed.stderr.split()))

    def test_rejects_unrelated_explicit_tool(self):
        decoy = self.tmp / "llvm-mc"
        decoy.write_text("#!/bin/sh\nexit 0\n")
        decoy.chmod(0o755)
        failed = self.run_configure(f"-DLLVM_DIR={LLVM_DIR}", f"-Dllvm-mc:FILEPATH={decoy}")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Conflicting llvm-mc", " ".join(failed.stderr.split()))

    def test_missing_differential_tool_ignores_path(self):
        if sys.platform != "darwin":
            self.skipTest("the differential harness configures on macOS")
        # Wrap the real package. Advertise a tool directory containing only
        # llvm-config, with the genuine opt available as a tempting PATH fallback.
        package = self.tmp / "package"
        package.mkdir()
        tools = self.tmp / "bin"
        tools.mkdir()
        (package / "LLVMConfig.cmake").write_text(
            f"include([[{LLVM_DIR}/LLVMConfig.cmake]])\nset(LLVM_TOOLS_BINARY_DIR [[{tools}]])\n")
        config = tools / "llvm-config"
        config.write_text(f'#!/bin/sh\nif [ "$1" = --bindir ]; then dirname "$0"; '
                          f'else exec "{LLVM_BIN / "llvm-config"}" "$@"; fi\n')
        config.chmod(0o755)
        env = dict(self.env, PATH=str(LLVM_BIN) + os.pathsep + self.env["PATH"])
        failed = self.run_configure(f"-DLLVM_DIR={package}", "-DBUILD_TESTING=OFF",
                                    f"-DFORGE_DIFFERENTIAL_IR={self.tmp / 'lift.ll'}", env=env)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Missing required LLVM tool 'opt'", " ".join(failed.stderr.split()))

    @unittest.skipUnless(WITH_CLI == "1", "requires a provisioned CLI")
    def test_fresh_cli_and_external_database(self):
        # Model an LLVM installation that exports a shared include root containing another CLI11.
        package = self.tmp / "llvm package"
        headers = package / "include" / "CLI"
        headers.mkdir(parents=True)
        (headers / "CLI.hpp").write_text('#error "Global CLI11 header loaded"\n')
        (package / "LLVMConfig.cmake").write_text(
            f"include([[{LLVM_DIR}/LLVMConfig.cmake]])\nlist(APPEND LLVM_INCLUDE_DIRS [[{headers.parent}]])\n")
        options = [f"-DLLVM_DIR={package}", f"-DCMAKE_TOOLCHAIN_FILE={TOOLCHAIN}", "-DBUILD_TESTING=OFF"]
        if GENERATOR == "Xcode":
            # Xcode does not export compile_commands.json. Its lint workflow uses the lint preset.
            build = self.tmp / "ide build"
            self.invoke(CMAKE, "-G", GENERATOR, "-S", SOURCE, "-B", build, *options)
            self.invoke(CMAKE, "--build", build, "--config", CONFIG, "--target", "forge", "--parallel", "4")
            self.assertTrue((build / CONFIG / "forge").is_file())
            return
        build = self.tmp / "analysis build"
        self.invoke(CMAKE, "-S", SOURCE, "-B", build, *options, f"-DCMAKE_BUILD_TYPE={CONFIG}",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")
        database = build / "compile_commands.json"
        contents = database.read_bytes()
        entries = json.loads(contents)
        harness = SOURCE / "tests/support/native_harness.cpp"
        self.assertIn(str(harness), [e["file"] for e in entries])
        self.assertIn(str(SOURCE / "tests/support/register_state.cpp"), [e["file"] for e in entries])
        self.assertIn(str(SOURCE / "tests/unit/integer.cpp"), [e["file"] for e in entries])
        self.invoke(CMAKE, "--build", build, "--parallel", "4")
        self.assertTrue((build / "forge").is_file())
        self.assertFalse((build / "tests/integer_semantics").exists())
        self.assertFalse(list(build.rglob("register_state.cpp.o")))
        if read_cache(build)["FORGE_CONAN_PRESET"] == "sanitize":
            parsing = next(e for e in entries if e["file"] == str(SOURCE / "src/cli/parsing.cpp"))
            self.assertIn("-fsanitize=address,undefined", parsing["command"])
            self.assertIn("-fsanitize=address,undefined", (build / "CMakeFiles/forge.dir/link.txt").read_text())
            failed = self.invoke(CMAKE, "-S", SOURCE, "-B", self.tmp / "unsanitized", *options,
                                 f"-DCMAKE_BUILD_TYPE={CONFIG}", "-DFORGE_ENABLE_SANITIZERS=OFF", success=False)
            self.assertIn("FORGE_ENABLE_SANITIZERS conflicts", failed)

        # Exercise the wrapper even on machines without clang-tidy.
        config = self.tmp / "llvm-config"
        config.write_text(f'#!/bin/sh\nif [ "$1" = --bindir ]; then dirname "$0"; '
                          f'else exec "{LLVM_BIN / "llvm-config"}" "$@"; fi\n')
        config.chmod(0o755)
        tidy = self.tmp / "clang-tidy"
        tidy.write_text('#!/bin/sh\ncase "$1" in\n'
                        '  --version) echo "LLVM version 23.1.5" ;;\n'
                        '  *) for arg do case "$arg" in --checks=-readability-*) '
                        'printf "%s\\n" "$@" > "$0.args";; esac; done ;;\n'
                        'esac\n')
        tidy.chmod(0o755)
        command = ["make", "lint", f"LLVM_CONFIG={config}", f"LINT_DATABASE={database}"]
        env = dict(self.env, FORGE_STYLE_BASE="HEAD")
        subprocess.run(command, cwd=SOURCE, env=env, check=True)
        args = (self.tmp / "clang-tidy.args").read_text().splitlines()
        self.assertEqual(args[:2], ["-p", str(build)])
        expected = [str(p) for folder in ("src", "tests/support", "tests/unit")
                    for p in (SOURCE / folder).rglob("*.cpp")]
        self.assertTrue(any(arg.startswith("--vfsoverlay=") for arg in args))
        self.assertCountEqual([arg for arg in args if arg.endswith(".cpp")], expected)
        self.assertEqual(database.read_bytes(), contents)

        for missing in (harness, SOURCE / "src/pe/pe.cpp", SOURCE / "tests/unit/integer.cpp"):
            with self.subTest(missing=missing):
                database.write_text(json.dumps([e for e in entries if e["file"] != str(missing)]))
                failed = subprocess.run(command, cwd=SOURCE, env=self.env, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("Missing first-party compile commands", failed.stderr)
                self.assertIn(str(missing), failed.stderr)


class Provisioning(BuildCase):
    def test_cache_only_rejects_missing_package(self):
        # An empty, private cache leaves existing packages and configured remotes untouched.
        env = dict(self.env, CONAN_HOME=str(self.tmp / "empty cache"))
        args = ("make", "provision", "CACHE_ONLY=1", "PRESET=dev", f"BUILD_DIR={self.tmp / 'cold build'}")
        output = self.invoke(*args, env=env, success=False)
        self.assertIn("cli11/", output.lower())
        self.assertRegex(output.lower(), r"not (found|in cache)|missing|unable to find")
        self.assertNotIn("connecting to remote", output.lower())
        # Restore only the locked recipe; a build-allowed install could now manufacture a binary.
        revision = next(ref.split("%")[0] for ref in json.loads((SOURCE / "conan.lock").read_text())["requires"]
                        if ref.startswith("cli11/"))
        archive = self.tmp / "recipe.tgz"
        self.invoke("conan", "cache", "save", revision, "--file", archive)
        self.invoke("conan", "cache", "restore", archive, env=env)
        output = self.invoke(*args, env=env, success=False)
        self.assertIn("missing binary", output.lower())
        self.assertNotIn("connecting to remote", output.lower())

    def test_empty_cache_can_provision_core(self):
        root = self.tmp / "custom output root"
        env = dict(self.env, CONAN_HOME=str(self.tmp / "core cache"))
        self.invoke("make", "provision", f"BUILD_ROOT={root}", "PRESET=dev", "WITH_CLI=OFF", "CACHE_ONLY=1", env=env)
        self.invoke("make", "configure", f"BUILD_ROOT={root}", f"LLVM_DIR={LLVM_DIR}", env=env)
        directory = root / "dev"
        self.assertFalse((directory / "conan/CLI11Config.cmake").exists())
        self.assertFalse((root / "CMakeCache.txt").exists())
        self.assertNotIn("forge", self.invoke(CMAKE, "--build", directory, "--target", "help", env=env).split())
        output = self.invoke("make", "configure", f"BUILD_ROOT={root}", "WITH_CLI=ON", env=env, success=False)
        self.assertIn("WITH_CLI", output)

    def test_provision_repairs_first_configure_and_respects_exact_directory(self):
        tree = self.tmp / "new ASan tree"
        exact = f"BUILD_DIR={tree}"
        output = self.invoke(CMAKE, "--preset", "sanitize", "-B", tree, success=False)
        self.assertIn("make provision PRESET=sanitize", " ".join(output.split()))
        (tree / "conan").mkdir()
        foreign_config = tree / "conan/CLI11Config.cmake"
        foreign_config.write_text("existing local configuration")
        output = self.invoke("make", "provision", exact, "CACHE_ONLY=1", success=False)
        self.assertIn(str(foreign_config.parent), output)
        self.assertEqual(foreign_config.read_text(), "existing local configuration")
        self.assertEqual(list(foreign_config.parent.iterdir()), [foreign_config])
        foreign_config.unlink()
        self.invoke("make", "provision", exact, "CACHE_ONLY=1")
        self.invoke("make", "configure", exact, f"LLVM_DIR={LLVM_DIR}")
        self.assertEqual(read_cache(tree)["FORGE_CONFIGURED_PRESET"], "sanitize")

        original = (tree / "CMakeCache.txt").read_bytes()
        other = self.tmp / "another directory"
        for option in ("CONFIG=Debug", "PRESET=dev", f'CMAKE_ARGS=-B "{other}"',
                       "CMAKE_ARGS=-DFORGE_BUILD_CLI=OFF", "CMAKE_ARGS=-D FORGE_BUILD_CLI:BOOL=OFF",
                       "CMAKE_ARGS=-DFORGE_ENABLE_SANITIZERS:BOOL=OFF", "CMAKE_ARGS=-D FORGE_ENABLE_SANITIZERS=OFF"):
            with self.subTest(option=option):
                self.invoke("make", "configure", exact, option, success=False)
                self.assertEqual(original, (tree / "CMakeCache.txt").read_bytes())
        self.assertFalse(other.exists())
        self.invoke("make", "configure", exact)

        note = tree / "conan" / "local-note.txt"
        note.write_text("retained")
        (tree / "conan/conan_toolchain.cmake").unlink()
        self.invoke("make", "provision", exact, "CACHE_ONLY=1")
        self.assertEqual(note.read_text(), "retained")
        self.invoke("make", "clean", f"BUILD_DIR={other}")
        self.assertFalse(other.exists())

    def test_cached_llvm_and_build_type(self):
        root = self.tmp / "external output"
        build = root / "dev"
        self.invoke("make", "provision", f"BUILD_DIR={build}", "PRESET=release", "CACHE_ONLY=1")
        for action in ("provision", "configure", "clean"):
            with self.subTest(action=action):
                output = self.invoke("make", action, f"BUILD_ROOT={root}", "CACHE_ONLY=1", success=False)
                self.assertIn("PRESET=release", output)
                self.assertFalse((build / "CMakeCache.txt").exists())
        package = self.tmp / "llvm package"
        package.mkdir()
        (package / "LLVMConfig.cmake").write_text(f"include([[{LLVM_DIR}/LLVMConfig.cmake]])\n")

        def configure(*options):
            self.invoke("make", "configure", f"BUILD_DIR={build}", *options)
            return read_cache(build)

        cache = configure(f"LLVM_DIR={package}")
        self.assertEqual(cache["FORGE_CONFIGURED_PRESET"], "release")
        readobj = cache["llvm-readobj"]
        pinned = self.tmp / "pinned-readobj"
        pinned.symlink_to(readobj)
        cache = configure(f'CMAKE_ARGS="-Dllvm-readobj:FILEPATH={pinned}"')
        self.assertEqual(cache["LLVM_DIR"], str(package))
        self.assertEqual(cache["CMAKE_BUILD_TYPE"], "Release")
        self.assertEqual(cache["llvm-readobj"], str(pinned))
        cache = configure(f"LLVM_DIR={LLVM_DIR}", f"LLVM_CONFIG={LLVM_BIN / 'llvm-config'}")
        self.assertEqual(cache["LLVM_DIR"], str(LLVM_DIR))
        self.assertEqual(cache["llvm-readobj"], readobj)
        for action in ("configure", "sanitize"):
            with self.subTest(action=action):
                args = ["PRESET=dev"] if action == "configure" else []
                self.invoke("make", action, f"BUILD_DIR={build}", *args, success=False)
                self.assertEqual(read_cache(build)["FORGE_CONFIGURED_PRESET"], "release")

        # Direct CMake configuration can leave a conflicting cache even when it fails.
        self.invoke(CMAKE, "--preset", "release", "-B", build, "-DFORGE_BUILD_CLI=OFF", success=False)
        cache_file = build / "CMakeCache.txt"
        toolchain = build / "conan/conan_toolchain.cmake"
        poisoned = cache_file.read_bytes()
        before = toolchain.stat().st_mtime_ns
        for action in ("provision", "configure", "clean"):
            output = self.invoke("make", action, f"BUILD_DIR={build}", "CACHE_ONLY=1", success=False)
            self.assertIn("FORGE_BUILD_CLI", output)
            self.assertEqual(cache_file.read_bytes(), poisoned)
            self.assertEqual(toolchain.stat().st_mtime_ns, before)

    def test_named_configurations_in_clean_checkout(self):
        src = self.tmp / "clean checkout"
        self.copy_build_files(src)
        for name in ("src", "tests", "conan"):
            shutil.copytree(SOURCE / name, src / name)
        for name in ("conanfile.py", "conan.lock", "requirements-build.txt", ".gitignore"):
            shutil.copyfile(SOURCE / name, src / name)
        self.invoke("git", "init", "-q", cwd=src)
        self.invoke("git", "add", ".", cwd=src)
        presets = self.invoke(CMAKE, "--list-presets", cwd=src)
        configurations = ("dev", "release", "sanitize", "lint", "xcode")
        for name in configurations:
            self.assertIn(f'"{name}"', presets)
        build = src / "build"
        self.assertFalse(build.exists())
        user_presets = src / "CMakeUserPresets.json"
        contents = b'{"version":2,"configurePresets":[]}\n'
        user_presets.write_bytes(contents)

        for name in configurations:
            with self.subTest(preset=name):
                if name == "xcode" and (not shutil.which("xcodebuild") or
                        subprocess.run(["xcodebuild", "-version"], capture_output=True).returncode):
                    self.skipTest("the Xcode preset requires a selected Xcode installation")
                self.invoke("make", "provision", f"PRESET={name}", "CACHE_ONLY=1",
                            f"LLVM_CONFIG={LLVM_BIN / 'llvm-config'}", cwd=src)
                self.invoke("make", "configure", f"PRESET={name}", f"LLVM_DIR={LLVM_DIR}", cwd=src)
                self.assertEqual(user_presets.read_bytes(), contents)
                cache = read_cache(build / name)
                self.assertEqual(cache["FORGE_CONFIGURED_PRESET"], name)
                self.assertEqual((build / name / cache["CMAKE_TOOLCHAIN_FILE"]).resolve(),
                                 build / name / "conan/conan_toolchain.cmake")
                if name == "xcode":
                    self.assertEqual(cache["CMAKE_GENERATOR"], "Xcode")
                    # CMakeDeps loads per-configuration data with a glob. All other configs still exist.
                    generators = build / name / "conan"
                    release_data, = generators.glob("CLI11-release-*-data.cmake")
                    release_data.unlink()
                    failed = self.invoke(CMAKE, "--preset", name, cwd=src, success=False)
                    self.assertIn("Missing CLI11 integration for Release", " ".join(failed.split()))
                    self.assertIn("make provision PRESET=xcode", " ".join(failed.split()))
                else:
                    self.assertEqual(cache["CMAKE_BUILD_TYPE"], "Release" if name == "release" else "Debug")
                self.assertEqual(cache["FORGE_ENABLE_SANITIZERS"] in ("ON", "TRUE", "1"), name == "sanitize")
                if name == "lint":
                    self.assertTrue((build / name / "compile_commands.json").is_file())
                    self.assertFalse((build / name / "forge").exists())
        self.assertFalse((build / "CMakeCache.txt").exists())
        self.assertFalse(list(src.glob("build-*")))

        ctest = (CMAKE.parent / "ctest", "--preset", "dev", "-R", "^build_provisioning$", "--output-on-failure")
        bin_dir = self.tmp / "test tools"
        bin_dir.mkdir()
        sentinel = bin_dir / "conan"
        sentinel.write_text('#!/bin/sh\necho called >> "$0.calls"\nexit 1\n')
        sentinel.chmod(0o755)
        env = dict(self.env, PATH=str(bin_dir) + os.pathsep + self.env["PATH"])
        env.pop("FORGE_TEST_PROVISIONING", None)
        self.assertIn("Skipped", self.invoke(*ctest, cwd=src, env=env))
        self.assertFalse((bin_dir / "conan.calls").exists())

        sentinel.unlink()
        env.update(FORGE_TEST_PROVISIONING="1", PATH=str(bin_dir))
        output = self.invoke(*ctest, cwd=src, env=env, success=False)
        self.assertIn("require Conan on PATH", output)

        legacy = build / "CMakeCache.txt"
        legacy.write_text("old developer build, keep until deliberately retired\n")
        output = self.invoke("make", "configure", f"LLVM_DIR={LLVM_DIR}", cwd=src)
        self.assertIn("legacy cache", output)
        self.assertTrue((build / "dev" / "CMakeCache.txt").is_file())
        self.assertEqual(legacy.read_text(), "old developer build, keep until deliberately retired\n")

        # Clean a compiled product through the normal wrapper and verify the other configurations survive.
        self.invoke(CMAKE, "--build", build / "dev", "--target", "forge_native_harness", cwd=src)
        self.invoke(CMAKE, "--build", build / "release", "--target", "forge_native_harness", cwd=src)
        object_pattern = "**/native_harness.cpp.o"
        self.assertTrue(list((build / "dev").glob(object_pattern)))
        release_objects = list((build / "release").glob(object_pattern))
        self.assertTrue(release_objects)
        copied = self.tmp / "copied dev"
        shutil.copytree(build / "dev", copied, symlinks=True)
        output = self.invoke("make", "clean", f"BUILD_DIR={copied}", cwd=src, success=False)
        self.assertIn("CMAKE_CACHEFILE_DIR", output)
        self.assertTrue(list((build / "dev").glob(object_pattern)))
        self.assertTrue(list(copied.glob(object_pattern)))
        self.invoke("make", "clean", "PRESET=dev", cwd=src)
        self.assertFalse(list((build / "dev").glob(object_pattern)))
        self.assertTrue(all(path.is_file() for path in release_objects))
        self.assertEqual(self.invoke("git", "diff", "--name-only", cwd=src), "")
        self.assertEqual(self.invoke("git", "ls-files", "--others", "--exclude-standard", cwd=src), "")


if __name__ == "__main__":
    if MODE == "provisioning":
        if os.environ.get("FORGE_TEST_PROVISIONING") != "1":
            print("Set FORGE_TEST_PROVISIONING=1 to run the cache-only provisioning checks.")
            sys.exit(77)
        if not shutil.which("conan"):
            sys.exit("The cache-only provisioning checks require Conan on PATH. Activate the pinned build environment.")
    unittest.main(argv=[sys.argv[0], {"build": "BuildConfig", "provisioning": "Provisioning"}[MODE]])
