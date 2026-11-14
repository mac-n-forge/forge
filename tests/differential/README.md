# Windows whole-executable fixtures

These C11 and C++20 console programs provide Windows x64 inputs for whole-executable reference runs. Each manifest records a single invocation and its expected output. The programs build independently of Forge.

| Fixture | What the invocation exercises |
| --- | --- |
| `arithmetic/add_i64` | Two signed 64-bit sums, one positive and one negative, computed by the exported two-argument leaf. Enabled for function-level differential testing. |
| `arithmetic/basic` | Two digits supply bounded signed operands, a nonzero divisor, and the shift count for a 32-bit unsigned rotation. |
| `arithmetic/weighted_pair_i64` | A signed 64-bit branch selects addition or subtraction after tripling the left operand’s low 32 bits. Enabled for function-level differential testing. |
| Integer flag fixtures | The `flag_*` leaves expose byte and word arithmetic through SETO and LAHF. `carry_chain`, `neg_flags`, `multiply_flags` and `joined_flags` exercise preservation, signed minimum, overflow and forward joins. |
| Width and condition fixtures | `integer_mix` is compiled unsigned C arithmetic. `mixed_widths`, `extensions`, `logic_flags`, `predicates` and `conditional_moves` exercise register aliases, flag results and all sixteen conditions. The extensions leaf combines a signed word and an independently zero-extended byte. In the predicates leaf, left operands 23 and 24 select the minimum and maximum signed 64-bit values. Comparing them with 1 and −1 exercises signed predicates with OF set in both directions. |
| Shift fixtures | `shift_one`, `shift_flags` and `shift_widths` exercise single-bit overflow, masked-zero preservation, narrow operands and large CL counts. |
| Control-flow leaves | `diamond` merges different byte writes. `counted_sum` and `shift_loop` expose the iteration count or accumulator. `nested_exits` uses bits 0–2 and 3–5 of its left operand as outer and inner bounds. Its accumulator records both loops. The low two result bits identify normal completion (0), an inner early return (1), or an outer early return (2). A negative right operand returns −7 before either loop. `flag_join` consumes carry from different predecessors. `carry_loop` feeds ADC with the previous iteration’s carry. `jcc` encodes all sixteen branch decisions as distinct output bits after the same byte comparison. All seven run in both PE configurations through the decimal-pairs harness. |
| CFG edge and register regressions | `entry_backedge` adds one to its seed on each of one to eight visits to the first instruction. `identical_successors` returns ZF and CF after a CL shift and a branch to its fallthrough. `partial_join` returns a word formed by SETcc and LAHF on one path or preserved across TEST on the other. All three use the decimal-pairs harness in Debug and Release. |
| `control_flow/branches` | One pass covers the early return, even and odd digits, three switch arms, and the default. Each input byte has its own output line. |
| Stack fixtures | Six `memory/` leaves cover independent quadwords, signed and unsigned narrow loads, overlapping unaligned accesses, scaled RBP/RSP addresses, conditional stores with live flags, and loop-carried memory. Each selected leaf uses the caller-provided shadow space. The indexed leaf selects one of four adjacent doublewords initialized at fixed offsets and returns it through EAX. The indexed export saves and restores its caller’s RBP. The Windows driver calls that export directly. |
| `frames/calculate` | A C++ export homes the two arguments, writes a three-element volatile array, and returns its product plus sum. The Windows driver and native `calculate_pairs` harness validate every operand against the inclusive ±1,000,000,000 bounds before printing. Invalid input exits 2 with empty output. Release stores and reloads all three RSP-relative array slots before returning the result. |
| `frames/branch_locals` | A C export uses byte, signed word, and doubleword locals. Three Debug paths converge on one RBP epilogue. Release uses extending loads from its byte, word and doubleword locals and has two reachable returns. |
| `frames/count_locals` | A C export adds the loop index to a stack accumulator over zero to seven iterations. The linked loop loads and stores the same quadword at an RBP-relative slot in Debug and an RSP-relative slot in Release. |
| `functions/calls` | Recursive calls return into a six-argument call that uses four Windows x64 argument registers and two stack slots. |
| `memory/arrays` | Stack struct fields supply products written through a pointer into a heap allocation. The program sums the products and frees the allocation. |
| `globals/state` | An initialized global, a zero-initialized global, and a static local change across iterations. Input bytes select weights from read-only data. |
| `imports/kernel32` | Process and module validity and a last-error round trip yield three Boolean results. |
| `cpp/lifetime` | The input selects both derived types. The program prints the result of virtual dispatch and the order of construction and destruction after each scope ends. |
| `runner/stderr_only` | Writes exactly `runner-error\n` to stderr and exits zero. |
| `runner/exit_nonzero` | Exits 7 with both streams empty. |
| `runner/exit_and_stderr` | Writes the same 13 stderr bytes and calls `ExitProcess(0x1234)`. |

## Build and inspect

From the repository root, use Docker with Linux amd64 container support. Apple Silicon uses Docker Desktop's amd64 emulation. Explicit image preparation needs access to the Debian image registry and package snapshot. Fixture compilation and inspection run with networking disabled. Rerun image preparation when a pinned image input changes. The native Forge dependency setup is independent.

```sh
make provision-fixtures
./tools/build-windows-fixtures.sh --all
./tools/build-windows-fixtures.sh --config debug
./tools/build-windows-fixtures.sh --config release
```

The wrapper configures the standalone fixture CMake project with Ninja and the Windows x64 toolchain. Each selected configuration builds twice in clean directories. The wrapper checks the exact set of executables, compares the bytes, and uses MinGW objdump to check PE32+, AMD64, executable characteristics, the zero timestamp, and the kernel32 case's four named imports. It then replaces that configuration's export directory. Each directory contains the executables and a filename-sorted `SHA256SUMS` file.

```sh
(cd build/fixtures/windows-x64/debug && shasum -a 256 -c SHA256SUMS)
build/dev/forge inspect build/fixtures/windows-x64/release/imports_kernel32.exe --format json
```

The Dockerfile pins the amd64 Debian Bookworm image by digest and installs packages from the signed 2025-02-24 snapshot. The cross compiler uses the Win32 threading model. The exact package revisions are GCC/G++ `12.2.0-14+25.2`, MinGW-w64 headers and libraries `10.0.0-3`, binutils `2.40-2+10.4`, CMake `3.25.1-1`, and Ninja `1.11.1-2~deb12u1`. The build fixes the locale, timezone, source and debug directory mappings, and PE timestamp. Debug uses `-O0 -g` and Release uses `-O2`. Compiler support libraries are linked statically. [Toolchain definition](toolchain/Dockerfile) · [Compiler and linker flags](fixtures/CMakeLists.txt)

## Manifest v1

Each UTF-8 JSON file under `manifests/` declares one executable. For example:

```json
{
  "schema_version": 1,
  "id": "memory/arrays",
  "description": "Sum weighted bytes copied from stack records to a heap array.",
  "source": "fixtures/memory/arrays.c",
  "binary": "memory_arrays.exe",
  "args": ["Forge"],
  "expected": {"exit_code": 0, "stdout": "sum=1551\n", "stderr": ""}
}
```

Use a unique lowercase `category/name` ID and a portable, case-insensitively unique `.exe` basename. Source paths are relative to this guide's directory and must resolve inside `fixtures/`. Binary names resolve inside the selected configuration's export directory. The ordered `args` list excludes the executable name. Use `[]` for an invocation without arguments.

Both expected streams are required, including empty strings. Their UTF-8 encoding specifies the exact bytes and ordering within each stream. Fixtures use ASCII and set stdout and stderr to binary mode so LF remains LF in redirected Windows output. The exit code is an unsigned 32-bit process status. The contract preserves whitespace and trailing newlines and uses literal strings throughout.

## Add a fixture

1. Add a small source under `fixtures/<category>/`. Include `streams.h` and call `open_binary_streams()` before output. Make the result depend on arguments or an observable API operation. Bound arithmetic, shifts, memory accesses, and recursion for every accepted input. Convert environment-dependent values into deterministic checks inside the program.
2. Add the manifest under `manifests/` or a category subdirectory. Derive the expected exit status and streams from the declared input. CMake discovers targets from the validated manifests.
3. Run `python3 -B tests/differential/manifests.py`, `make format-check`, and the Docker build from the repository root. Inspect optimized code when a particular call, memory access, or branch is essential to the case. Commit source and metadata. Git ignores the generated binaries and checksums under `build/`.

## Capture Wine references

Use Python 3.9 or newer and a local Docker engine with Linux amd64 support. Run these commands from the repository root after building the corresponding configurations.

```sh
./tools/run-windows-references.sh --all
./tools/run-windows-references.sh --config release
./tools/run-windows-references.sh --fixture runner/exit_and_stderr --config debug
```

The runner locks the publication directory, withdraws the selected previous results, and loads the same validated catalog as the builder. For each invocation it checks a private binary snapshot against the export's `SHA256SUMS` and mounts that file read-only in a fresh container. MinGW objdump checks the snapshot's PE format. The container runs as an unprivileged user with a fixed hostname, UTC, `C.UTF-8`, a private initialized 64-bit Wine prefix, and networking disabled. The Windows working directory is `C:\work`, stdin reads from `NUL`, and the fixture starts with the ordered manifest arguments. Container removal discards the working directory, registry, and remaining processes.

The reference image extends the pinned toolchain with Debian Wine and libwine `8.0~repack-4`. A Windows parent starts the PE with separate inheritable pipe handles and drains both concurrently. On this Wine version the initial ntdll breakpoint follows DLL initialization. The parent detaches there, waits for termination and both pipe readers, and reads the full unsigned status with `GetExitCodeProcess`. A separate control record carries that value to the host. Wine runs with `WINEDEBUG=-all`; its launcher diagnostics have a separate channel with a bounded 64 KiB diagnostic tail.

The startup deadline is 120 seconds and the execution deadline is 10 seconds. Each fixture stream can contain up to 1 MiB. Exceeding a limit fails the invocation and the supervisor removes the container, including descendants holding a pipe open. The deadlines cover fixture execution after image preparation. The runner is intended for repository-owned console fixtures. GUI, interactive input, external services, and arbitrary untrusted programs fall outside this workflow.

### Result layout and interpretation

```text
build/differential/reference/windows-x64/wine/debug/runner/exit_and_stderr/
  result.json
  stdout.bin
  stderr.bin
```

Manifest expectations describe intended behavior. A passing reference records the observed Wine behavior for one exact binary and manifest. The publisher compares each byte with the UTF-8 encoding of the expected stream, including whitespace, CR, LF, and trailing newlines. It also checks the full exit code. Expected stderr may contain data and an expected nonzero status may pass.

The version 1 JSON names both raw files and records their lengths and SHA-256 hashes, fixture ID, configuration, pass status, exit code, binary SHA-256, relative manifest path and SHA-256, runner version, Wine version, immutable image ID, container platform, and Docker host architecture. The runner version fingerprints the host implementation and the image ID identifies the guest implementation. All three files appear together by directory rename after validation. Git ignores the output tree. A rerun of one fixture withdraws only that fixture's selected configuration.

For the combined regression, `stdout.bin` is empty, `stderr.bin` contains the 13 bytes ending in hex `0a`, and `result.json` records `4660`.

### Troubleshooting and CI

- **Missing executable or checksum mismatch.** Rebuild with `./tools/build-windows-fixtures.sh --config debug` or `--config release`. An unsupported PE fails inspection before Wine launches it.
- **Wine startup or dependency failure.** Check the fixture/configuration label, loader status, and diagnostic tail. Use the pinned toolchain's `x86_64-w64-mingw32-objdump -p` to inspect imported DLL names. A missing imported DLL can yield `0xc0000135`; a fixture that deliberately exits with that value after startup has an observable exit code.
- **Output or exit mismatch.** Rerun the individual fixture. Diagnostics identify every differing field, the first differing byte offset, both lengths, and escaped byte context. Check binary stream mode, arguments, and flushes before explicit process termination.
- **Timeout, overflow, or artifact write failure.** Check fixture termination, descendants inheriting handles, output volume, and permissions or free space under `build/differential/reference/`. Correct the cause and rerun to publish a fresh result.

The existing `windows-fixtures` job on native Linux amd64 builds both configurations, runs this CLI, reopens the entire artifact matrix, exercises real Wine failure cases, and uploads the references and matching PE exports together in `windows-x64-inputs` on success. Run `python3 -B tests/differential/reference/test_runner.py` for Wine-free tests and `python3 -B tests/differential/reference/test_wine.py` after a complete capture for integration tests. The native Forge CTest suite includes the Wine-free runner tests.

Linux amd64 CI is the canonical Wine environment. Apple Silicon results record the ARM64 Docker host separately. The image disables Rosetta AVX advertisement because the emulator can otherwise abort while restoring Wine's breakpoint signal context. On an Apple Silicon Docker Desktop host with Rosetta enabled, Wine returned AH = 0x47 for byte 0xff + 1 followed by SETO and LAHF. The defined AF bit makes the architectural result 0x57. These fixtures reject that reference during capture. Use the canonical amd64 producer or its validated artifacts if this mismatch occurs. Wine implements Windows APIs with its own loader and runtime. Equivalence with native Windows requires separate evidence and backend provenance.

## Related Forge tests

The initial suite produced seven Debug and seven Release PEs with byte-identical clean rebuilds for each configuration. Native Forge inspection identified all fourteen as AMD64 PE32+ executables importing `KERNEL32.dll` and `msvcrt.dll`. On macOS, Forge reports `DLL_NOT_FOUND` for `msvcrt.dll` when inspecting without Windows DLL search paths. Release disassembly confirmed recursive calls, stack-passed arguments, stack-to-heap copies, and indirect virtual dispatch.

The SDK-free parser and lifter samples live in `tests/fixtures/`. The existing `differential` CTest uses Unicorn to compare an individual x86-64 function with the ARM64 harness.

## Compare a lifted function with Wine

On Apple Silicon, build Forge with LLVM 23 and export the LLVM selection from the [build instructions](../../README.md#build-and-run) for the harness configurations. Prepare matching Windows binaries and references with the commands above, or extract the successful Linux job’s `windows-x64-inputs` artifact into `build/`. The native comparison runs offline using those files.

```sh
make provision
make CONFIG=Debug
./tools/run-differential.sh --fixture arithmetic/add_i64 --config debug
./tools/run-differential.sh --fixture arithmetic/weighted_pair_i64 --config debug
./tools/run-differential.sh --all --config release --jobs 2
# Downloaded roots each contain debug/ and release/.
./tools/run-differential.sh --all --config debug \
  --binary-root /path/to/windows-x64-fixtures \
  --reference-root /path/to/windows-x64-wine-references
```

Use `--forge PATH` to select the executable for inspection, analysis, and lifting. Relative paths resolve from the directory where you invoke the runner. The default is the repository’s `build/dev/forge`. The report records the SHA-256 of the selected executable. To use the Xcode preset, run both commands from the repository root.

```sh
make provision PRESET=xcode
make build PRESET=xcode CONFIG=Debug
CMAKE_GENERATOR=Xcode ./tools/run-differential.sh --all --config debug --forge build/xcode/Debug/forge
```

The manifest supplies the binary, arguments and expected Windows behavior. [cases.json](cases.json) associates an enabled fixture ID with its function export, explicit ABI signature, scope and CMake harness. Each invocation snapshots the selected PE against its configuration’s `SHA256SUMS`. The consumer checks the v1 reference’s validated status, IDs, configuration, binary and manifest hashes, publisher fingerprint, and Wine provenance. It requires the designated regular stream files, verifies sizes and hashes, and independently checks the recorded bytes and full exit code against the manifest. It compares native behavior with the verified observation held in memory. A local override must point to a trusted producer’s artifacts. Hashes detect changes relative to the publication. CI obtains producer identity from its same-run artifact transfer.

For each enabled case, the runner resolves the named PE export, checks its discovered range, then lifts it once using `i64(i64,i64)`. Both the Windows driver and the ARM64 harness call their function for every manifest operand pair. The register-only C fixtures use `noipa` and function-local optimization settings. The three frame exports use the ordinary Debug and Release compiler flags. The builder checks the linked Debug RBP prologues and the reachable local operations, loop and shared branch epilogue. Both native IR optimization paths execute each PE configuration. The instruction-specific cases link Windows x64 assembly with a C driver. Each such binary selects its leaf by name. The MinGW build disassembles the linked symbols and checks the expected instruction sequences before publishing the PE. For `nested_exits`, it follows reachable direct branches through the whole export, groups backedges by their dominating header, and requires an inner natural loop strictly inside an outer one. It checks for an inner continuation, separate exit decisions, and multiple reachable returns. Backward jumps to a shared return do not establish nesting.

The nested-loop manifest uses `9,999,999,999` (written without separators in the arguments) as the no-exit sentinel. All operands fit the existing decimal-pairs parser. The cases include both signed 32-bit endpoints, inner and outer counts of zero, one and three, and a full seven-by-seven traversal.

Each PE configuration requires two independent native executions against its single validated Wine reference. The `baseline` build verifies the canonical IR and passes it to `llc`. The `o2` build verifies that IR, runs LLVM’s `default<O2>` pipeline, verifies the result and feeds it to the same `llc` command. The harness, code-generation options, linker settings and input pairs match. Both variants run after a successful lift, even when one fails. A fixture passes when both executions complete and both match the reference exit code and stream bytes.

The `weighted_pair_i64` export compares its original signed 64-bit inputs. It triples the left operand’s unsigned low 32 bits, then subtracts the right operand’s unsigned low 32 bits when the left input is smaller and adds them otherwise. Every intermediate fits in `int64_t`. The function disables MinGW if-conversion to exercise a forward conditional jump. Its 14 pairs include equality, both branch directions, negative results, truncation at 2³², and the decimal parser limits.

The pairs `(-1, 1)` and `(4294967295, 1)` differ only in the left operand’s upper bits and take opposite branches. Swapping the operands checks the right side independently. Wine prints `4294967298` for `(1, -1)` and `-4294967292` for `(1, 4294967295)`. The manifest expectation comes from the Wine capture. The ARM64 comparison uses the validated Windows process observations.

**Coverage is function-level.** The Windows reference exercises the entire console program. The native run exercises the lifted function and the harness’s formatting. Ten other fixtures remain in the Wine suite. Current lifting requires an eligible function using supported integer and stack operations with an explicit supported ABI. The existing arithmetic, branching and call fixtures need additional instruction, stack or call support to reproduce their observations. The remaining fixtures exercise memory, globals, imports, C++ lifetime, or process behavior. In particular, Windows status 4660 in `runner/exit_and_stderr` requires a future full-width guest termination channel. The current harness provides a normal zero completion. Its nonzero statuses and signals indicate execution failure.

### Reports and diagnosis

Each selected fixture has a `result.json` below `build/differential/windows-x64/<config>/<fixture-id>/`. For enabled cases, the same directory holds the PE snapshot, inspection and analysis JSON, stage logs, `generated/lifted.ll`, and separate `baseline/` and `o2/` directories containing the linked executable, compiler log, and captured `stdout.bin` and `stderr.bin`. The result records the Forge executable digest, original PE digest, reference identity, function RVA and scope, native architecture, each stage outcome, and any mismatch details. Its `variants` entries identify baseline and O2 failures independently. Each variant records its run ID, fixture ID, PE configuration and SHA-256 digests of the PE, canonical IR and actual input to `llc`. The coverage gate reopens the PE, both IR files and both sets of streams to check this evidence. Regenerate older native reports with the differential runner. The configuration’s `suite.json` records the latest selection, case report paths, and counts. A fixture counts once as executed when either native process completes, including a behavioral mismatch. Passing requires two completed comparisons matching Wine. A compilation or execution failure in the other variant still fails the fixture. Reruns replace selected artifacts under a configuration lock.

The runner requests `--diagnostics-format json` for each lift and preserves the complete stderr in `lifting.log` and stdout in `lifting.stdout`. On exit 1 it validates the version, stage, category, code and context against the request. The runner checks the reported extent, instruction location, offset, and bytes against the selected discovery row, the inspected executable section, and the PE snapshot. It checks capability claims against the guest, entry restrictions, and the 64 KiB function limit. It terminates remaining members of the subprocess group before examining the output. The CLI documents the [lift diagnostic format](../../README.md#lift-diagnostics).

A validated `unsupported` diagnostic on exit 1 fails an enabled case with `unsupported_lifting_capability`. Missing or malformed records, unexpected stdout and inconsistent process status produce `lifting_failure`. A missing or ineligible discovery row produces `analysis_failure`. A Windows exit status the harness cannot represent produces `lifting_failure` before launching Forge. Success requires exit 0, empty diagnostic streams and a newly published IR file.

| Report | Where to look |
| --- | --- |
| Reference validation failure | Check the manifest, export checksum, producer identity, streams and downloaded configuration. Rebuild or recapture explicitly when the inputs change. |
| Analysis failure | Inspect `inspect.json`, `analysis.json` and their logs for missing, forwarded or ambiguous exports and conflicting ranges. |
| Unsupported instruction in an enabled case | Check the selected range and the opcode/RVA in `lifting.log`. This stage error fails the suite. |
| Lifting failure | Inspect `lifting.log` for verifier or IR publication errors. |
| Native compilation failure | The diagnostic identifies configuration, object compilation, or linking. Open the variant’s `compilation.log` for the failing command. On a full run it also points to the responsible worker’s `configuration.log`. |
| Native execution failure | Inspect the captured bytes and diagnostic for launch errors, signals, harness exit, the 10-second deadline or the 1 MiB per-stream limit. The supervisor runs with closed stdin in a fresh directory and terminates the process group on failure. |
| Behavioral failure | The report lists every differing field. For stream differences it includes both lengths, the first differing byte offset and escaped byte context. For decimal-pair stdout it also identifies the operands for the first differing expected line. Extra bytes after the last line have no associated pair. For exit-code differences it includes both semantic values. |
| Uncovered | The manifest has no enabled function-level case. Selecting only uncovered fixtures fails with zero executions. |

A full run accepts `--jobs N` (default 1). Each worker configures its own fresh CMake tree for one PE configuration and compiles each selected harness object once. The two variant targets for each enabled fixture write their verified IR, objects and linked executables to fixture-specific directories. Results appear in catalog order regardless of worker completion order. Use `--fixture` to reproduce a single failure with an isolated build and the same CMake rules.

To add coverage, capture passing Debug and Release Wine references, identify the callable export and its declared signature, then add the contract to `cases.json`. Use the decimal-pairs harness when the invocation fits. Harnesses in `tests/support/` parse inputs and format observations. The linked Forge output performs the computation.

Use `python3 -B tests/differential/test_differential.py` for the Wine-free comparator, validator, supervisor and runner tests. With the full local artifacts available, `python3 -B tests/differential/test_native_differential.py` lifts and runs the weighted case twice in fresh directories and compares the generated IR and process observations. It checks instrumented harness linking with Unix Makefiles and Xcode. In private IR copies, it changes a return value in only one variant, truncates the right operand of the signed comparison, injects invalid IR, replaces signed word extension with zero extension, changes the indexed stack load’s stride from four bytes to one, and renames the callable wrapper to exercise mismatch, compilation, and link failures. It also sends a private baseline IR copy into a nonterminating loop, checks the native deadline and the independently passing O2 execution, and tests a failed harness invocation and a mismatched PE. The negative reports live under `build/differential/negative-tests/`.

## Regression CI and local reproduction

From an Apple Silicon checkout, follow the [tool setup](../../README.md#build-and-run) to select LLVM and activate the pinned Python environment. The full gate uses Xcode, CMake 3.21+ for JUnit, and Docker with Linux amd64 images. Prepare the native configurations and fixture images before starting it.

```sh
make provision
make provision PRESET=sanitize
make provision PRESET=lint
make provision-fixtures
./tools/test-forge.sh --all
```

The stage commands also work individually. Run `--native` for formatting, clang-tidy, Debug CTest, and ASan/UBSan CTest. This stage sets `FORGE_TEST_PROVISIONING=1` and checks both JUnit reports for execution of the native, Unicorn, guest stack, and cache-only provisioning tests. Run `--references` to build both PE configurations twice, inspect them, capture Wine behavior, and exercise the real capture boundaries. Run `--differential` after those stages, or after extracting the matching CI inputs. It consumes the existing exports, checks every reference, runs both configurations and the negative integrations, and writes local coverage. Preserved Wine observations from before the Conan migration can be supplied with `--reference-root` on the individual differential runner. Each observation must match the selected PE and manifest and pass the same stream and provenance checks. Use the individual fixture commands above to investigate a failure. A single-fixture run replaces that configuration’s suite index. Rerun the full differential stage to produce complete evidence.

PRs into `main` and pushes to `main` start three Apple Silicon jobs and one Linux job together. A newer commit cancels the superseded run for the same PR.

| Job | Produces or verifies |
| --- | --- |
| `macos-dev` and `macos-sanitize` | Each runs its full CTest suite with outbound networking disabled, checks JUnit for execution of the native, Unicorn, guest stack and provisioning tests, and publishes its tested Forge executable and SHA-256. |
| `macos-presets` | Runs formatting and clang-tidy, builds Release and both Xcode configurations, runs their CLI smoke tests with fixture setup, and checks the build layout. |
| `windows-fixtures` | On Linux amd64, builds each Windows configuration twice, checks PE reproducibility, captures Wine behavior and tests the capture boundaries. Publishes the exports and references together. |
| `differential` | Downloads both tested executables and the Windows inputs after those producers succeed. Uses sanitized Forge with Xcode for Debug and ordinary dev Forge with Unix Makefiles for Release. Runs the negative integrations. |
| `regression-gate` | Requires every preceding job and stage. Independently checks suite membership, producer digests, IR and saved native observations against the validated Windows inputs. |

The gate binds the differential evidence to its producing attempt, workflow run and checked-out revision. This allows a gate-only rerun to verify its successful producer's original artifacts. Each macOS runner verifies the pinned LLVM archive before extraction.

The gate publishes a job summary and schema-v1 `build/differential/coverage/coverage.json`. Each row identifies its configuration, target, scope, reference and case report. Read the category totals and passing scopes separately for Debug and Release. A missing prerequisite, case report, or successful execution fails the gate. The JSON and diagnostic artifacts are available from the workflow run for seven days. Extract `macos-arm64-differential` under `build/differential/` to follow report paths. The native harness in the downloaded diagnostics can be made executable with `chmod +x`. Failed Windows captures are kept separately in `windows-diagnostics` and are ineligible as CI reference inputs.

| Coverage status | Evidence |
| --- | --- |
| `passed` | A completed native execution matched the validated Windows observation in all fields. |
| `failed` | A completed execution differed in stdout, stderr, or full exit status. |
| `error` | Required evidence was missing, inconsistent, or invalid, or an enabled stage failed. Inspect the stage diagnostics first. |
| `reference_only` | The PE has a validated Windows reference and no differential case enabled for this configuration. |
| `blocked` | A validated fixture has a predeclared capability limitation for this configuration. The row records the reason. |

For a new enabled case, add its function contract to `cases.json` and add a matching `id`, `config`, `target` obligation to `coverage-baseline.json` for each supported configuration. Cases default to Debug and Release. Use the optional nonempty `configs` list for a narrower contract. A known blocker may be declared as a fixture ID with `blocked_reason` and optional `configs`. A fixture can have an enabled entry for Debug and a blocked entry for Release when their configurations are disjoint. CI never converts an enabled failure into a blocker. An intentional coverage reduction requires matching definition and baseline edits plus an explanation in the PR, preferably with a replacement test or tracking issue. The baseline is maintained by hand.

### CI timing and worker selection

Use workflow creation through completion of `regression-gate` to measure PR latency. For a rerun, start the clock when GitHub creates the new attempt. Sum the durations of all macOS jobs to compare runner use. The Actions summaries separate configure, build and CTest on macOS. The differential summary gives wall time plus cumulative worker time for reference validation, analysis, lifting, configuration, object compilation, linking, execution and comparison. Cumulative times overlap when workers run concurrently.

| Hosted run, 29 Windows references and 19 enabled fixtures per configuration | Elapsed through gate | macOS runner time | Differential job |
| --- | ---: | ---: | ---: |
| [Before the change](https://github.com/RecastIR/forge/actions/runs/43540234265) | 45m39s | 45m21s | 18m26s |
| [Two workers, cold Conan and compiler caches](https://github.com/RecastIR/forge/actions/runs/43545829055/attempts/1) | 18m12s | 25m40s | 5m57s |
| [Same commit, warm caches](https://github.com/RecastIR/forge/actions/runs/43545829055/attempts/2) | 18m27s | 28m33s | 9m15s |

Before the change, per-variant CMake configuration took 11m14s across 76 positive variants. The cold two-worker run included nearly five minutes waiting for the differential runner. On the warm rerun the two native builds had 27/27 compiler-cache hits, while the nine negative integrations took 3m54s versus 2m00s on the cold run. Queue time and Xcode performance both affect total latency.

CI uses four fixture workers on one Apple Silicon runner. On identical inputs, both full positive suites took 257s with one worker, 150s with two, and 118s with four. Including setup, all negative integrations, transfers and gate reconciliation, one four-worker runner took 4m39s from job start. Splitting the fixtures over two four-worker runners took 6m44s and consumed 9m55s of macOS runner time versus 4m25s. All comparisons produced matching fixture evidence. The performance PR records end-to-end runs on the expanded control-flow catalog. [Hosted worker and sharding experiment](https://github.com/RecastIR/forge/actions/runs/43548398069) · [Production measurements](https://github.com/RecastIR/forge/pull/11)

Native builds use three compilation jobs, a runner-local ThinLTO cache and a bounded ccache for the two Makefile test configurations. In a separate Debug trial, a fresh runner restored an 11.8 MB compiler cache and built in 65.8s versus 90.2s cold. Editing one translation unit caused one miss and 26 hits. The rebuilt object contained the changed symbol. A profile edit changed the Conan key and regenerated the same locked package identity. [Compiler-cache trial](https://github.com/RecastIR/forge/actions/runs/43546000884) · [Cold toolchain validation](https://github.com/RecastIR/forge/actions/runs/43546114845) · [Conan invalidation trial](https://github.com/RecastIR/forge/actions/runs/43547833484)

Repository administrators should require the GitHub Actions check `regression-gate` on `main`, require pull requests and code-owner review, and retain other required checks. The baseline and ownership file designate `@ziflex`. Add a second owner with write access before enforcing owner reviews on baseline changes authored by `@ziflex`. Verify the status check after the first hosted run.
