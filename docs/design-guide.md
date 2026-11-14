# Designing changes in Forge

## Where does the change belong?

The CLI calls the private `forge_core` library. Inspection follows imports across files and returns a report. Analysis and lifting share one parsed image. The CLI can render the analysis or request a verified LLVM module and pass it to publication. Keep dependencies pointing toward the data each stage consumes. Core contract tests call these same interfaces directly.

| Component | Responsibility and contract |
| --- | --- |
| [File input](../src/pe/input.h) | `InputFile` owns the open descriptor. Validation, physical file identity, and the byte snapshot come from that descriptor. |
| [PE parsing](../src/pe/image.h) | `ParsedImage` owns the snapshot, the LLVM COFF object that borrows it, and the observed PE metadata in `forge::Module`. Put file-format facts and checked RVA mapping here. |
| [Dependency inspection](../src/pe/dependencies.h) | `inspect` uses `inspectPE` to obtain detached module metadata. It resolves imports in the importing directory and configured search paths, then returns modules, locations, and dependency edges in a `Report`. DLL search policy belongs here. |
| [Function analysis](../src/analysis/analysis.h) | `AnalyzedImage` owns its `ParsedImage`. It derives function ranges, overlaps, findings, and eligibility from the parsed records. Optional debug enrichment uses the same image. |
| [Lifting](../src/lift/lift.h) | `generateIR` borrows the analysis, validates the requested entry, translates supported AMD64 instructions, and verifies the resulting `llvm::Module`. Reachable CFG discovery consumes the validated range and LLVM MC decoder. The translator uses that graph to prove entry state, emit LLVM blocks and connect flag PHIs. Use this stage for guest semantics. |
| [Publication](../src/output/publication.h) | `publishIR` borrows the completed module and parsed image. It checks the requested destination and owns the file operations that replace it. |
| [CLI](../src/cli/main.cpp) | The entry point registers commands and handles help and usage errors. Each command selects policies, sequences core calls, and returns an exit status. Renderers consume reports, findings, and classified errors. |

## Adding a CLI command

1. Follow the [inspect implementation](../src/cli/commands/inspect.cpp). Put the option struct and registration declaration in a header under `src/cli/commands/`. Store paths, flags, and existing core request types by value. Keep command-specific options, validation, and help text in the matching implementation.
2. In `main.cpp`, declare the options before the `CLI::App`, then call the registration function with the app, options, and exit status. CLI11 retains references to option storage. Bind a `final_callback` that calls the typed executor and records its return value. It runs after help and argument checks. Use `trigger_on_parse()` for options whose every occurrence needs validation.
3. Keep the executor independent of CLI11. Call the owning core interfaces, render reports to stdout and diagnostics to stderr, and return the command's status. Use `cli/parsing.h` for shared input and report options and `cli/report.h` for existing renderers. Add the command's sources to the root CMake `forge` target.
4. Exercise the public syntax, both streams, and exit status in the [CLI suite](../tests/integration/test_inspect.py). For a separately testable executor, see the [typed lift test](../tests/unit/lift_command.cpp), which calls the production executor with a generated PE fixture and a diagnostic stream. Register tests in `tests/CMakeLists.txt`.

From the repository root, run the focused tests with fixture setup, including when the build was previously configured with tests disabled.

```sh
make provision
make test CONFIG=Debug BUILD_TESTING=ON CTEST_ARGS='-R "^(cli|lift_command)$$"'
```

## Extending an existing component

1. Trace a similar change from a caller through the owning interface to a test. Identify the first stage with enough information to answer the new question. An import's spelling comes from parsing, its resolution status comes from inspection, and its displayed text comes from the CLI.
2. Use the owner's existing model, parser, validation, and error mechanism. List the input assumptions, output guarantees, failure classifications, and observable behavior callers rely on. If any must change, identify the affected callers and describe the revised contract.
3. Trace each borrowed value back to its owner. Both the section and bytes returned by `ParsedImage::mapRva` borrow the image. Pass the image down while those views are in use. Reopening its path could read a replacement file. Reuse the parsed image and make the borrow explicit before considering shared ownership. Follow the [C++ style guide](cpp-style.md) and its [ownership and borrowed storage rules](cpp-style.md#ownership-and-borrowed-storage).
4. Test the rule at the lowest level that can observe it. Add a contract or CLI test when data, errors, or side effects cross a boundary. For new lifting behavior, compare defined guest results against an independent reference. Preserve negative cases and enabled comparisons. An enabled case that starts returning “unsupported” is a regression. [Test layers](../AGENTS.md#test-layers) and [differential coverage rules](../tests/differential/README.md#regression-ci-and-local-reproduction)

## When to introduce a component

Extract a component when the change introduces a distinct responsibility or resource lifetime. For a new component or meaningful cross-stage change, a short note in the change description is enough. Small edits can follow the existing contract directly.

```text
Responsibility:
Why an existing component is not the right owner:
Inputs, outputs, and dependencies:
Ownership and lifetime:
Failure behavior and preserved invariants:
How the contract will be tested:
```

Use a **function** for an operation with no state to retain between calls. Use a **value type** for data that travels together, such as the start RVA and entry mode in `LiftRequest`. Use an **owning object** when resources must share a lifetime or destruction order, as the COFF object and its backing bytes do in `ParsedImage`. Introduce an **interface** when a current caller needs to use different implementations through the same contract. Use LLVM types directly where the contract already calls for decoded instructions or IR.

Keep helpers with the responsibility they serve. A long file or a new directory alone does not warrant a component or library. Speculative factories, backend registries, inheritance hierarchies, catch-all utilities, and generic managers make it harder to find the owner of a rule.

## Forge-specific decisions

- **Guest and output target.** PE machine metadata identifies the guest. AMD64 is the implemented guest, and the typed entry wrapper models Windows x64 calling semantics. The output module has its own ARM64 macOS triple and data layout. A future 32-bit x86 guest would need its own validated input, discovery, and calling semantics before a shared CPU abstraction could serve it. [Lifting interface and targets](../README.md#lifting-interface-and-targets)
- **Addresses.** A file offset indexes snapshot bytes. An RVA is relative to the image base. A guest virtual address, such as a TLS callback address, needs a checked conversion before comparison with an RVA. Use `mapRva` for file-backed bytes. A host pointer refers to storage in Forge's process and carries that storage's lifetime. Equal integer widths do not justify conversions between these quantities.
- **Lifted stack.** The lifter owns the guest stack rules. The synthetic entry allocates private register storage and, for memory instructions, a byte array plus one validity byte per guest byte. LLVM owns the IR objects. At runtime each call owns its allocations. Register availability is proved over the guest CFG. Stack stores and validity updates follow the executed LLVM path. Guard continuations are the real predecessors of successor flag PHIs.
- **Translating an access.** Compute the guest address as a wrapping integer. Subtract the fixed stack base, check the unsigned offset against capacity minus access size, and exclude overlap with the entry return slot. Only the successful branch forms an in-bounds byte offset into either allocation. The validity check precedes the data load. Both buffers use alignment-one accesses at guest operand width. The fixed little-endian ARM64 data layout supplies the byte order. [Guest stack contract](../README.md#guest-stack-memory)
- **Facts and policy.** Keep the raw record, the analysis conclusion, and the caller's selection distinguishable. For example, `--signature` selects an entry mode. It supplies no evidence about the original function's type. `ParsePolicy::Inspection` reads import and export tables and rejects a partial exception record. `ParsePolicy::FunctionAnalysis` skips those tables, retains complete exception records, and lets analysis report trailing bytes as a finding. Preserve both contracts when extending their shared parser. [Image ownership and stage contracts](../README.md#image-ownership-and-stage-contracts)
- **Failures.** Assign an `InspectionError` its `FailureCode` where the cause is known. Carry owned context through callers. Malformed input, unsupported capabilities, I/O failures, and internal defects have distinct consequences for consumers. Classify lift failures by stage, category, and code. Parsing diagnostic prose makes a wording change alter program behavior. [Failure definitions](../src/diagnostics.def) and [CLI diagnostic schema](../README.md#lift-diagnostics)

## Worked examples

### Extending the lifter with an immediate multiply (hypothetical)

Forge supports register-pair `IMUL`. Suppose we wanted to lift `imul rdx, rcx, -3` (Intel syntax). LLVM decodes it as `IMUL64rri8`. Today `x86::integerInstruction` excludes immediate multiply. Merely accepting the suffix would send it through a path in `Translator::integer` that reads the old destination. With RCX = 4 and RDX = 7, that would give −21. The guest result is −12. [Form recognition](../src/lift/integer.cpp) and [operand lowering](../src/lift/lift.cpp)

The extension would read RCX and the signed immediate, reuse `IntegerSemantics::arithmetic` for the product and its carry and overflow flags, and write RDX. Instruction bytes would still borrow the analyzed image. A unit test could check form recognition, and a negative lift test should still get `LIFT_UNSUPPORTED_INSTRUCTION` for the neighboring memory form `IMUL64rmi8`. A differential fixture modeled on `multiply_flags` would use distinct register values and expose the product and defined flags. Compare baseline and optimized native runs with Wine for ordinary and overflowing inputs. [Integer unit tests](../tests/unit/integer.cpp) and [assembly fixtures](../tests/differential/fixtures/arithmetic/integer_cases.S)

### Why publication warrants a component (implemented)

`generateIR` returns a verified module that the caller owns. The image can be destroyed after generation. The caller's `LLVMContext` must outlive the module. Opening the destination inside the translator would let an unsupported instruction truncate an existing file and would impose filesystem effects on in-memory callers. [Generation and lifetime tests](../tests/unit/lift.cpp)

Publication has a separate resource lifetime. The CLI preflights the path with `checkedOutputDestination`. At publication, `publishIR` checks it again against the borrowed image's captured file identity and original directory entry. Publication owns a sibling temporary through writing and closing, then renames it into place. A write, close, or replacement failure carries a publication I/O code and triggers cleanup while preserving the previous destination. CLI tests exercise these guarantees by forcing a write failure and a failed replacement, checking both the old contents and the absence of a leftover temporary. [Publication implementation](../src/output/publication.cpp) and [CLI failure tests](../tests/integration/test_functions.py)
