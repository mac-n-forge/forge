"""Build and inspect the Windows fixtures inside the pinned Linux container."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from manifests import SUITE, load_cases


def compile_suite(tree, config):
    subprocess.run(["cmake", "-S", SUITE / "fixtures", "-B", tree, "-G", "Ninja",
                    f"-DCMAKE_TOOLCHAIN_FILE={SUITE}/toolchain/windows-x64.cmake",
                    f"-DCMAKE_BUILD_TYPE={config.capitalize()}"], check=True)
    subprocess.run(["cmake", "--build", tree], check=True)
    return tree / "bin"


def inspect_image(path):
    report = subprocess.check_output(["x86_64-w64-mingw32-objdump", "-p", path], text=True)
    characteristics = re.search(r"^Characteristics\s+(0x[0-9a-fA-F]+)$", report, re.MULTILINE)
    flags = int(characteristics[1], 16) if characteristics else 0
    if (not re.search(r"file format pei-x86-64$", report, re.MULTILINE)
            or not re.search(r"^Magic\s+020b\s+\(PE32\+\)", report, re.MULTILINE)
            or not flags & 0x0002 or flags & 0x2000):
        raise ValueError(f"{path}: expected an AMD64 PE32+ executable image")
    return report


def inspect_pe(path, fixture_id):
    report = inspect_image(path)
    if not re.search(r"^Time/Date\s+Thu Jan\s+1 00:00:00 1970$", report, re.MULTILINE):
        raise ValueError(f"{path}: expected a zero COFF timestamp")

    tables = re.split(r"^\s*DLL Name: (\S+)\s*$", report, flags=re.MULTILINE)
    imports = {dll.lower(): table for dll, table in zip(tables[1::2], tables[2::2])}
    for dll in imports:
        if dll.startswith(("libgcc_s_", "libstdc++-", "libwinpthread-")):
            raise ValueError(f"{path}: unexpected MinGW runtime dependency {dll}")
    if fixture_id == "imports/kernel32":
        for name in ("GetCurrentProcessId", "GetModuleHandleW", "SetLastError", "GetLastError"):
            if not re.search(rf"^\s*[0-9a-f]+\s+\d+\s+{name}$",
                             imports.get("kernel32.dll", ""), re.MULTILINE):
                raise ValueError(f"{path}: missing KERNEL32.dll import {name}")


# Instruction-specific contracts are checked on the linked, callable leaf in
# each configuration. Operand spelling matters for byte aliases and widths.
INTEGER_WITNESSES = {
    "flag_add": ("add cl,dl", "seto al", "lahf"),
    "flag_sub": ("sub cx,dx", "lahf"),
    "flag_adc": ("cmp rcx,rdx", "adc cl,dl", "lahf"),
    "flag_sbb": ("cmp r9,r9", "sete r9b", "cmp rcx,rdx", "sbb r8,r8", "sbb cl,dl", "lahf"),
    "carry_chain": ("add rax,rdx", "inc ax", "not rax", "adc rax,", "dec ah", "sbb rax,"),
    "neg_flags": ("shl rcx,", "neg rcx", "lahf"),
    "mixed_widths": ("mov ah,dl", "xor dh,ch", "add ax,dx"),
    "extensions": ("movsx eax,ch", "movsxd rax,eax", "movzx r8w,dl", "movsx rdx,dx", "xor rax,r8"),
    "multiply_flags": ("imul cx,dx", "setb al", "seto ah"),
    "logic_flags": ("or rcx,rdx", "and rcx,", "test rcx,rcx", "sete al", "setp ah"),
    "predicates": ("movabs rcx,0x8000000000000000", "movabs rcx,0x7fffffffffffffff") + tuple("set" + cc + " " for cc in
                        ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g")),
    "conditional_moves": ("cmovl ax,dx", "cmovb eax,edx", "cmovp rax,rdx"),
    "shift_flags": ("cmp rdx,rcx", "sar dl,cl", "setp al", "setb ah"),
    "shift_widths": ("shr ax,cl", "shl dh,cl", "shr rdx,cl"),
    "shift_one": ("shl dl,1", "seto al", "setb ah", "shr cx,1"),
    "joined_flags": ("cmp rcx,rdx", "jbe ", "sub rdx,rcx", "jmp ", "add rdx,rcx", "lahf"),
    "stack_roundtrip": ("mov QWORD PTR [rsp+0x8],rcx", "mov rax,QWORD PTR [rsp+0x8]"),
    "stack_widths": ("mov QWORD PTR [rsp+0x8],", "movsx r10,BYTE PTR", "movsx r8,WORD PTR",
                     "movsxd rdx,DWORD PTR", "mov eax,DWORD PTR"),
    "stack_overlap": ("mov QWORD PTR [rsp+0x9],rcx", "mov WORD PTR [rsp+0xb],dx", "mov eax,DWORD PTR [rsp+0xa]"),
    "stack_indexed": ("push rbp", "mov DWORD PTR [rsp+0x10],0x11223344", "mov DWORD PTR [rsp+0x14],0x80000001",
                      "mov DWORD PTR [rsp+0x18],edx", "mov DWORD PTR [rsp+0x1c],0xfedcba98",
                      "lea rbp,[rsp+0x20]", "and ecx,0x3", "mov rax,0xffffffffffffffff",
                      "movsxd eax,DWORD PTR [rbp+rcx*4-0x10]", "pop rbp"),
    "stack_branch": ("jg ", "mov QWORD PTR [rsp+0x8],rdx", "jmp ", "mov QWORD PTR [rsp+0x8],rcx", "adc rax,r10"),
    "stack_loop": ("mov rax,QWORD PTR [rsp+0x10]", "mov QWORD PTR [rsp+0x10],rax", "jne ", "mov rax,QWORD PTR [rsp+0x10]"),
    "integer_mix": ("shl ", "xor ", "imul "),
}


def leaf_instructions(output, symbol):
    heading = re.search(rf"^([0-9a-f]+) <{re.escape(symbol)}>:$", output, re.MULTILINE)
    if heading is None:
        raise ValueError(f"missing disassembly for {symbol}")
    # PE objdump can include adjacent symbols even with --disassemble=<symbol>.
    body = re.split(r"^(?:[0-9a-f]+ <[^>]+>:|Disassembly of section )", output[heading.end():],
                    maxsplit=1, flags=re.MULTILINE)[0]
    instructions = {}
    for address, text in re.findall(r"^[ \t]*([0-9a-f]+):[ \t]*([^\n]+)", body, re.MULTILINE):
        address = int(address, 16)
        if instructions and address <= next(reversed(instructions)):
            raise ValueError("duplicate or unordered instruction address")
        instructions[address] = " ".join(text.split())
    if not instructions or next(iter(instructions)) != int(heading[1], 16):
        raise ValueError("missing leaf entry instruction")
    return instructions


def reachable_leaf(instructions):
    # This is a fixture-shape oracle over objdump output, independent of Forge's decoder.
    conditions = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
                  "jp", "jnp", "jl", "jge", "jle", "jg"}
    ordinary = {"mov", "movabs", "movzx", "movsx", "movsxd", "lea", "add", "sub", "xor",
                "and", "or", "test", "cmp", "shl", "shr", "sar", "inc", "dec", "not", "neg", "imul",
                "push", "pop", "cwde", "cdqe", "nop"}
    addresses = list(instructions)
    following = dict(zip(addresses, addresses[1:]))
    graph = {}
    pending = [addresses[0]]
    while pending:
        address = pending.pop()
        if address in graph:
            continue
        text = instructions[address]
        opcode, _, operands = text.partition(" ")
        successors = []
        if opcode == "ret" and not operands:
            graph[address] = successors
            continue
        if opcode == "jmp" or opcode in conditions:
            target = re.fullmatch(r"([0-9a-f]+)(?: <[^>]+>)?", operands)
            if target is None or int(target[1], 16) not in instructions:
                raise ValueError(f"invalid direct target at {address:x}: {text}")
            successors.append(int(target[1], 16))
        elif opcode not in ordinary:
            raise ValueError(f"unsupported instruction or transfer at {address:x}: {text}")
        if opcode != "jmp":
            if address not in following:
                raise ValueError(f"fallthrough outside leaf at {address:x}")
            successors.append(following[address])
        graph[address] = successors
        pending.extend(successors)
    return graph


def natural_loops(graph):
    entry = next(iter(graph))
    predecessors = {address: set() for address in graph}
    for source, targets in graph.items():
        for target in targets:
            predecessors[target].add(source)
    dominators = {address: set(graph) for address in graph}
    dominators[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for address in graph:
            if address == entry:
                continue
            incoming = set.intersection(*(dominators[p] for p in predecessors[address])) | {address}
            if incoming != dominators[address]:
                dominators[address] = incoming
                changed = True

    loops = {}
    for source, targets in graph.items():
        for header in targets:
            if header not in dominators[source]:
                continue
            body = {header, source}
            pending = [source] if source != header else []
            while pending:
                for predecessor in predecessors[pending.pop()]:
                    if predecessor not in body:
                        body.add(predecessor)
                        pending.append(predecessor)
            # Multiple latches with the same header still form one loop.
            loops.setdefault(header, set()).update(body)
    return loops, predecessors


def check_nested_exits(instructions):
    graph = reachable_leaf(instructions)
    returns = {address for address, targets in graph.items() if not targets}
    if len(returns) < 2:
        raise ValueError("expected at least two reachable returns")
    loops, predecessors = natural_loops(graph)
    for outer in loops.values():
        # Find exit destinations that can reach a return without reentering the outer loop.
        returning = returns - outer
        pending = list(returning)
        while pending:
            for predecessor in predecessors[pending.pop()] - outer - returning:
                returning.add(predecessor)
                pending.append(predecessor)
        for inner in loops.values():
            if not inner < outer:
                continue
            enclosing = outer - inner
            inner_targets = {target for source in inner for target in graph[source]}
            inner_exits = inner_targets & returning
            # A peeled inner iteration may branch to the same early return; it cannot
            # witness an outer early exit. Require distinct outer decisions and exits.
            outer_exits = [(source, target) for source in enclosing for target in graph[source]
                           if target in returning and target not in inner_exits]
            if (inner_targets & enclosing and inner_exits and
                    len({source for source, _ in outer_exits}) >= 2 and
                    len({target for _, target in outer_exits}) >= 2):
                return
    raise ValueError("expected nested natural loops with inner continuation and early exits at both levels")


FRAME_LOCALS = {
    "calculate": ("mov QWORD PTR [rbp-0x20]", "mov QWORD PTR [rbp-0x18]", "mov QWORD PTR [rbp-0x10]", "imul "),
    "branch_locals": ("mov BYTE PTR [rbp-", "mov WORD PTR [rbp-", "mov DWORD PTR [rbp-", "cdqe"),
    "count_locals": ("mov QWORD PTR [rbp-", "add DWORD PTR [rbp-", "cmp eax,DWORD PTR [rbp-"),
}


def check_frame(name, instructions, config):
    graph = reachable_leaf(instructions)
    body = [instructions[address] for address in sorted(graph)]
    if config == "debug":
        if body[:2] != ["push rbp", "mov rbp,rsp"] or not body[2].startswith("sub rsp,"):
            raise ValueError("missing unoptimized RBP frame")
        witnesses = (*FRAME_LOCALS[name], "add rsp,", "pop rbp", "ret")
        if body.count("ret") != 1:
            raise ValueError("expected a shared frame epilogue")
    else:
        witnesses = ("sub rsp,", "mov ", "add rsp,", "ret")
    for witness in witnesses:
        if not any(text.startswith(witness) for text in body):
            raise ValueError(f"missing reachable {witness!r}")
    loops, predecessors = natural_loops(graph)
    if name == "count_locals" and not any(
            any(instructions[a].startswith("mov QWORD PTR [") for a in loop) for loop in loops.values()):
        raise ValueError("missing loop with stack-resident accumulator")
    if name == "branch_locals" and config == "debug":
        epilogue = next(a for a in graph if instructions[a].startswith("add rsp,"))
        if len(predecessors[epilogue]) < 3:
            raise ValueError("missing three return paths into the shared epilogue")


def check_leaf(path, config="debug"):
    witnesses = INTEGER_WITNESSES.get(path.stem)
    if witnesses is None and path.stem != "cfg_nested_exits" and path.stem not in FRAME_LOCALS:
        return
    output = subprocess.check_output(["x86_64-w64-mingw32-objdump", "-d", "--no-show-raw-insn",
                                      "-Mintel", "--disassemble=" + path.stem, path], text=True)
    try:
        instructions = leaf_instructions(output, path.stem)
        if path.stem in FRAME_LOCALS:
            check_frame(path.stem, instructions, config)
        if path.stem == "cfg_nested_exits":
            check_nested_exits(instructions)
        if witnesses is not None:
            texts = list(instructions.values())
            body = iter(texts[:texts.index("ret")])
            for witness in witnesses:
                if not any(inst.startswith(witness) for inst in body):
                    raise ValueError(f"missing {witness!r}")
    except ValueError as error:
        raise ValueError(f"{path}: {path.stem} instruction contract: {error}\n{output}") from error


def publish(staged, target):
    # Both renames are on the export filesystem. Serialize writers and recover a
    # previous export if an interrupted invocation stopped between the renames.
    parent = os.open(target.parent, os.O_RDONLY)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        previous = target.with_name("." + target.name + ".previous")
        if previous.exists():
            if target.exists():
                shutil.rmtree(previous)
            else:
                previous.rename(target)
        if target.exists():
            target.rename(previous)
        try:
            staged.rename(target)
        except OSError:
            if previous.exists():
                previous.rename(target)
            raise
        if previous.exists():
            shutil.rmtree(previous)
    finally:
        os.close(parent)


def build(config, cases, output):
    expected = {case["binary"]: case["id"] for case in cases}
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory(dir=output) as staging:
        first = compile_suite(Path(tmp) / "first", config)
        second = compile_suite(Path(tmp) / "second", config)
        for directory in (first, second):
            names = {p.name for p in directory.iterdir()}
            if names != expected.keys():
                raise ValueError(f"{directory}: missing {sorted(expected.keys() - names)}, "
                                 f"unexpected {sorted(names - expected.keys())}")

        staged = Path(staging) / config
        staged.mkdir()
        checksums = []
        for binary, fixture_id in sorted(expected.items()):
            path = first / binary
            data = path.read_bytes()
            if data != (second / binary).read_bytes():
                other = hashlib.sha256((second / binary).read_bytes()).hexdigest()
                raise ValueError(f"{config}/{binary}: clean builds differ: {hashlib.sha256(data).hexdigest()} vs {other}")
            inspect_pe(path, fixture_id)
            check_leaf(path, config)
            checksums.append(f"{hashlib.sha256(data).hexdigest()}  {binary}\n")
            shutil.copy2(path, staged / binary)
        (staged / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
        provenance = dict(schema_version=1, build_config=config, toolchain_image_id=os.environ["FORGE_TOOLCHAIN_ID"],
                          reproducible=True, checksums_sha256=hashlib.sha256((staged / "SHA256SUMS").read_bytes()).hexdigest())
        (staged / "build.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="ascii")
        publish(staged, output / config)
        print(f"{config}: inspected {len(cases)} byte-reproducible PE executables.", flush=True)


if __name__ == "__main__":
    try:
        cases = load_cases()
        for config in sys.argv[1:]:
            build(config, cases, Path("/output"))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
