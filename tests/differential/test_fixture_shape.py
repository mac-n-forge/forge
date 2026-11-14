"""Instruction and control-flow witnesses for the linked MinGW fixtures."""
from pathlib import Path
import unittest
from unittest.mock import patch

from build import check_frame, check_leaf, check_nested_exits, leaf_instructions


# Both loops are laid out after a shared return. Absolute addresses are immaterial.
NESTED = """
10: jmp 30 <cfg_nested_exits+0x20>
11: ret
30: je 11
31: je 60
40: je 80
41: jne 40
60: je 90
61: jmp 30
80: ret
90: ret
"""


class FixtureShapeTests(unittest.TestCase):
    def check(self, listing):
        entry = listing.lstrip().split(":", 1)[0]
        output = f"{entry} <cfg_nested_exits>:\n{listing}"
        check_nested_exits(leaf_instructions(output, "cfg_nested_exits"))

    def reject(self, listing):
        with self.assertRaisesRegex(ValueError, "nested natural loops"):
            self.check(listing)

    def test_frame_loop_must_store_inside_a_reachable_loop(self):
        instructions = dict(enumerate([
            "push rbp", "mov rbp,rsp", "sub rsp,0x10", "mov QWORD PTR [rbp-0x10],rdx",
            "mov rax,QWORD PTR [rbp-0x10]", "mov QWORD PTR [rbp-0x10],rax", "add DWORD PTR [rbp-0x4],0x1",
            "cmp eax,DWORD PTR [rbp-0x8]", "jb 4", "add rsp,0x10", "pop rbp", "ret"]))
        check_frame("count_locals", instructions, "debug")
        instructions[8] = "jb 6"
        with self.assertRaisesRegex(ValueError, "stack-resident accumulator"):
            check_frame("count_locals", instructions, "debug")
        instructions[0] = "nop"
        with self.assertRaisesRegex(ValueError, "RBP frame"):
            check_frame("count_locals", instructions, "debug")

    def test_frame_branch_has_three_reachable_epilogue_paths(self):
        instructions = dict(enumerate([
            "push rbp", "mov rbp,rsp", "sub rsp,0x10", "mov BYTE PTR [rbp-1],al",
            "mov WORD PTR [rbp-4],dx", "mov DWORD PTR [rbp-8],eax", "cdqe",
            "js a", "je b", "jmp c", "jmp c", "jmp c", "add rsp,0x10", "pop rbp", "ret"]))
        check_frame("branch_locals", instructions, "debug")
        instructions[8] = "je a"
        with self.assertRaisesRegex(ValueError, "three return paths"):
            check_frame("branch_locals", instructions, "debug")

    def test_nested_after_first_return(self):
        self.check(NESTED)

    def test_release_calculate_requires_all_array_slots_and_multiply(self):
        def check(body):
            check_frame("calculate", dict(enumerate(["sub rsp,0x28", *body, "add rsp,0x28", "ret"])), "release")

        body = ["mov QWORD PTR [rsp+0x8],rax", "mov QWORD PTR [rsp],r9", "mov QWORD PTR [rsp+0x10],rdx",
                "mov r10,QWORD PTR [rsp+0x10]", "mov rdx,QWORD PTR [rsp]", "mov r8,QWORD PTR [rsp+0x8]",
                "imul rdx,r8"]
        check(body)
        for incomplete in ([*body[:3], *body[4:]], body[1:], body[:-1],
                           ["mov rax,rcx", "imul rax,rdx", "add rax,rcx", "add rax,rdx"]):
            with self.subTest(body=incomplete), self.assertRaisesRegex(ValueError, "array slots"):
                check(incomplete)

    def test_release_branch_requires_reachable_returns_and_matching_loads(self):
        body = ["sub rsp,0x18", "mov BYTE PTR [rsp+0x9],al", "mov WORD PTR [rsp+0xa],dx",
                "mov DWORD PTR [rsp+0xc],r8d", "movsx r9d,WORD PTR [rsp+0xa]", "movzx eax,BYTE PTR [rsp+0x9]",
                "movsxd r11,DWORD PTR [rsp+0xc]", "js a", "add rsp,0x18", "ret", "add rsp,0x18", "ret"]
        check_frame("branch_locals", dict(enumerate(body)), "release")
        for index, replacement, reason in ((7, "jmp a", "two reachable returns"), (4, "mov eax,edx", "movsx"),
                                           (5, "movzx eax,BYTE PTR [rsp+0x8]", "movzx"),
                                           (3, "mov r8d,edx", "movsxd")):
            instructions = dict(enumerate(body))
            instructions[index] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, reason):
                check_frame("branch_locals", instructions, "release")

    def test_release_loop_requires_load_and_store_of_one_rsp_slot_inside_loop(self):
        body = ["sub rsp,0x18", "mov QWORD PTR [rsp+0x8],rdx", "mov r8,QWORD PTR [rsp+0x8]",
                "add r8,rax", "mov QWORD PTR [rsp+0x8],r8", "jne 2", "add rsp,0x18", "ret"]
        check_frame("count_locals", dict(enumerate(body)), "release")
        for changed in ([s.replace("rsp+0x8", "rcx") for s in body],
                        [*body[:4], "mov QWORD PTR [rsp+0x10],r8", *body[5:]],
                        [*body[:4], "jne 2", body[4], *body[6:]]):
            with self.subTest(body=changed), self.assertRaisesRegex(ValueError, "stack-resident accumulator"):
                check_frame("count_locals", dict(enumerate(changed)), "release")

    def test_former_nested_exits(self):
        # Control transfers of the previous compiled fixture, at offsets from its export.
        self.reject("""
            06: js 58
            0b: je 4b
            10: je 50
            17: jmp 2c
            19: lea r8,[rax+r8+7]
            25: je 3c
            27: cmp rdx,rax
            2a: je 40
            2c: test al,1
            2e: je 19
            3a: jne 27
            3c: mov rax,r8
            3f: ret
            40: add r8,1000
            4a: ret
            4b: xor r8d,r8d
            4e: jmp 3c
            50: mov r8d,1000
            56: jmp 3c
            58: mov r8,-7
            5f: jmp 3c
        """)

    def test_sequential_loops(self):
        self.reject("10: jne 10\n20: jne 20\n30: je 50\n40: ret\n50: ret")

    def test_two_latches_one_header(self):
        self.reject("10: je 40\n20: jne 10\n30: ret\n40: jne 10\n50: ret")

    def test_backward_jumps_to_shared_return(self):
        self.reject("10: je 60\n20: jmp 40\n30: ret\n40: je 30\n50: jmp 30\n60: ret")

    def test_unreachable_nesting_and_transfer(self):
        self.reject("01: je 03\n02: ret\n03: ret\n" + NESTED)
        self.check(NESTED + "a0: jmp rax\n")

    def test_missing_inner_or_outer_exit(self):
        self.reject(NESTED.replace("40: je 80", "40: cmp rcx,rdx"))
        self.reject(NESTED.replace("60: je 90", "60: cmp rcx,rdx"))
        # A peeled inner exit before the inner header cannot witness the outer exit.
        self.reject(NESTED.replace("60: je 90", "60: cmp rcx,rdx").replace("31: je 60", "31: je 80"))

    def test_one_reachable_return(self):
        with self.assertRaisesRegex(ValueError, "two reachable returns"):
            self.check(NESTED.replace("80: ret", "80: jmp 11").replace("90: ret", "90: jmp 11"))

    def test_adjacent_symbol_is_outside_leaf(self):
        adjacent = "\na0 <neighbor>:\na0: ret\n"
        self.check(NESTED + adjacent)
        with self.assertRaisesRegex(ValueError, "invalid direct target"):
            self.check(NESTED.replace("40: je 80", "40: je a0") + adjacent)

    def test_malformed_or_unsupported_transfers_keep_provenance(self):
        for transfer in ("jmp 71", "jne nowhere", "jmp rax", "call 11", "ret 8", "loop 40", "syscall"):
            output = "10 <cfg_nested_exits>:\n" + NESTED.replace("40: je 80", "40: " + transfer)
            with self.subTest(transfer=transfer), patch("build.subprocess.check_output", return_value=output):
                with self.assertRaises(ValueError) as failure:
                    check_leaf(Path("cfg_nested_exits.exe"))
                self.assertIn("cfg_nested_exits.exe", str(failure.exception))
                self.assertIn(output, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
