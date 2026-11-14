.text
.macro stack_leaf name
    .globl stack_\name
    .seh_proc stack_\name
stack_\name:
    .seh_endprologue
    .section .drectve
    .ascii " -export:stack_\name"
    .text
.endm

stack_leaf roundtrip
    movq %rcx, 8(%rsp)
    movq %rdx, 24(%rsp)
    movq 8(%rsp), %rax
    movq 24(%rsp), %r8
    subq %r8, %rax
    ret
    .seh_endproc

stack_leaf widths
    movq $-2, 8(%rsp)
    movb %dl, 8(%rsp)
    movq 8(%rsp), %r9
    movb %cl, 16(%rsp)
    movsbq 16(%rsp), %r10
    movw %cx, 18(%rsp)
    movswq 18(%rsp), %r8
    movl %edx, 22(%rsp)
    movslq 22(%rsp), %rdx
    movl 22(%rsp), %eax
    addq %rdx, %rax
    addq %r8, %rax
    addq %r9, %rax
    addq %r10, %rax
    ret
    .seh_endproc

stack_leaf overlap
    movq %rcx, 9(%rsp)
    movw %dx, 11(%rsp)
    movl 10(%rsp), %eax
    movzbw 9(%rsp), %r8w
    movzwq %r8w, %r8
    addq %r8, %rax
    ret
    .seh_endproc

# Only the outer Windows entry saves the native caller's nonvolatile RBP.
.globl stack_indexed_driver
.seh_proc stack_indexed_driver
stack_indexed_driver:
    pushq %rbp
    .seh_pushreg %rbp
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    call stack_indexed
    addq $32, %rsp
    popq %rbp
    ret
    .seh_endproc

stack_leaf indexed
    movl $0x11223344, 8(%rsp)
    movl $0x80000001, 12(%rsp)
    movl %edx, 16(%rsp)
    movl $0xfedcba98, 20(%rsp)
    leaq 24(%rsp), %rbp
    andl $3, %ecx
    movq $-1, %rax
    # MOVSXD EAX, dword ptr [RBP + RCX*4 - 16], opcode 63 without REX.W.
    .byte 0x63, 0x44, 0x8d, 0xf0
    ret
    .seh_endproc

stack_leaf branch
    movq %rdx, 24(%rsp)
    cmpq %rdx, %rcx
    jg 1f
    movq %rdx, 8(%rsp)
    jmp 2f
1:
    movq %rcx, 8(%rsp)
2:
    movq 8(%rsp), %rax
    movq 24(%rsp), %r10
    adcq %r10, %rax
    ret
    .seh_endproc

stack_leaf loop
    movq %rdx, 16(%rsp)
    andl $7, %ecx
    je 2f
1:
    movq 16(%rsp), %rax
    addq %rcx, %rax
    movq %rax, 16(%rsp)
    decl %ecx
    jne 1b
2:
    movq 16(%rsp), %rax
    ret
    .seh_endproc
