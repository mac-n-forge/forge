# Native fault and signatureless ABI probes. Each entry is lifted independently.
.text
.globl entry
entry:
    ret

.macro probe name
    .globl \name
    .seh_proc \name
\name:
    .seh_endprologue
    .section .drectve
    .ascii " -export:\name"
    .text
.endm

.macro boundary suffix,src,dst
probe access_\suffix
    mov\suffix %\src, (%rcx)
    movl $0, %eax
    mov\suffix (%rcx), %\dst
    ret
    .seh_endproc
.endm

boundary b,dl,al
boundary w,dx,ax
boundary l,edx,eax
boundary q,rdx,rax

probe checked_read
    movq %rdx, 8(%rsp)
    movq (%rcx), %rax
    ret
    .seh_endproc

probe conditional_read
    movb %dl, 8(%rsp)
    testq %rcx, %rcx
    je 1f
    movb %dl, 9(%rsp)
1:
    movzwl 8(%rsp), %eax
    ret
    .seh_endproc

probe shifted_rsp
    movq %rdx, %rax
    leaq (%rsp,%rcx), %rsp
    ret
    .seh_endproc

probe restore_rsp
    subq $24, %rsp
    movq %rcx, (%rsp)
    movq (%rsp), %rax
    addq $24, %rsp
    ret
    .seh_endproc

probe moved_rsp_slot
    subq $16, %rsp
    movq %rdx, (%rsp,%rcx)
    movq (%rsp,%rcx), %rax
    addq $16, %rsp
    ret
    .seh_endproc

probe wrap_index
    # Large index products can wrap into a legal address.
    movq %rdx, 8(%rsp,%rcx,8)
    movq 8(%rsp), %rax
    ret
    .seh_endproc

probe entry_memory_loop
1:
    testq %rcx, %rcx
    je 2f
    movq %rdx, 8(%rsp)
    xorq %rcx, %rcx
    jmp 1b
2:
    movq 8(%rsp), %rax
    ret
    .seh_endproc

probe parallel_memory_edges
    cmpq %rdx, %rcx
    movq %rcx, 8(%rsp)
    je 1f
1:
    movq 8(%rsp), %rax
    adcq %rdx, %rax
    ret
    .seh_endproc

# Save valid RSP while testing every view, including SPL. Observe the parent
# after narrow writes and again after its doubleword write via legacy slots.
.macro aliases name,wide,dword,word,low,scratch
probe alias_\name
    movq %rsp, %\scratch
    movabsq $0x123456789abcdef0, %\wide
    movw $0xcdef, %\word
    movb $0x21, %\low
    movq %\wide, 8(%\scratch)
    movl $0x87654321, %\dword
    movq %\wide, %r9
    movq 8(%\scratch), %r8
    movq %\scratch, %rsp
    ret
    .seh_endproc
.endm

aliases ax,rax,eax,ax,al,rsi
aliases cx,rcx,ecx,cx,cl,rsi
aliases dx,rdx,edx,dx,dl,rsi
aliases r8,r8,r8d,r8w,r8b,rsi
aliases r9,r9,r9d,r9w,r9b,rsi
aliases r10,r10,r10d,r10w,r10b,rsi
aliases r11,r11,r11d,r11w,r11b,rsi
aliases sp,rsp,esp,sp,spl,rsi
aliases bp,rbp,ebp,bp,bpl,rsi
aliases bx,rbx,ebx,bx,bl,rsi
aliases si,rsi,esi,si,sil,rdi
aliases di,rdi,edi,di,dil,rsi
aliases r12,r12,r12d,r12w,r12b,rsi
aliases r13,r13,r13d,r13w,r13b,rsi
aliases r14,r14,r14d,r14w,r14b,rsi
aliases r15,r15,r15d,r15w,r15b,rsi

probe high_bytes
    movl $0x76543210, %ebx
    movb %ah, %bh
    movb %ch, %al
    movb %dh, %ah
    movzwl %ax, %r11d
    movq %rbx, %rax
    ret
    .seh_endproc

probe store_immediates
    movq $-1, 8(%rsp)
    movl $0x12345678, 10(%rsp)
    movw $0x5678, 11(%rsp)
    movb $0x34, 12(%rsp)
    movq 8(%rsp), %rax
    ret
    .seh_endproc

# The alternate FF /6 and 8F /0 register encodings also exercise ordering
# when the destination of POP is RSP itself.
probe push_pop_order
    pushq %rbp
    movq %rsp, %rbp
    cmpq %rdx, %rcx
    .byte 0xff, 0xf4   # push rsp
    pushq %rcx
    .byte 0x8f, 0xc0   # pop rax
    popq %rsp
    pushq $-128
    popq %r9
    pushq $-2147483648
    popq %r10
    movq (%rbp), %r11
    movq %r11, (%rbp)
    leave
    adcq %r9, %rax
    addq %r10, %rax
    ret
    .seh_endproc

probe push_rsp_value
    pushq %rsp
    popq %rax
    ret
    .seh_endproc

probe push_rsp_value_modrm
    .byte 0xff, 0xf4   # push rsp (FF /6)
    popq %rax
    ret
    .seh_endproc

probe rsp_pop_destination
    movq %rsp, %r8
    subq $32, %rsp
    pushq %r8
    .byte 0x8f, 0xc4   # pop rsp: the value from the stack wins
    movq %rcx, %rax
    ret
    .seh_endproc

probe frame_layout
    movq %rsp, %r8
    andl $15, %r8d
    pushq %rbp
    movq %rsp, %rbp
    movq %rbp, %rax
    andl $15, %eax
    addq %r8, %rax
    movq %rcx, 16(%rbp)
    movq %rdx, 40(%rbp)
    movq 16(%rbp), %r8
    movq 40(%rbp), %r9
    addq %r8, %rax
    subq %r9, %rax
    leave
    ret
    .seh_endproc

probe saved_registers
    pushq %r12
    movq %r13, %r12
    movq %rbx, 8(%rsp,%rcx)   # rcx=8 selects the first home slot
    movq %rdx, %rbx
    movq %rbx, %rax
    movq 8(%rsp,%rcx), %rbx
    popq %r12
    ret
    .seh_endproc

probe register_save
    movq %rbx, %r10
    movq %rcx, %rbx
    movq %r10, %rbx
    xorl %r10d, %r10d
    movq %rdx, %rax
    ret
    .seh_endproc

probe opaque_scratch
    movq %rbx, %r10
    movq %rdx, %rax
    ret
    .seh_endproc

probe opaque_arithmetic
    movq %rbx, %rax
    addq %rdx, %rax
    ret
    .seh_endproc

probe partial_opaque_return
    movb $1, %r13b
    movq %r13, %rax
    ret
    .seh_endproc

probe swapped_saves
    pushq %rsi
    pushq %rdi
    popq %rsi
    popq %rdi
    movq %rcx, %rax
    ret
    .seh_endproc

probe corrupt_save
    pushq %rbp
    movb $0, (%rsp,%rcx)
    popq %rbp
    movq %rdx, %rax
    ret
    .seh_endproc

probe reordered_save
    pushq %rbp
    movb 1(%rsp), %al
    movb %al, (%rsp)
    popq %rbp
    movq %rdx, %rax
    ret
    .seh_endproc

probe early_clobber
    pushq %rbx
    xorl %ebx, %ebx
    testq %rcx, %rcx
    je 1f
    popq %rbx
    jmp 2f
1:
    addq $8, %rsp
2:
    movq %rdx, %rax
    ret
    .seh_endproc

probe leak_return
    pushq %rbp
    movq (%rsp), %rax
    popq %rbp
    ret
    .seh_endproc

probe leak_address
    pushq %rbp
    popq %r8
    movq (%r8), %rax
    ret
    .seh_endproc

probe frame_loop
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movq %rdx, -8(%rbp)
    andl $7, %ecx
    je 2f
1:
    subq %rcx, %rsp
    movq -8(%rbp), %rax
    addq %rcx, %rax
    movq %rax, -8(%rbp)
    decl %ecx
    jne 1b
2:
    movq -8(%rbp), %rax
    leave
    ret
    .seh_endproc

probe pop_uninitialized
    subq $8, %rsp
    popq %rax
    ret
    .seh_endproc

probe bad_teardown
    pushq %rcx
    movq %rcx, %rax
    ret
    .seh_endproc

probe reserved_pop
    popq %rax
    pushq %rax
    ret
    .seh_endproc

probe push_boundary
    movq %rsp, %r8
    movq %rcx, %rsp
    pushq %rdx
    movq (%rsp), %rax
    popq %rdx
    movq %r8, %rsp
    ret
    .seh_endproc

probe save_all_nonvolatiles
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rcx, %rbx
    movq %rcx, %rbp
    movq %rcx, %rsi
    movq %rcx, %rdi
    movq %rcx, %r12
    movq %rcx, %r13
    movq %rcx, %r14
    movq %rcx, %r15
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    movq %rdx, %rax
    ret
    .seh_endproc

probe read_modify_uninitialized
    subq $8, %rsp
    movw %cx, (%rsp)
    addl $1, (%rsp)
    movl (%rsp), %eax
    addq $8, %rsp
    ret
    .seh_endproc

probe implicit_extensions
    movq %rcx, %rax
    cmpq %rdx, %rcx
    cwde
    cdqe
    adcq $0, %rax
    ret
    .seh_endproc
