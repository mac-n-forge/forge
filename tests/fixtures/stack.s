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
