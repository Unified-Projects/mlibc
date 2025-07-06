
.global _start
_start:
	mov $0x1B, %ax
    mov %ax, %ds
    mov %ax, %es

    xor %rbp, %rbp

	call relocateSelf

	mov %rsp, %rdi
	call interpreterMain

	jmp *%rax
.section .note.GNU-stack,"",%progbits

