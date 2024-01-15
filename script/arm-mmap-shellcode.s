	.section	.rodata
	.align	2
.LC0:
	.ascii	"/dev/mem\000"
	.text
	.align	2
	.global _start	
	.type	_start, %function
_start:
	mov	r0, #0
	mov	r1, #8192 	@ Page size - 0x2000
	mov	r2, #7 		@ PROT_READ | PROT_WRITE | PROT_EXEC
	mov	r3, #33  	@ MAP_SHARED | MAP_ANONYMOUS
	mov	r4, #-1 	@ INVALID FD
	mov	r5, #0		@ offset
	mov	r7, #192	@ syscall ID
	swi	#0 			@ make the sycall
	mov	r0, #0
	mov	r7, #1
	swi	#0 @ exit(0)                                 = ?
.L4:
	.align	2
.L3:
	.word	.LC0
	.size	_start, .-_start
