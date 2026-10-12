# gcc 13.3.0 -O2, x86_64, category 252 TARGET 45. Extracted by tools/pca-implverif (see doc section 4).

######## generator_monomial_mul (codes.c)
generator_monomial_mul:
.LFB83:
	endbr64
	pushq	%r12
	pushq	%rbp
	pushq	%rbx
	leaq	-61440(%rsp), %r11
.LPSRL0:
	subq	$4096, %rsp
	orq	$0, (%rsp)
	cmpq	%r11, %rsp
	jne	.LPSRL0
	subq	$2080, %rsp
	movl	$252, %r9d
	movl	$126, %r8d
	movl	$252, %ecx
	movq	%fs:40, %rax
	movq	%rax, 63512(%rsp)
	xorl	%eax, %eax
	movq	%rsp, %rbp
	movq	%rdi, %r12
	movq	%rdx, %rbx
	movq	%rbp, %rdi
	movl	$126, %edx
	call	matrix_transpose@PLT
	movq	%rbp, %rsi
	xorl	%r10d, %r10d
	leaq	31752(%rsp), %r11
	leaq	31760(%rsp), %rdi
.L11:
	movzwl	252(%rbx,%r10,2), %edx
	movzbl	(%rbx,%r10), %r9d
	xorl	%ecx, %ecx
	movq	%rdx, %rax
	salq	$6, %rax
	subq	%rdx, %rax
	leaq	(%rdi,%rax,2), %r8
.L10:
	movl	%r9d, %eax
	mulb	(%rsi,%rcx)
	movl	%eax, %edx
	andl	$127, %eax
	shrw	$7, %dx
	leal	-127(%rax,%rdx), %eax
	movl	%eax, %edx
	sarb	$7, %dl
	andl	$127, %edx
	addl	%edx, %eax
	movb	%al, (%r8,%rcx)
	addq	$1, %rcx
	cmpq	$126, %rcx
	jne	.L10
	addq	$126, %rsi
	addq	$1, %r10
	cmpq	%rsi, %r11
	jne	.L11
	movq	%rdi, %rsi
	movl	$126, %r9d
	movl	$252, %edx
	movq	%r12, %rdi
	movl	$252, %r8d
	call	matrix_transpose@PLT
	movq	63512(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L16
	addq	$63520, %rsp
	popq	%rbx
	popq	%rbp
	popq	%r12
	ret
.L16:
	call	__stack_chk_fail@PLT

######## CosetRep (monomial.c)
CosetRep:
.LFB63:
	endbr64
	pxor	%xmm0, %xmm0
	leaq	252(%rsi), %r9
	movl	$1, %r8d
	movups	%xmm0, (%rdi)
	movups	%xmm0, 16(%rdi)
.L49:
	movzwl	(%rsi), %ecx
	movl	%r8d, %edx
	addq	$2, %rsi
	movl	%ecx, %eax
	andl	$7, %ecx
	shrw	$3, %ax
	sall	%cl, %edx
	movzwl	%ax, %eax
	xorb	%dl, (%rdi,%rax)
	cmpq	%rsi, %r9
	jne	.L49
	ret

######## generator_RREF_pivot_reuse_ct (codes.c)
generator_RREF_pivot_reuse_ct:
.LFB84:
	endbr64
	pushq	%r15
	movq	%rdx, %r15
	pushq	%r14
	pushq	%r13
	movq	%rdi, %r13
	pushq	%r12
	pushq	%rbp
	movl	%ecx, %ebp
	pushq	%rbx
	subq	$40, %rsp
	movq	%rsi, (%rsp)
	testl	%ecx, %ecx
	je	.L24
	leaq	31500(%rdi), %r12
	movl	$125, %ebx
	jmp	.L23
.L20:
	subq	$1, %rbx
	subq	$252, %r12
	cmpq	$-1, %rbx
	je	.L24
.L23:
	cmpb	$1, (%r15,%rbx)
	jne	.L20
	leaq	0(%r13,%rbx), %rdx
	xorl	%eax, %eax
	xorl	%ecx, %ecx
.L22:
	cmpb	$0, (%rdx)
	cmovne	%rax, %rcx
	addl	$1, %eax
	addq	$252, %rdx
	cmpl	$126, %eax
	jne	.L22
	movq	%rcx, %rax
	movq	%r12, %rdi
	salq	$6, %rax
	subq	%rcx, %rax
	leaq	0(%r13,%rax,4), %rsi
	call	swap_rows
	jmp	.L20
.L24:
	xorl	%r9d, %r9d
	movl	%ebp, %eax
	xorl	%ebx, %ebx
	xorl	%r8d, %r8d
	movl	%r9d, %ebp
	movl	%eax, %r9d
.L19:
	movq	%r8, %r12
	movl	%r8d, %r14d
	movl	%r12d, %ecx
	cmpl	$252, %r12d
	je	.L41
.L56:
	movl	%r14d, %esi
	movl	%r12d, %edx
.L27:
	movl	%esi, %edi
	movq	%rdi, %rax
	salq	$6, %rax
	subq	%rdi, %rax
	salq	$2, %rax
	leaq	0(%r13,%rax), %r10
	cmpb	$0, (%r10,%rdx)
	jne	.L29
	addq	%r12, %rax
	addq	%r13, %rax
.L30:
	cmpb	$0, (%rax)
	jne	.L27
	addl	$1, %esi
	addq	$252, %rax
	cmpl	$126, %esi
	jne	.L30
	addq	$1, %r12
	movl	%r12d, %ecx
	cmpl	$252, %r12d
	jne	.L56
.L41:
	xorl	%eax, %eax
.L17:
	addq	$40, %rsp
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
.L29:
	movq	(%rsp), %rax
	movl	%r12d, %r12d
	movb	$1, (%rax,%r12)
	cmpl	%esi, %r14d
	jne	.L57
.L31:
	cmpb	$1, (%r15,%r12)
	jne	.L32
	cmpl	%ebp, %r9d
	jle	.L32
	cmpl	$125, %ecx
	ja	.L32
	addl	$1, %ebp
.L33:
	addq	$1, %r8
	addq	$252, %rbx
	cmpq	$126, %r8
	jne	.L19
	movl	$1, %eax
	jmp	.L17
.L32:
	movl	%r14d, %esi
	xorl	%edi, %edi
	leaq	fq_inv_table(%rip), %r10
	movq	%rsi, %rax
	salq	$6, %rax
	subq	%rsi, %rax
	leaq	0(%r13,%rax,4), %rax
	movzbl	(%rax,%rdx), %r11d
	xorl	%edx, %edx
	xorl	%eax, %eax
.L34:
	movzbl	(%r10,%rdx), %esi
	cmpq	%r11, %rdx
	cmovne	%eax, %esi
	addq	$1, %rdx
	xorl	%esi, %edi
	cmpq	$127, %rdx
	jne	.L34
	leaq	1(%r13,%rbx), %rsi
	movl	$251, %eax
	leaq	(%rbx,%r12), %rdx
	addq	%r12, %rsi
	subl	%ecx, %eax
	addq	%r13, %rdx
	leaq	(%rsi,%rax), %rcx
.L35:
	movl	%edi, %eax
	mulb	(%rdx)
	addq	$1, %rdx
	movl	%eax, %esi
	andl	$127, %eax
	shrw	$7, %si
	leal	-127(%rax,%rsi), %eax
	movl	%eax, %esi
	sarb	$7, %sil
	andl	$127, %esi
	addl	%esi, %eax
	movb	%al, -1(%rdx)
	cmpq	%rdx, %rcx
	jne	.L35
	leaq	252(%r13), %rcx
	xorl	%esi, %esi
	xorl	%r10d, %r10d
.L37:
	cmpl	%r10d, %r14d
	je	.L39
	movzbl	-252(%rcx,%r12), %edi
	leaq	-252(%rcx), %rdx
.L38:
	leaq	(%rsi,%rdx), %r11
	movl	%edi, %eax
	addq	$1, %rdx
	mulb	(%r11,%rbx)
	movl	%eax, %r11d
	andl	$127, %eax
	shrw	$7, %r11w
	leal	-127(%rax,%r11), %eax
	movzbl	-1(%rdx), %r11d
	subl	%eax, %r11d
	sarb	$7, %al
	andl	$127, %eax
	subl	%eax, %r11d
	movl	%r11d, %eax
	sarb	$7, %al
	andl	$127, %eax
	addl	%eax, %r11d
	movb	%r11b, -1(%rdx)
	cmpq	%rcx, %rdx
	jne	.L38
.L39:
	addl	$1, %r10d
	subq	$252, %rsi
	addq	$252, %rcx
	cmpl	$126, %r10d
	jne	.L37
	jmp	.L33
.L57:
	movb	$0, (%r15,%rdi)
	movq	%r10, %rsi
	leaq	0(%r13,%rbx), %rdi
	movl	%r9d, 28(%rsp)
	movq	%r8, 16(%rsp)
	movq	%rdx, 8(%rsp)
	movl	%ecx, 24(%rsp)
	call	swap_rows
	movl	28(%rsp), %r9d
	movq	16(%rsp), %r8
	movq	8(%rsp), %rdx
	movl	24(%rsp), %ecx
	jmp	.L31

######## sort (sort.c)
sort:
.LFB84:
	endbr64
	movq	$0, (%rdi)
	movq	%rdi, %r8
	leaq	8(%rdi), %rdi
	xorl	%eax, %eax
	movq	$0, 112(%rdi)
	movq	%r8, %rcx
	andq	$-8, %rdi
	subq	%rdi, %rcx
	subl	$-128, %ecx
	shrl	$3, %ecx
	rep stosq
	testl	%edx, %edx
	je	.L8
	movl	%edx, %edx
	addq	%rsi, %rdx
.L10:
	movzbl	(%rsi), %eax
	addq	$1, %rsi
	addb	$1, (%r8,%rax)
	cmpq	%rsi, %rdx
	jne	.L10
.L8:
	ret

######## SortRows (sort.c)
SortRows:
.LFB87:
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	leaq	-16384(%rsp), %r11
.LPSRL0:
	subq	$4096, %rsp
	orq	$0, (%rsp)
	cmpq	%r11, %rsp
	jne	.LPSRL0
	subq	$1920, %rsp
	movq	%rdi, 40(%rsp)
	movl	%esi, %ebx
	movq	%rdx, %r13
	movq	%fs:40, %rax
	movq	%rax, 18296(%rsp)
	xorl	%eax, %eax
	testl	%esi, %esi
	je	.L43
	movl	%esi, %eax
	leaq	96(%rsp), %r12
	movq	%rdi, %rcx
	xorl	%r14d, %r14d
	movq	%rax, 88(%rsp)
	leaq	1120(%rsp), %rax
	xorl	%r15d, %r15d
	leaq	126(%rcx), %r8
	movl	%esi, 68(%rsp)
	leaq	2144(%rsp), %rdi
	movq	%r8, %r13
	movq	%rdx, 56(%rsp)
	movq	%r12, 72(%rsp)
	movq	%rax, 80(%rsp)
	movq	%r14, %rax
	movl	%r15d, %r14d
	movq	%rax, %r15
.L18:
	movq	%r15, %rcx
	movl	$128, %edx
	xorl	%esi, %esi
	movl	%r15d, %r12d
	negq	%rcx
	leaq	-126(%r13), %rbx
	salq	$7, %rcx
	addq	$16128, %rcx
	call	__memset_chk@PLT
	movq	%rax, %rdi
.L17:
	movzbl	(%rbx), %eax
	addq	$1, %rbx
	addb	$1, (%rdi,%rax)
	cmpq	%r13, %rbx
	jne	.L17
	movzbl	(%rdi), %eax
	cmpl	%eax, %r14d
	cmovb	%eax, %r14d
	movq	80(%rsp), %rax
	addq	$126, %r13
	movq	%rdi, (%rax,%r15,8)
	movq	72(%rsp), %rax
	subq	$-128, %rdi
	movl	%r12d, (%rax,%r15,4)
	addq	$1, %r15
	cmpq	%r15, 88(%rsp)
	jne	.L18
	movl	68(%rsp), %ebx
	movq	56(%rsp), %r13
	movl	%r14d, %r15d
.L16:
	testq	%r13, %r13
	je	.L19
	movzbl	0(%r13), %edx
	xorl	%eax, %eax
	cmpl	%edx, %r15d
	jb	.L15
.L19:
	leal	-1(%rbx), %eax
	movl	$1, %r15d
	movl	%ebx, 64(%rsp)
	movl	$1, %r14d
	movl	%eax, 612(%rsp)
	leaq	1120(%rsp), %rax
	movq	%rax, 32(%rsp)
	leaq	96(%rsp), %rax
	movl	$0, 608(%rsp)
	movq	%rax, 24(%rsp)
	movq	%r15, 88(%rsp)
.L21:
	leal	-1(%r14), %r13d
	movq	24(%rsp), %r15
	movl	%r13d, %edx
	movq	32(%rsp), %r13
.L36:
	movq	88(%rsp), %rax
	movl	608(%rsp,%rax,4), %r12d
	movslq	%edx, %rax
	movl	608(%rsp,%rax,4), %eax
	leal	-1(%rax), %r11d
	cmpl	%eax, %r12d
	jle	.L61
	movl	%eax, 80(%rsp)
	movslq	%eax, %r8
	movslq	%r12d, %rcx
	movl	%r14d, 72(%rsp)
	leaq	0(%r13,%r8,8), %r9
	leaq	(%r15,%r8,4), %r10
	movl	%eax, %r8d
	movl	%edx, 68(%rsp)
	leaq	0(%r13,%rcx,8), %rbx
	movq	%r15, 56(%rsp)
	movq	%r13, 48(%rsp)
.L30:
	movq	(%rbx), %r14
	movq	(%r9), %rdi
	xorl	%eax, %eax
	jmp	.L25
.L27:
	addq	$1, %rax
	cmpq	$126, %rax
	je	.L62
.L25:
	movzbl	(%rdi,%rax), %esi
	movzbl	(%r14,%rax), %edx
	cmpb	%dl, %sil
	je	.L27
.L26:
	cmpb	%dl, %sil
	ja	.L63
.L28:
	addl	$1, %r8d
	addq	$8, %r9
	addq	$4, %r10
	cmpl	%r8d, %r12d
	jne	.L30
	leal	1(%r11), %r8d
	movl	80(%rsp), %eax
	movl	72(%rsp), %r14d
	movl	68(%rsp), %edx
	movq	56(%rsp), %rdi
	movq	48(%rsp), %rsi
	cmpl	%r8d, %r12d
	je	.L31
.L23:
	movslq	%r8d, %r8
	leaq	(%rdi,%rcx,4), %r10
	leaq	(%rsi,%rcx,8), %rcx
	leaq	(%rdi,%r8,4), %r9
	leaq	(%rsi,%r8,8), %rsi
	movq	(%rcx), %r8
	movl	(%r9), %edi
	xorl	(%r10), %edi
	movl	%edi, (%r9)
	xorl	(%r10), %edi
	movl	%edi, (%r10)
	xorl	%edi, (%r9)
	movq	(%rsi), %rdi
	movq	%r8, (%rsi)
	movq	%rdi, (%rcx)
.L31:
	cmpl	%r11d, %eax
	jl	.L32
.L24:
	addl	$2, %r11d
	subl	$2, %r14d
	cmpl	%r11d, %r12d
	jg	.L33
	testl	%r14d, %r14d
	js	.L58
	movslq	%r14d, %rax
	leal	-1(%r14), %edx
	movq	%rax, 88(%rsp)
	jmp	.L36
.L63:
	addl	$1, %r11d
	cmpl	%r11d, %r8d
	je	.L28
	movslq	%r11d, %rsi
	leaq	(%r15,%rsi,4), %rdx
	movl	(%rdx), %eax
	xorl	(%r10), %eax
	movl	%eax, (%rdx)
	xorl	(%r10), %eax
	movl	%eax, (%r10)
	xorl	%eax, (%rdx)
	leaq	0(%r13,%rsi,8), %rax
	movq	(%rax), %rdx
	movq	%rdi, (%rax)
	movq	%rdx, (%r9)
	jmp	.L28
.L62:
	movzbl	126(%r14), %edx
	movzbl	126(%rdi), %esi
	jmp	.L26
.L32:
	movq	88(%rsp), %rax
	movl	%r11d, 608(%rsp,%rax,4)
	addl	$2, %r11d
	cmpl	%r12d, %r11d
	jge	.L36
.L33:
	leal	1(%r14), %eax
	addl	$2, %r14d
	cltq
	movl	%r11d, 608(%rsp,%rax,4)
	movslq	%r14d, %rax
	movq	%rax, 88(%rsp)
	movl	%r12d, 608(%rsp,%rax,4)
	jmp	.L21
.L61:
	je	.L24
	movq	%r13, %rsi
	movq	%r15, %rdi
	movslq	%r12d, %rcx
	movl	%eax, %r8d
	jmp	.L23
.L58:
	movl	64(%rsp), %r13d
	xorl	%r14d, %r14d
	leaq	96(%rsp), %r12
	testl	%r13d, %r13d
	je	.L41
	movq	40(%rsp), %rbx
.L40:
	movl	(%r12,%r14,4), %eax
	movl	%r14d, %edx
	cmpl	%r14d, %eax
	jnb	.L38
.L39:
	movl	(%r12,%rax,4), %eax
	cmpl	%edx, %eax
	jb	.L39
.L38:
	movl	%r14d, %esi
	movzwl	%ax, %edx
	movq	%rbx, %rdi
	addq	$1, %r14
	call	normalized_row_swap@PLT
	cmpq	%r14, %r13
	jne	.L40
.L41:
	movl	$1, %eax
.L15:
	movq	18296(%rsp), %rdx
	subq	%fs:40, %rdx
	jne	.L64
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
.L43:
	xorl	%r15d, %r15d
	jmp	.L16
.L64:
	call	__stack_chk_fail@PLT

######## ScaleCF (canonical.c)
ScaleCF:
.LFB82:
	pushq	%rbp
	movq	%rdi, %r9
	movq	%rsi, %rbp
	leaq	fq_inv_table(%rip), %r8
	pushq	%rbx
	movq	%rdi, %rbx
	leaq	126(%rdi), %rdi
	leaq	1(%rbx), %r10
	leaq	16002(%rbx), %r11
	subq	$8, %rsp
.L9:
	movzbl	(%r9), %eax
	movq	%r10, %rdx
	movl	%eax, %ecx
	jmp	.L3
.L23:
	addq	$1, %rdx
	cmpq	%rdx, %rdi
	je	.L4
.L3:
	movl	%ecx, %esi
	movzbl	(%rdx), %ecx
	cmpb	%sil, %cl
	je	.L23
	movq	%r10, %rdx
.L2:
	movzbl	(%rdx), %ecx
	addq	$1, %rdx
	leal	-127(%rax,%rcx), %eax
	movl	%eax, %ecx
	sarb	$7, %cl
	andl	$127, %ecx
	addl	%ecx, %eax
	cmpq	%rdx, %rdi
	jne	.L2
	movl	%eax, %edx
	shrb	$7, %al
	andl	$127, %edx
	leal	-127(%rax,%rdx), %eax
	movl	%eax, %esi
	sarb	$7, %sil
	andl	$127, %esi
	addb	%al, %sil
	je	.L12
	movzbl	%sil, %esi
	movzbl	(%r8,%rsi), %esi
.L6:
	movq	%r9, %rcx
.L8:
	movl	%esi, %eax
	mulb	(%rcx)
	addq	$1, %rcx
	movl	%eax, %edx
	andl	$127, %eax
	shrw	$7, %dx
	leal	-127(%rax,%rdx), %eax
	movl	%eax, %edx
	sarb	$7, %dl
	andl	$127, %edx
	addl	%eax, %edx
	movb	%dl, -1(%rcx)
	cmpq	%rcx, %rdi
	jne	.L8
.L4:
	addq	$126, %rdi
	addq	$126, %r9
	addq	$126, %r10
	cmpq	%rdi, %r11
	jne	.L9
	movq	%rbp, %rdx
	movl	$126, %esi
	movq	%rbx, %rdi
	call	SortRows@PLT
	testl	%eax, %eax
	jne	.L24
.L10:
	addq	$8, %rsp
	xorl	%eax, %eax
	popq	%rbx
	popq	%rbp
	ret
.L12:
	movq	%r9, %rdx
.L5:
	movzbl	(%rdx), %eax
	addq	$1, %rdx
	movzbl	(%r8,%rax), %eax
	leal	-127(%rsi,%rax), %eax
	movl	%eax, %esi
	sarb	$7, %sil
	andl	$127, %esi
	addl	%eax, %esi
	cmpq	%rdx, %rdi
	jne	.L5
	testb	%sil, %sil
	jne	.L6
	jmp	.L10
.L24:
	movq	%rbx, %rdi
	movl	$126, %esi
	call	SortCols@PLT
	addq	$8, %rsp
	movl	$1, %eax
	popq	%rbx
	popq	%rbp
	ret

######## ImprovedCF (canonical.c)
ImprovedCF:
.LFB88:
	pushq	%rbp
	pxor	%xmm0, %xmm0
	movq	%rdi, %rdx
	leaq	126(%rdi), %rsi
	movq	%rdi, %r9
	xorl	%r8d, %r8d
	xorl	%r10d, %r10d
	movq	%rsp, %rbp
	pushq	%r15
	movq	%rdi, %r15
	xorl	%edi, %edi
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$1184, %rsp
	movq	%fs:40, %rax
	movq	%rax, 1176(%rsp)
	xorl	%eax, %eax
	movaps	%xmm0, 736(%rsp)
	movaps	%xmm0, 640(%rsp)
	movaps	%xmm0, 656(%rsp)
	movaps	%xmm0, 672(%rsp)
	movaps	%xmm0, 688(%rsp)
	movaps	%xmm0, 704(%rsp)
	movaps	%xmm0, 720(%rsp)
	movups	%xmm0, 750(%rsp)
.L120:
	movl	%r8d, %r11d
	movq	%r9, %rax
	xorl	%ecx, %ecx
.L117:
	cmpb	$1, (%rax)
	adcl	$0, %ecx
	addq	$1, %rax
	cmpq	%rax, %rsi
	jne	.L117
	testl	%ecx, %ecx
	je	.L118
	movb	$1, 640(%rsp,%r8)
	cmpl	%ecx, %r10d
	jb	.L175
.L118:
	cmpl	%r10d, %ecx
	jne	.L119
	movl	%edi, %eax
	addl	$1, %edi
	movl	%r11d, 128(%rsp,%rax,4)
.L119:
	addq	$1, %r8
	addq	$126, %r9
	addq	$126, %rsi
	cmpq	$126, %r8
	jne	.L120
	cmpl	$126, %edi
	je	.L176
	movl	%edi, %ecx
	leaq	B.2(%rip), %rbx
	pxor	%xmm0, %xmm0
	xorl	%r11d, %r11d
	leaq	128(%rsp), %rax
	movq	%r15, 80(%rsp)
	movq	%rdx, %r15
	leaq	768(%rsp), %r13
	leaq	(%rax,%rcx,4), %r8
	movq	%rax, 88(%rsp)
	movq	%rcx, %rax
	leaq	fq_inv_table(%rip), %r14
	salq	$6, %rax
	movaps	%xmm0, 864(%rsp)
	leaq	1024(%rsp), %r12
	subq	%rcx, %rax
	leaq	126(%rbx), %rcx
	movl	$0, 116(%rsp)
	leaq	(%rbx,%rax,2), %rax
	movq	%rbx, 72(%rsp)
	movq	%rax, 120(%rsp)
	leaq	640(%rsp), %rax
	movq	%rax, 104(%rsp)
	leaq	896(%rsp), %rax
	movq	%rax, 96(%rsp)
	movq	%rcx, 64(%rsp)
	movaps	%xmm0, 768(%rsp)
	movaps	%xmm0, 784(%rsp)
	movaps	%xmm0, 800(%rsp)
	movaps	%xmm0, 816(%rsp)
	movaps	%xmm0, 832(%rsp)
	movaps	%xmm0, 848(%rsp)
	movups	%xmm0, 878(%rsp)
	movaps	%xmm0, 896(%rsp)
	movaps	%xmm0, 912(%rsp)
	movaps	%xmm0, 928(%rsp)
	movaps	%xmm0, 944(%rsp)
	movaps	%xmm0, 960(%rsp)
	movaps	%xmm0, 976(%rsp)
	movaps	%xmm0, 992(%rsp)
	movaps	%xmm0, 1008(%rsp)
	jmp	.L140
.L125:
	addq	$1, %r11
	addq	$126, %r15
	cmpq	$126, %r11
	je	.L177
.L140:
	movq	104(%rsp), %rax
	cmpb	$0, (%rax,%r11)
	jne	.L125
	xorl	%eax, %eax
.L126:
	movzbl	(%r15,%rax), %ecx
	movzbl	(%r14,%rcx), %ecx
	movb	%cl, 0(%r13,%rax)
	addq	$1, %rax
	cmpq	$126, %rax
	jne	.L126
	testl	%edi, %edi
	je	.L125
	movq	88(%rsp), %r9
	leaq	B.2(%rip), %rsi
.L129:
	movl	(%r9), %ecx
	movq	%rcx, %rax
	salq	$6, %rax
	subq	%rcx, %rax
	xorl	%ecx, %ecx
	leaq	(%rdx,%rax,2), %r10
.L128:
	movzbl	(%r10,%rcx), %eax
	mulb	0(%r13,%rcx)
	movl	%eax, %ebx
	andl	$127, %eax
	shrw	$7, %bx
	leal	-127(%rax,%rbx), %eax
	movl	%eax, %ebx
	sarb	$7, %bl
	andl	$127, %ebx
	addl	%ebx, %eax
	movb	%al, (%rsi,%rcx)
	addq	$1, %rcx
	cmpq	$126, %rcx
	jne	.L128
	addq	$4, %r9
	addq	$126, %rsi
	cmpq	%r9, %r8
	jne	.L129
	movl	%edi, 60(%rsp)
	pxor	%xmm0, %xmm0
	leaq	126+B.2(%rip), %rcx
	movl	$0, 112(%rsp)
	leaq	-126(%rcx), %rbx
	movq	%r11, 40(%rsp)
	movq	%r8, 32(%rsp)
	movq	%rdx, 24(%rsp)
	movq	%r15, 48(%rsp)
	movq	96(%rsp), %r15
	movq	%r13, 16(%rsp)
	movq	%rcx, %r13
	movaps	%xmm0, 1024(%rsp)
	movaps	%xmm0, 1040(%rsp)
	movaps	%xmm0, 1056(%rsp)
	movaps	%xmm0, 1072(%rsp)
	movaps	%xmm0, 1088(%rsp)
	movaps	%xmm0, 1104(%rsp)
	movaps	%xmm0, 1120(%rsp)
	movaps	%xmm0, 1136(%rsp)
.L139:
	movzbl	(%rbx), %eax
	leaq	-125(%r13), %rsi
.L132:
	movzbl	(%rsi), %edx
	addq	$1, %rsi
	leal	-127(%rax,%rdx), %eax
	movl	%eax, %edx
	sarb	$7, %dl
	andl	$127, %edx
	addl	%edx, %eax
	cmpq	%rsi, %r13
	jne	.L132
	movl	%eax, %edx
	shrb	$7, %al
	andl	$127, %edx
	leal	-127(%rax,%rdx), %eax
	movl	%eax, %r9d
	sarb	$7, %r9b
	andl	$127, %r9d
	addb	%al, %r9b
	je	.L147
	movzbl	%r9b, %r9d
	movzbl	(%r14,%r9), %r9d
.L134:
	movq	%rbx, %rdi
.L136:
	movl	%r9d, %eax
	mulb	(%rdi)
	addq	$1, %rdi
	movl	%eax, %edx
	andl	$127, %eax
	shrw	$7, %dx
	leal	-127(%rax,%rdx), %eax
	movl	%eax, %edx
	sarb	$7, %dl
	andl	$127, %edx
	addl	%edx, %eax
	movb	%al, -1(%rdi)
	cmpq	%rdi, %r13
	jne	.L136
	movq	%rbx, %rsi
	movq	%r12, %rdi
	movl	$126, %edx
	call	sort@PLT
	movq	%r15, %rsi
	movq	%r12, %rdi
	call	compare_rows@PLT
	testl	%eax, %eax
	js	.L178
.L138:
	addq	$126, %rbx
	addq	$126, %r13
	cmpq	%rbx, 120(%rsp)
	jne	.L139
	movl	112(%rsp), %eax
	movq	40(%rsp), %r11
	movq	48(%rsp), %r15
	movl	60(%rsp), %edi
	testl	%eax, %eax
	movl	116(%rsp), %eax
	movq	32(%rsp), %r8
	movq	24(%rsp), %rdx
	movq	16(%rsp), %r13
	cmovne	%r11d, %eax
	addq	$1, %r11
	addq	$126, %r15
	movl	%eax, 116(%rsp)
	cmpq	$126, %r11
	jne	.L140
.L177:
	movl	116(%rsp), %eax
	movq	80(%rsp), %r15
	movq	72(%rsp), %rbx
	movq	64(%rsp), %rcx
	movq	%rax, %rsi
	salq	$6, %rsi
	subq	%rax, %rsi
	xorl	%eax, %eax
	leaq	(%rdx,%rsi,2), %rdi
.L141:
	movzbl	(%rdi,%rax), %esi
	movzbl	(%r14,%rsi), %esi
	movb	%sil, 0(%r13,%rax)
	addq	$1, %rax
	cmpq	$126, %rax
	jne	.L141
	leaq	15876+B.2(%rip), %rdi
.L143:
	xorl	%esi, %esi
.L142:
	movzbl	(%r15,%rsi), %eax
	mulb	0(%r13,%rsi)
	movl	%eax, %r8d
	andl	$127, %eax
	shrw	$7, %r8w
	leal	-127(%rax,%r8), %eax
	movl	%eax, %r8d
	sarb	$7, %r8b
	andl	$127, %r8d
	addl	%r8d, %eax
	movb	%al, (%rbx,%rsi)
	addq	$1, %rsi
	cmpq	$126, %rsi
	jne	.L142
	addq	$126, %r15
	movq	%rcx, %rbx
	cmpq	%rdi, %rcx
	je	.L172
	addq	$126, %rcx
	jmp	.L143
.L175:
	movl	%r11d, 128(%rsp)
	movl	%ecx, %r10d
	movl	$1, %edi
	jmp	.L119
.L147:
	movq	%rbx, %rdx
	movl	%r9d, %eax
.L133:
	movzbl	(%rdx), %ecx
	addq	$1, %rdx
	movzbl	(%r14,%rcx), %ecx
	leal	-127(%rax,%rcx), %eax
	movl	%eax, %ecx
	sarb	$7, %cl
	andl	$127, %ecx
	addl	%ecx, %eax
	cmpq	%r13, %rdx
	jne	.L133
	movl	%eax, %r9d
	testb	%al, %al
	jne	.L134
	jmp	.L138
.L178:
	movdqa	(%r12), %xmm1
	movdqa	16(%r12), %xmm2
	movl	$1, 112(%rsp)
	movdqa	32(%r12), %xmm3
	movdqa	48(%r12), %xmm4
	movdqa	64(%r12), %xmm5
	movdqa	80(%r12), %xmm6
	movaps	%xmm1, (%r15)
	movdqa	96(%r12), %xmm7
	movdqu	111(%r12), %xmm1
	movaps	%xmm2, 16(%r15)
	movaps	%xmm3, 32(%r15)
	movaps	%xmm7, 96(%r15)
	movaps	%xmm4, 48(%r15)
	movaps	%xmm5, 64(%r15)
	movaps	%xmm6, 80(%r15)
	movups	%xmm1, 111(%r15)
	jmp	.L138
.L172:
	movq	96(%rsp), %rsi
	leaq	B.2(%rip), %rdi
	movq	%rdx, 120(%rsp)
	call	ScaleCF
	movq	120(%rsp), %rdx
	cmpl	$1, %eax
	movl	%eax, %ebx
	jne	.L179
	leaq	B.2(%rip), %rsi
	movq	%rdx, %rdi
	call	normalized_copy@PLT
.L116:
	movq	1176(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L174
	leaq	-40(%rbp), %rsp
	movl	%ebx, %eax
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
.L179:
	movq	%rdx, %rdi
	call	ImprovedCFBase
	movl	%eax, %ebx
	jmp	.L116
.L176:
	movq	1176(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L174
	leaq	-40(%rbp), %rsp
	movq	%rdx, %rdi
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	jmp	CFOriginal
.L174:
	call	__stack_chk_fail@PLT
######## LESS_sign: stores indexed by a loaded permutation value (permuted_pivot_flags[perm[t]] = flags[t])
329:	movb	%cl, 110416(%rsp,%rdx)
735:	movb	%cl, 352400(%rsp,%rdx)
