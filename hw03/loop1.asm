
loop1:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	55                   	push   %rbp
  401005:	48 89 e5             	mov    %rsp,%rbp
  401008:	48 83 ec 10          	sub    $0x10,%rsp
  40100c:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401013:	66 c7 45 f9 30 0a    	movw   $0xa30,-0x7(%rbp)
  401019:	c6 45 fb 00          	movb   $0x0,-0x5(%rbp)
  40101d:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401024:	eb 08                	jmp    40102e <_start+0x2e>
  401026:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  40102a:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  40102e:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
  401032:	7e f2                	jle    401026 <_start+0x26>
  401034:	0f b6 45 f9          	movzbl -0x7(%rbp),%eax
  401038:	89 c2                	mov    %eax,%edx
  40103a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40103d:	01 d0                	add    %edx,%eax
  40103f:	88 45 f9             	mov    %al,-0x7(%rbp)
  401042:	48 8d 45 f9          	lea    -0x7(%rbp),%rax
  401046:	ba 02 00 00 00       	mov    $0x2,%edx
  40104b:	48 89 c6             	mov    %rax,%rsi
  40104e:	bf 01 00 00 00       	mov    $0x1,%edi
  401053:	e8 0a 00 00 00       	call   401062 <write>
  401058:	bf 00 00 00 00       	mov    $0x0,%edi
  40105d:	e8 10 00 00 00       	call   401072 <exit>

0000000000401062 <write>:
  401062:	b8 01 00 00 00       	mov    $0x1,%eax
  401067:	0f 05                	syscall
  401069:	c3                   	ret

000000000040106a <read>:
  40106a:	b8 00 00 00 00       	mov    $0x0,%eax
  40106f:	0f 05                	syscall
  401071:	c3                   	ret

0000000000401072 <exit>:
  401072:	b8 3c 00 00 00       	mov    $0x3c,%eax
  401077:	0f 05                	syscall
