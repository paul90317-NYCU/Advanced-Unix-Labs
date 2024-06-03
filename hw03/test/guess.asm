
guess:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <cmpans>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	55                   	push   %rbp
  401005:	48 89 e5             	mov    %rsp,%rbp
  401008:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  40100c:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  401010:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401017:	eb 2f                	jmp    401048 <cmpans+0x48>
  401019:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40101c:	48 63 d0             	movslq %eax,%rdx
  40101f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401023:	48 01 d0             	add    %rdx,%rax
  401026:	0f b6 10             	movzbl (%rax),%edx
  401029:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40102c:	48 63 c8             	movslq %eax,%rcx
  40102f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  401033:	48 01 c8             	add    %rcx,%rax
  401036:	0f b6 00             	movzbl (%rax),%eax
  401039:	38 c2                	cmp    %al,%dl
  40103b:	74 07                	je     401044 <cmpans+0x44>
  40103d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  401042:	eb 45                	jmp    401089 <cmpans+0x89>
  401044:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  401048:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40104b:	48 63 d0             	movslq %eax,%rdx
  40104e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  401052:	48 01 d0             	add    %rdx,%rax
  401055:	0f b6 00             	movzbl (%rax),%eax
  401058:	84 c0                	test   %al,%al
  40105a:	74 28                	je     401084 <cmpans+0x84>
  40105c:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40105f:	48 63 d0             	movslq %eax,%rdx
  401062:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401066:	48 01 d0             	add    %rdx,%rax
  401069:	0f b6 00             	movzbl (%rax),%eax
  40106c:	3c 30                	cmp    $0x30,%al
  40106e:	74 14                	je     401084 <cmpans+0x84>
  401070:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401073:	48 63 d0             	movslq %eax,%rdx
  401076:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40107a:	48 01 d0             	add    %rdx,%rax
  40107d:	0f b6 00             	movzbl (%rax),%eax
  401080:	3c 0a                	cmp    $0xa,%al
  401082:	75 95                	jne    401019 <cmpans+0x19>
  401084:	b8 00 00 00 00       	mov    $0x0,%eax
  401089:	5d                   	pop    %rbp
  40108a:	c3                   	ret

000000000040108b <_start>:
  40108b:	f3 0f 1e fa          	endbr64
  40108f:	55                   	push   %rbp
  401090:	48 89 e5             	mov    %rsp,%rbp
  401093:	48 83 ec 10          	sub    $0x10,%rsp
  401097:	ba 12 00 00 00       	mov    $0x12,%edx
  40109c:	48 8d 05 5d 0f 00 00 	lea    0xf5d(%rip),%rax        # 402000 <prompt>
  4010a3:	48 89 c6             	mov    %rax,%rsi
  4010a6:	bf 01 00 00 00       	mov    $0x1,%edi
  4010ab:	e8 78 00 00 00       	call   401128 <write>
  4010b0:	ba 10 00 00 00       	mov    $0x10,%edx
  4010b5:	48 8d 05 44 2f 00 00 	lea    0x2f44(%rip),%rax        # 404000 <buf>
  4010bc:	48 89 c6             	mov    %rax,%rsi
  4010bf:	bf 00 00 00 00       	mov    $0x0,%edi
  4010c4:	e8 67 00 00 00       	call   401130 <read>
  4010c9:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4010cd:	48 8d 05 3e 0f 00 00 	lea    0xf3e(%rip),%rax        # 402012 <answer>
  4010d4:	48 89 c6             	mov    %rax,%rsi
  4010d7:	48 8d 05 22 2f 00 00 	lea    0x2f22(%rip),%rax        # 404000 <buf>
  4010de:	48 89 c7             	mov    %rax,%rdi
  4010e1:	e8 1a ff ff ff       	call   401000 <cmpans>
  4010e6:	85 c0                	test   %eax,%eax
  4010e8:	75 1b                	jne    401105 <_start+0x7a>
  4010ea:	ba 06 00 00 00       	mov    $0x6,%edx
  4010ef:	48 8d 05 1f 0f 00 00 	lea    0xf1f(%rip),%rax        # 402015 <ok>
  4010f6:	48 89 c6             	mov    %rax,%rsi
  4010f9:	bf 01 00 00 00       	mov    $0x1,%edi
  4010fe:	e8 25 00 00 00       	call   401128 <write>
  401103:	eb 19                	jmp    40111e <_start+0x93>
  401105:	ba 0b 00 00 00       	mov    $0xb,%edx
  40110a:	48 8d 05 0f 0f 00 00 	lea    0xf0f(%rip),%rax        # 402020 <fail>
  401111:	48 89 c6             	mov    %rax,%rsi
  401114:	bf 01 00 00 00       	mov    $0x1,%edi
  401119:	e8 0a 00 00 00       	call   401128 <write>
  40111e:	bf 00 00 00 00       	mov    $0x0,%edi
  401123:	e8 10 00 00 00       	call   401138 <exit>

0000000000401128 <write>:
  401128:	b8 01 00 00 00       	mov    $0x1,%eax
  40112d:	0f 05                	syscall
  40112f:	c3                   	ret

0000000000401130 <read>:
  401130:	b8 00 00 00 00       	mov    $0x0,%eax
  401135:	0f 05                	syscall
  401137:	c3                   	ret

0000000000401138 <exit>:
  401138:	b8 3c 00 00 00       	mov    $0x3c,%eax
  40113d:	0f 05                	syscall
