
main:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000318 <.interp>:
 318:	2f                   	(bad)
 319:	6c                   	ins    BYTE PTR es:[rdi],dx
 31a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 321:	2d 6c 69 6e 75       	sub    eax,0x756e696c
 326:	78 2d                	js     355 <__abi_tag-0x27>
 328:	78 38                	js     362 <__abi_tag-0x1a>
 32a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
 330:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 331:	2e 32 00             	cs xor al,BYTE PTR [rax]

Disassembly of section .note.gnu.property:

0000000000000338 <.note.gnu.property>:
 338:	04 00                	add    al,0x0
 33a:	00 00                	add    BYTE PTR [rax],al
 33c:	10 00                	adc    BYTE PTR [rax],al
 33e:	00 00                	add    BYTE PTR [rax],al
 340:	05 00 00 00 47       	add    eax,0x47000000
 345:	4e 55                	rex.WRX push rbp
 347:	00 02                	add    BYTE PTR [rdx],al
 349:	80 00 c0             	add    BYTE PTR [rax],0xc0
 34c:	04 00                	add    al,0x0
 34e:	00 00                	add    BYTE PTR [rax],al
 350:	01 00                	add    DWORD PTR [rax],eax
 352:	00 00                	add    BYTE PTR [rax],al
 354:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .note.gnu.build-id:

0000000000000358 <.note.gnu.build-id>:
 358:	04 00                	add    al,0x0
 35a:	00 00                	add    BYTE PTR [rax],al
 35c:	14 00                	adc    al,0x0
 35e:	00 00                	add    BYTE PTR [rax],al
 360:	03 00                	add    eax,DWORD PTR [rax]
 362:	00 00                	add    BYTE PTR [rax],al
 364:	47                   	rex.RXB
 365:	4e 55                	rex.WRX push rbp
 367:	00 a2 c3 7b 43 2e    	add    BYTE PTR [rdx+0x2e437bc3],ah
 36d:	d7                   	xlat   BYTE PTR ds:[rbx]
 36e:	c2 54 77             	ret    0x7754
 371:	dd 1b                	fstp   QWORD PTR [rbx]
 373:	55                   	push   rbp
 374:	b5 dd                	mov    ch,0xdd
 376:	71 3a                	jno    3b2 <__abi_tag+0x36>
 378:	ac                   	lods   al,BYTE PTR ds:[rsi]
 379:	df 61 7e             	fbld   TBYTE PTR [rcx+0x7e]

Disassembly of section .note.ABI-tag:

000000000000037c <__abi_tag>:
 37c:	04 00                	add    al,0x0
 37e:	00 00                	add    BYTE PTR [rax],al
 380:	10 00                	adc    BYTE PTR [rax],al
 382:	00 00                	add    BYTE PTR [rax],al
 384:	01 00                	add    DWORD PTR [rax],eax
 386:	00 00                	add    BYTE PTR [rax],al
 388:	47                   	rex.RXB
 389:	4e 55                	rex.WRX push rbp
 38b:	00 00                	add    BYTE PTR [rax],al
 38d:	00 00                	add    BYTE PTR [rax],al
 38f:	00 03                	add    BYTE PTR [rbx],al
 391:	00 00                	add    BYTE PTR [rax],al
 393:	00 02                	add    BYTE PTR [rdx],al
 395:	00 00                	add    BYTE PTR [rax],al
 397:	00 00                	add    BYTE PTR [rax],al
 399:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .gnu.hash:

00000000000003a0 <.gnu.hash>:
 3a0:	02 00                	add    al,BYTE PTR [rax]
 3a2:	00 00                	add    BYTE PTR [rax],al
 3a4:	06                   	(bad)
 3a5:	00 00                	add    BYTE PTR [rax],al
 3a7:	00 01                	add    BYTE PTR [rcx],al
 3a9:	00 00                	add    BYTE PTR [rax],al
 3ab:	00 06                	add    BYTE PTR [rsi],al
 3ad:	00 00                	add    BYTE PTR [rax],al
 3af:	00 00                	add    BYTE PTR [rax],al
 3b1:	00 81 00 00 00 00    	add    BYTE PTR [rcx+0x0],al
 3b7:	00 06                	add    BYTE PTR [rsi],al
 3b9:	00 00                	add    BYTE PTR [rax],al
 3bb:	00 00                	add    BYTE PTR [rax],al
 3bd:	00 00                	add    BYTE PTR [rax],al
 3bf:	00 d1                	add    cl,dl
 3c1:	65 ce                	gs (bad)
 3c3:	6d                   	ins    DWORD PTR es:[rdi],dx

Disassembly of section .dynsym:

00000000000003c8 <.dynsym>:
	...
 3e0:	06                   	(bad)
 3e1:	00 00                	add    BYTE PTR [rax],al
 3e3:	00 12                	add    BYTE PTR [rdx],dl
	...
 3f5:	00 00                	add    BYTE PTR [rax],al
 3f7:	00 48 00             	add    BYTE PTR [rax+0x0],cl
 3fa:	00 00                	add    BYTE PTR [rax],al
 3fc:	20 00                	and    BYTE PTR [rax],al
	...
 40e:	00 00                	add    BYTE PTR [rax],al
 410:	01 00                	add    DWORD PTR [rax],eax
 412:	00 00                	add    BYTE PTR [rax],al
 414:	12 00                	adc    al,BYTE PTR [rax]
	...
 426:	00 00                	add    BYTE PTR [rax],al
 428:	64 00 00             	add    BYTE PTR fs:[rax],al
 42b:	00 20                	add    BYTE PTR [rax],ah
	...
 43d:	00 00                	add    BYTE PTR [rax],al
 43f:	00 73 00             	add    BYTE PTR [rbx+0x0],dh
 442:	00 00                	add    BYTE PTR [rax],al
 444:	20 00                	and    BYTE PTR [rax],al
	...
 456:	00 00                	add    BYTE PTR [rax],al
 458:	18 00                	sbb    BYTE PTR [rax],al
 45a:	00 00                	add    BYTE PTR [rax],al
 45c:	22 00                	and    al,BYTE PTR [rax]
	...

Disassembly of section .dynstr:

0000000000000470 <.dynstr>:
 470:	00 70 75             	add    BYTE PTR [rax+0x75],dh
 473:	74 73                	je     4e8 <__abi_tag+0x16c>
 475:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 478:	6c                   	ins    BYTE PTR es:[rdi],dx
 479:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
 480:	72 74                	jb     4f6 <__abi_tag+0x17a>
 482:	5f                   	pop    rdi
 483:	6d                   	ins    DWORD PTR es:[rdi],dx
 484:	61                   	(bad)
 485:	69 6e 00 5f 5f 63 78 	imul   ebp,DWORD PTR [rsi+0x0],0x78635f5f
 48c:	61                   	(bad)
 48d:	5f                   	pop    rdi
 48e:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 494:	7a 65                	jp     4fb <__abi_tag+0x17f>
 496:	00 6c 69 62          	add    BYTE PTR [rcx+rbp*2+0x62],ch
 49a:	63 2e                	movsxd ebp,DWORD PTR [rsi]
 49c:	73 6f                	jae    50d <__abi_tag+0x191>
 49e:	2e 36 00 47 4c       	cs ss add BYTE PTR [rdi+0x4c],al
 4a3:	49                   	rex.WB
 4a4:	42                   	rex.X
 4a5:	43 5f                	rex.XB pop r15
 4a7:	32 2e                	xor    ch,BYTE PTR [rsi]
 4a9:	32 2e                	xor    ch,BYTE PTR [rsi]
 4ab:	35 00 47 4c 49       	xor    eax,0x494c4700
 4b0:	42                   	rex.X
 4b1:	43 5f                	rex.XB pop r15
 4b3:	32 2e                	xor    ch,BYTE PTR [rsi]
 4b5:	33 34 00             	xor    esi,DWORD PTR [rax+rax*1]
 4b8:	5f                   	pop    rdi
 4b9:	49 54                	rex.WB push r12
 4bb:	4d 5f                	rex.WRB pop r15
 4bd:	64 65 72 65          	fs gs jb 526 <__abi_tag+0x1aa>
 4c1:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 4c8:	4d 
 4c9:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 4cb:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 4cc:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 4cd:	65 54                	gs push rsp
 4cf:	61                   	(bad)
 4d0:	62                   	(bad)
 4d1:	6c                   	ins    BYTE PTR es:[rdi],dx
 4d2:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 4d6:	67 6d                	ins    DWORD PTR es:[edi],dx
 4d8:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 4d9:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 4da:	5f                   	pop    rdi
 4db:	73 74                	jae    551 <__abi_tag+0x1d5>
 4dd:	61                   	(bad)
 4de:	72 74                	jb     554 <__abi_tag+0x1d8>
 4e0:	5f                   	pop    rdi
 4e1:	5f                   	pop    rdi
 4e2:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 4e5:	54                   	push   rsp
 4e6:	4d 5f                	rex.WRB pop r15
 4e8:	72 65                	jb     54f <__abi_tag+0x1d3>
 4ea:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 4f1:	4d 
 4f2:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 4f4:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 4f5:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 4f6:	65 54                	gs push rsp
 4f8:	61                   	(bad)
 4f9:	62                   	.byte 0x62
 4fa:	6c                   	ins    BYTE PTR es:[rdi],dx
 4fb:	65                   	gs
	...

Disassembly of section .gnu.version:

00000000000004fe <.gnu.version>:
 4fe:	00 00                	add    BYTE PTR [rax],al
 500:	02 00                	add    al,BYTE PTR [rax]
 502:	01 00                	add    DWORD PTR [rax],eax
 504:	03 00                	add    eax,DWORD PTR [rax]
 506:	01 00                	add    DWORD PTR [rax],eax
 508:	01 00                	add    DWORD PTR [rax],eax
 50a:	03 00                	add    eax,DWORD PTR [rax]

Disassembly of section .gnu.version_r:

0000000000000510 <.gnu.version_r>:
 510:	01 00                	add    DWORD PTR [rax],eax
 512:	02 00                	add    al,BYTE PTR [rax]
 514:	27                   	(bad)
 515:	00 00                	add    BYTE PTR [rax],al
 517:	00 10                	add    BYTE PTR [rax],dl
 519:	00 00                	add    BYTE PTR [rax],al
 51b:	00 00                	add    BYTE PTR [rax],al
 51d:	00 00                	add    BYTE PTR [rax],al
 51f:	00 75 1a             	add    BYTE PTR [rbp+0x1a],dh
 522:	69 09 00 00 03 00    	imul   ecx,DWORD PTR [rcx],0x30000
 528:	31 00                	xor    DWORD PTR [rax],eax
 52a:	00 00                	add    BYTE PTR [rax],al
 52c:	10 00                	adc    BYTE PTR [rax],al
 52e:	00 00                	add    BYTE PTR [rax],al
 530:	b4 91                	mov    ah,0x91
 532:	96                   	xchg   esi,eax
 533:	06                   	(bad)
 534:	00 00                	add    BYTE PTR [rax],al
 536:	02 00                	add    al,BYTE PTR [rax]
 538:	3d 00 00 00 00       	cmp    eax,0x0
 53d:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

0000000000000540 <.rela.dyn>:
 540:	d0 3d 00 00 00 00    	sar    BYTE PTR [rip+0x0],1        # 546 <__abi_tag+0x1ca>
 546:	00 00                	add    BYTE PTR [rax],al
 548:	08 00                	or     BYTE PTR [rax],al
 54a:	00 00                	add    BYTE PTR [rax],al
 54c:	00 00                	add    BYTE PTR [rax],al
 54e:	00 00                	add    BYTE PTR [rax],al
 550:	30 11                	xor    BYTE PTR [rcx],dl
 552:	00 00                	add    BYTE PTR [rax],al
 554:	00 00                	add    BYTE PTR [rax],al
 556:	00 00                	add    BYTE PTR [rax],al
 558:	d8 3d 00 00 00 00    	fdivr  DWORD PTR [rip+0x0]        # 55e <__abi_tag+0x1e2>
 55e:	00 00                	add    BYTE PTR [rax],al
 560:	08 00                	or     BYTE PTR [rax],al
 562:	00 00                	add    BYTE PTR [rax],al
 564:	00 00                	add    BYTE PTR [rax],al
 566:	00 00                	add    BYTE PTR [rax],al
 568:	f0 10 00             	lock adc BYTE PTR [rax],al
 56b:	00 00                	add    BYTE PTR [rax],al
 56d:	00 00                	add    BYTE PTR [rax],al
 56f:	00 10                	add    BYTE PTR [rax],dl
 571:	40 00 00             	rex add BYTE PTR [rax],al
 574:	00 00                	add    BYTE PTR [rax],al
 576:	00 00                	add    BYTE PTR [rax],al
 578:	08 00                	or     BYTE PTR [rax],al
 57a:	00 00                	add    BYTE PTR [rax],al
 57c:	00 00                	add    BYTE PTR [rax],al
 57e:	00 00                	add    BYTE PTR [rax],al
 580:	10 40 00             	adc    BYTE PTR [rax+0x0],al
 583:	00 00                	add    BYTE PTR [rax],al
 585:	00 00                	add    BYTE PTR [rax],al
 587:	00 c0                	add    al,al
 589:	3f                   	(bad)
 58a:	00 00                	add    BYTE PTR [rax],al
 58c:	00 00                	add    BYTE PTR [rax],al
 58e:	00 00                	add    BYTE PTR [rax],al
 590:	06                   	(bad)
 591:	00 00                	add    BYTE PTR [rax],al
 593:	00 01                	add    BYTE PTR [rcx],al
	...
 59d:	00 00                	add    BYTE PTR [rax],al
 59f:	00 c8                	add    al,cl
 5a1:	3f                   	(bad)
 5a2:	00 00                	add    BYTE PTR [rax],al
 5a4:	00 00                	add    BYTE PTR [rax],al
 5a6:	00 00                	add    BYTE PTR [rax],al
 5a8:	06                   	(bad)
 5a9:	00 00                	add    BYTE PTR [rax],al
 5ab:	00 02                	add    BYTE PTR [rdx],al
	...
 5b5:	00 00                	add    BYTE PTR [rax],al
 5b7:	00 d0                	add    al,dl
 5b9:	3f                   	(bad)
 5ba:	00 00                	add    BYTE PTR [rax],al
 5bc:	00 00                	add    BYTE PTR [rax],al
 5be:	00 00                	add    BYTE PTR [rax],al
 5c0:	06                   	(bad)
 5c1:	00 00                	add    BYTE PTR [rax],al
 5c3:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 5ce:	00 00                	add    BYTE PTR [rax],al
 5d0:	d8 3f                	fdivr  DWORD PTR [rdi]
 5d2:	00 00                	add    BYTE PTR [rax],al
 5d4:	00 00                	add    BYTE PTR [rax],al
 5d6:	00 00                	add    BYTE PTR [rax],al
 5d8:	06                   	(bad)
 5d9:	00 00                	add    BYTE PTR [rax],al
 5db:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 5e1 <__abi_tag+0x265>
 5e1:	00 00                	add    BYTE PTR [rax],al
 5e3:	00 00                	add    BYTE PTR [rax],al
 5e5:	00 00                	add    BYTE PTR [rax],al
 5e7:	00 e0                	add    al,ah
 5e9:	3f                   	(bad)
 5ea:	00 00                	add    BYTE PTR [rax],al
 5ec:	00 00                	add    BYTE PTR [rax],al
 5ee:	00 00                	add    BYTE PTR [rax],al
 5f0:	06                   	(bad)
 5f1:	00 00                	add    BYTE PTR [rax],al
 5f3:	00 06                	add    BYTE PTR [rsi],al
	...

Disassembly of section .rela.plt:

0000000000000600 <.rela.plt>:
 600:	00 40 00             	add    BYTE PTR [rax+0x0],al
 603:	00 00                	add    BYTE PTR [rax],al
 605:	00 00                	add    BYTE PTR [rax],al
 607:	00 07                	add    BYTE PTR [rdi],al
 609:	00 00                	add    BYTE PTR [rax],al
 60b:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .init:

0000000000001000 <_init>:
    1000:	48 83 ec 08          	sub    rsp,0x8
    1004:	48 8b 05 c5 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fc5]        # 3fd0 <__gmon_start__@Base>
    100b:	48 85 c0             	test   rax,rax
    100e:	74 02                	je     1012 <_init+0x12>
    1010:	ff d0                	call   rax
    1012:	48 83 c4 08          	add    rsp,0x8
    1016:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <puts@plt-0x10>:
    1020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001030 <puts@plt>:
    1030:	ff 25 ca 2f 00 00    	jmp    QWORD PTR [rip+0x2fca]        # 4000 <puts@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	ff 25 9a 2f 00 00    	jmp    QWORD PTR [rip+0x2f9a]        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1046:	66 90                	xchg   ax,ax

Disassembly of section .text:

0000000000001050 <_start>:
    1050:	31 ed                	xor    ebp,ebp
    1052:	49 89 d1             	mov    r9,rdx
    1055:	5e                   	pop    rsi
    1056:	48 89 e2             	mov    rdx,rsp
    1059:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    105d:	50                   	push   rax
    105e:	54                   	push   rsp
    105f:	45 31 c0             	xor    r8d,r8d
    1062:	31 c9                	xor    ecx,ecx
    1064:	48 8d 3d ce 00 00 00 	lea    rdi,[rip+0xce]        # 1139 <main>
    106b:	ff 15 4f 2f 00 00    	call   QWORD PTR [rip+0x2f4f]        # 3fc0 <__libc_start_main@GLIBC_2.34>
    1071:	f4                   	hlt
    1072:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    1079:	00 00 00 
    107c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001080 <deregister_tm_clones>:
    1080:	48 8d 3d 91 2f 00 00 	lea    rdi,[rip+0x2f91]        # 4018 <__TMC_END__>
    1087:	48 8d 05 8a 2f 00 00 	lea    rax,[rip+0x2f8a]        # 4018 <__TMC_END__>
    108e:	48 39 f8             	cmp    rax,rdi
    1091:	74 15                	je     10a8 <deregister_tm_clones+0x28>
    1093:	48 8b 05 2e 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f2e]        # 3fc8 <_ITM_deregisterTMCloneTable@Base>
    109a:	48 85 c0             	test   rax,rax
    109d:	74 09                	je     10a8 <deregister_tm_clones+0x28>
    109f:	ff e0                	jmp    rax
    10a1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10a8:	c3                   	ret
    10a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000010b0 <register_tm_clones>:
    10b0:	48 8d 3d 61 2f 00 00 	lea    rdi,[rip+0x2f61]        # 4018 <__TMC_END__>
    10b7:	48 8d 35 5a 2f 00 00 	lea    rsi,[rip+0x2f5a]        # 4018 <__TMC_END__>
    10be:	48 29 fe             	sub    rsi,rdi
    10c1:	48 89 f0             	mov    rax,rsi
    10c4:	48 c1 ee 3f          	shr    rsi,0x3f
    10c8:	48 c1 f8 03          	sar    rax,0x3
    10cc:	48 01 c6             	add    rsi,rax
    10cf:	48 d1 fe             	sar    rsi,1
    10d2:	74 14                	je     10e8 <register_tm_clones+0x38>
    10d4:	48 8b 05 fd 2e 00 00 	mov    rax,QWORD PTR [rip+0x2efd]        # 3fd8 <_ITM_registerTMCloneTable@Base>
    10db:	48 85 c0             	test   rax,rax
    10de:	74 08                	je     10e8 <register_tm_clones+0x38>
    10e0:	ff e0                	jmp    rax
    10e2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    10e8:	c3                   	ret
    10e9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000010f0 <__do_global_dtors_aux>:
    10f0:	f3 0f 1e fa          	endbr64
    10f4:	80 3d 1d 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f1d],0x0        # 4018 <__TMC_END__>
    10fb:	75 2b                	jne    1128 <__do_global_dtors_aux+0x38>
    10fd:	55                   	push   rbp
    10fe:	48 83 3d da 2e 00 00 	cmp    QWORD PTR [rip+0x2eda],0x0        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1105:	00 
    1106:	48 89 e5             	mov    rbp,rsp
    1109:	74 0c                	je     1117 <__do_global_dtors_aux+0x27>
    110b:	48 8b 3d fe 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2efe]        # 4010 <__dso_handle>
    1112:	e8 29 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1117:	e8 64 ff ff ff       	call   1080 <deregister_tm_clones>
    111c:	c6 05 f5 2e 00 00 01 	mov    BYTE PTR [rip+0x2ef5],0x1        # 4018 <__TMC_END__>
    1123:	5d                   	pop    rbp
    1124:	c3                   	ret
    1125:	0f 1f 00             	nop    DWORD PTR [rax]
    1128:	c3                   	ret
    1129:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001130 <frame_dummy>:
    1130:	f3 0f 1e fa          	endbr64
    1134:	e9 77 ff ff ff       	jmp    10b0 <register_tm_clones>

0000000000001139 <main>:
    1139:	55                   	push   rbp
    113a:	48 89 e5             	mov    rbp,rsp
    113d:	48 8d 05 c0 0e 00 00 	lea    rax,[rip+0xec0]        # 2004 <_IO_stdin_used+0x4>
    1144:	48 89 c7             	mov    rdi,rax
    1147:	e8 e4 fe ff ff       	call   1030 <puts@plt>
    114c:	b8 00 00 00 00       	mov    eax,0x0
    1151:	5d                   	pop    rbp
    1152:	c3                   	ret

Disassembly of section .fini:

0000000000001154 <_fini>:
    1154:	48 83 ec 08          	sub    rsp,0x8
    1158:	48 83 c4 08          	add    rsp,0x8
    115c:	c3                   	ret

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    DWORD PTR [rax],eax
    2002:	02 00                	add    al,BYTE PTR [rax]
    2004:	4c 69 62 61 72 79 20 	imul   r12,QWORD PTR [rdx+0x61],0x49207972
    200b:	49 
    200c:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    200d:	6a 65                	push   0x65
    200f:	63 74 69 6f          	movsxd esi,DWORD PTR [rcx+rbp*2+0x6f]
    2013:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    2014:	20 66 61             	and    BYTE PTR [rsi+0x61],ah
    2017:	69                   	.byte 0x69
    2018:	6c                   	ins    BYTE PTR es:[rdi],dx
    2019:	65                   	gs
    201a:	64                   	fs
    201b:	2e                   	cs
	...

Disassembly of section .eh_frame_hdr:

0000000000002020 <__GNU_EH_FRAME_HDR>:
    2020:	01 1b                	add    DWORD PTR [rbx],ebx
    2022:	03 3b                	add    edi,DWORD PTR [rbx]
    2024:	2c 00                	sub    al,0x0
    2026:	00 00                	add    BYTE PTR [rax],al
    2028:	04 00                	add    al,0x0
    202a:	00 00                	add    BYTE PTR [rax],al
    202c:	00 f0                	add    al,dh
    202e:	ff                   	(bad)
    202f:	ff                   	(bad)
    2030:	78 00                	js     2032 <__GNU_EH_FRAME_HDR+0x12>
    2032:	00 00                	add    BYTE PTR [rax],al
    2034:	20 f0                	and    al,dh
    2036:	ff                   	(bad)
    2037:	ff a0 00 00 00 30    	jmp    QWORD PTR [rax+0x30000000]
    203d:	f0 ff                	lock (bad)
    203f:	ff 48 00             	dec    DWORD PTR [rax+0x0]
    2042:	00 00                	add    BYTE PTR [rax],al
    2044:	19 f1                	sbb    ecx,esi
    2046:	ff                   	(bad)
    2047:	ff                   	(bad)
    2048:	b8                   	.byte 0xb8
    2049:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .eh_frame:

0000000000002050 <__FRAME_END__-0xa8>:
    2050:	14 00                	adc    al,0x0
    2052:	00 00                	add    BYTE PTR [rax],al
    2054:	00 00                	add    BYTE PTR [rax],al
    2056:	00 00                	add    BYTE PTR [rax],al
    2058:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
    205b:	00 01                	add    BYTE PTR [rcx],al
    205d:	78 10                	js     206f <__GNU_EH_FRAME_HDR+0x4f>
    205f:	01 1b                	add    DWORD PTR [rbx],ebx
    2061:	0c 07                	or     al,0x7
    2063:	08 90 01 07 10 14    	or     BYTE PTR [rax+0x14100701],dl
    2069:	00 00                	add    BYTE PTR [rax],al
    206b:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    206e:	00 00                	add    BYTE PTR [rax],al
    2070:	e0 ef                	loopne 2061 <__GNU_EH_FRAME_HDR+0x41>
    2072:	ff                   	(bad)
    2073:	ff 22                	jmp    QWORD PTR [rdx]
	...
    207d:	00 00                	add    BYTE PTR [rax],al
    207f:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    2082:	00 00                	add    BYTE PTR [rax],al
    2084:	00 00                	add    BYTE PTR [rax],al
    2086:	00 00                	add    BYTE PTR [rax],al
    2088:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
    208b:	00 01                	add    BYTE PTR [rcx],al
    208d:	78 10                	js     209f <__GNU_EH_FRAME_HDR+0x7f>
    208f:	01 1b                	add    DWORD PTR [rbx],ebx
    2091:	0c 07                	or     al,0x7
    2093:	08 90 01 00 00 24    	or     BYTE PTR [rax+0x24000001],dl
    2099:	00 00                	add    BYTE PTR [rax],al
    209b:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    209e:	00 00                	add    BYTE PTR [rax],al
    20a0:	80 ef ff             	sub    bh,0xff
    20a3:	ff 20                	jmp    QWORD PTR [rax]
    20a5:	00 00                	add    BYTE PTR [rax],al
    20a7:	00 00                	add    BYTE PTR [rax],al
    20a9:	0e                   	(bad)
    20aa:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
    20ad:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
    20b0:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
    20b3:	80 00 3f             	add    BYTE PTR [rax],0x3f
    20b6:	1a 3b                	sbb    bh,BYTE PTR [rbx]
    20b8:	2a 33                	sub    dh,BYTE PTR [rbx]
    20ba:	24 22                	and    al,0x22
    20bc:	00 00                	add    BYTE PTR [rax],al
    20be:	00 00                	add    BYTE PTR [rax],al
    20c0:	14 00                	adc    al,0x0
    20c2:	00 00                	add    BYTE PTR [rax],al
    20c4:	44 00 00             	add    BYTE PTR [rax],r8b
    20c7:	00 78 ef             	add    BYTE PTR [rax-0x11],bh
    20ca:	ff                   	(bad)
    20cb:	ff 08                	dec    DWORD PTR [rax]
	...
    20d5:	00 00                	add    BYTE PTR [rax],al
    20d7:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    20da:	00 00                	add    BYTE PTR [rax],al
    20dc:	5c                   	pop    rsp
    20dd:	00 00                	add    BYTE PTR [rax],al
    20df:	00 59 f0             	add    BYTE PTR [rcx-0x10],bl
    20e2:	ff                   	(bad)
    20e3:	ff 1a                	call   FWORD PTR [rdx]
    20e5:	00 00                	add    BYTE PTR [rax],al
    20e7:	00 00                	add    BYTE PTR [rax],al
    20e9:	41 0e                	rex.B (bad)
    20eb:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    20f1:	55                   	push   rbp
    20f2:	0c 07                	or     al,0x7
    20f4:	08 00                	or     BYTE PTR [rax],al
	...

00000000000020f8 <__FRAME_END__>:
    20f8:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000003dd0 <__frame_dummy_init_array_entry>:
    3dd0:	30 11                	xor    BYTE PTR [rcx],dl
    3dd2:	00 00                	add    BYTE PTR [rax],al
    3dd4:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000003dd8 <__do_global_dtors_aux_fini_array_entry>:
    3dd8:	f0 10 00             	lock adc BYTE PTR [rax],al
    3ddb:	00 00                	add    BYTE PTR [rax],al
    3ddd:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000003de0 <_DYNAMIC>:
    3de0:	01 00                	add    DWORD PTR [rax],eax
    3de2:	00 00                	add    BYTE PTR [rax],al
    3de4:	00 00                	add    BYTE PTR [rax],al
    3de6:	00 00                	add    BYTE PTR [rax],al
    3de8:	27                   	(bad)
    3de9:	00 00                	add    BYTE PTR [rax],al
    3deb:	00 00                	add    BYTE PTR [rax],al
    3ded:	00 00                	add    BYTE PTR [rax],al
    3def:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
    3df2:	00 00                	add    BYTE PTR [rax],al
    3df4:	00 00                	add    BYTE PTR [rax],al
    3df6:	00 00                	add    BYTE PTR [rax],al
    3df8:	00 10                	add    BYTE PTR [rax],dl
    3dfa:	00 00                	add    BYTE PTR [rax],al
    3dfc:	00 00                	add    BYTE PTR [rax],al
    3dfe:	00 00                	add    BYTE PTR [rax],al
    3e00:	0d 00 00 00 00       	or     eax,0x0
    3e05:	00 00                	add    BYTE PTR [rax],al
    3e07:	00 54 11 00          	add    BYTE PTR [rcx+rdx*1+0x0],dl
    3e0b:	00 00                	add    BYTE PTR [rax],al
    3e0d:	00 00                	add    BYTE PTR [rax],al
    3e0f:	00 19                	add    BYTE PTR [rcx],bl
    3e11:	00 00                	add    BYTE PTR [rax],al
    3e13:	00 00                	add    BYTE PTR [rax],al
    3e15:	00 00                	add    BYTE PTR [rax],al
    3e17:	00 d0                	add    al,dl
    3e19:	3d 00 00 00 00       	cmp    eax,0x0
    3e1e:	00 00                	add    BYTE PTR [rax],al
    3e20:	1b 00                	sbb    eax,DWORD PTR [rax]
    3e22:	00 00                	add    BYTE PTR [rax],al
    3e24:	00 00                	add    BYTE PTR [rax],al
    3e26:	00 00                	add    BYTE PTR [rax],al
    3e28:	08 00                	or     BYTE PTR [rax],al
    3e2a:	00 00                	add    BYTE PTR [rax],al
    3e2c:	00 00                	add    BYTE PTR [rax],al
    3e2e:	00 00                	add    BYTE PTR [rax],al
    3e30:	1a 00                	sbb    al,BYTE PTR [rax]
    3e32:	00 00                	add    BYTE PTR [rax],al
    3e34:	00 00                	add    BYTE PTR [rax],al
    3e36:	00 00                	add    BYTE PTR [rax],al
    3e38:	d8 3d 00 00 00 00    	fdivr  DWORD PTR [rip+0x0]        # 3e3e <_DYNAMIC+0x5e>
    3e3e:	00 00                	add    BYTE PTR [rax],al
    3e40:	1c 00                	sbb    al,0x0
    3e42:	00 00                	add    BYTE PTR [rax],al
    3e44:	00 00                	add    BYTE PTR [rax],al
    3e46:	00 00                	add    BYTE PTR [rax],al
    3e48:	08 00                	or     BYTE PTR [rax],al
    3e4a:	00 00                	add    BYTE PTR [rax],al
    3e4c:	00 00                	add    BYTE PTR [rax],al
    3e4e:	00 00                	add    BYTE PTR [rax],al
    3e50:	f5                   	cmc
    3e51:	fe                   	(bad)
    3e52:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3e55:	00 00                	add    BYTE PTR [rax],al
    3e57:	00 a0 03 00 00 00    	add    BYTE PTR [rax+0x3],ah
    3e5d:	00 00                	add    BYTE PTR [rax],al
    3e5f:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 3e65 <_DYNAMIC+0x85>
    3e65:	00 00                	add    BYTE PTR [rax],al
    3e67:	00 70 04             	add    BYTE PTR [rax+0x4],dh
    3e6a:	00 00                	add    BYTE PTR [rax],al
    3e6c:	00 00                	add    BYTE PTR [rax],al
    3e6e:	00 00                	add    BYTE PTR [rax],al
    3e70:	06                   	(bad)
    3e71:	00 00                	add    BYTE PTR [rax],al
    3e73:	00 00                	add    BYTE PTR [rax],al
    3e75:	00 00                	add    BYTE PTR [rax],al
    3e77:	00 c8                	add    al,cl
    3e79:	03 00                	add    eax,DWORD PTR [rax]
    3e7b:	00 00                	add    BYTE PTR [rax],al
    3e7d:	00 00                	add    BYTE PTR [rax],al
    3e7f:	00 0a                	add    BYTE PTR [rdx],cl
    3e81:	00 00                	add    BYTE PTR [rax],al
    3e83:	00 00                	add    BYTE PTR [rax],al
    3e85:	00 00                	add    BYTE PTR [rax],al
    3e87:	00 8d 00 00 00 00    	add    BYTE PTR [rbp+0x0],cl
    3e8d:	00 00                	add    BYTE PTR [rax],al
    3e8f:	00 0b                	add    BYTE PTR [rbx],cl
    3e91:	00 00                	add    BYTE PTR [rax],al
    3e93:	00 00                	add    BYTE PTR [rax],al
    3e95:	00 00                	add    BYTE PTR [rax],al
    3e97:	00 18                	add    BYTE PTR [rax],bl
    3e99:	00 00                	add    BYTE PTR [rax],al
    3e9b:	00 00                	add    BYTE PTR [rax],al
    3e9d:	00 00                	add    BYTE PTR [rax],al
    3e9f:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 3ea5 <_DYNAMIC+0xc5>
	...
    3ead:	00 00                	add    BYTE PTR [rax],al
    3eaf:	00 03                	add    BYTE PTR [rbx],al
    3eb1:	00 00                	add    BYTE PTR [rax],al
    3eb3:	00 00                	add    BYTE PTR [rax],al
    3eb5:	00 00                	add    BYTE PTR [rax],al
    3eb7:	00 e8                	add    al,ch
    3eb9:	3f                   	(bad)
    3eba:	00 00                	add    BYTE PTR [rax],al
    3ebc:	00 00                	add    BYTE PTR [rax],al
    3ebe:	00 00                	add    BYTE PTR [rax],al
    3ec0:	02 00                	add    al,BYTE PTR [rax]
    3ec2:	00 00                	add    BYTE PTR [rax],al
    3ec4:	00 00                	add    BYTE PTR [rax],al
    3ec6:	00 00                	add    BYTE PTR [rax],al
    3ec8:	18 00                	sbb    BYTE PTR [rax],al
    3eca:	00 00                	add    BYTE PTR [rax],al
    3ecc:	00 00                	add    BYTE PTR [rax],al
    3ece:	00 00                	add    BYTE PTR [rax],al
    3ed0:	14 00                	adc    al,0x0
    3ed2:	00 00                	add    BYTE PTR [rax],al
    3ed4:	00 00                	add    BYTE PTR [rax],al
    3ed6:	00 00                	add    BYTE PTR [rax],al
    3ed8:	07                   	(bad)
    3ed9:	00 00                	add    BYTE PTR [rax],al
    3edb:	00 00                	add    BYTE PTR [rax],al
    3edd:	00 00                	add    BYTE PTR [rax],al
    3edf:	00 17                	add    BYTE PTR [rdi],dl
	...
    3ee9:	06                   	(bad)
    3eea:	00 00                	add    BYTE PTR [rax],al
    3eec:	00 00                	add    BYTE PTR [rax],al
    3eee:	00 00                	add    BYTE PTR [rax],al
    3ef0:	07                   	(bad)
    3ef1:	00 00                	add    BYTE PTR [rax],al
    3ef3:	00 00                	add    BYTE PTR [rax],al
    3ef5:	00 00                	add    BYTE PTR [rax],al
    3ef7:	00 40 05             	add    BYTE PTR [rax+0x5],al
    3efa:	00 00                	add    BYTE PTR [rax],al
    3efc:	00 00                	add    BYTE PTR [rax],al
    3efe:	00 00                	add    BYTE PTR [rax],al
    3f00:	08 00                	or     BYTE PTR [rax],al
    3f02:	00 00                	add    BYTE PTR [rax],al
    3f04:	00 00                	add    BYTE PTR [rax],al
    3f06:	00 00                	add    BYTE PTR [rax],al
    3f08:	c0 00 00             	rol    BYTE PTR [rax],0x0
    3f0b:	00 00                	add    BYTE PTR [rax],al
    3f0d:	00 00                	add    BYTE PTR [rax],al
    3f0f:	00 09                	add    BYTE PTR [rcx],cl
    3f11:	00 00                	add    BYTE PTR [rax],al
    3f13:	00 00                	add    BYTE PTR [rax],al
    3f15:	00 00                	add    BYTE PTR [rax],al
    3f17:	00 18                	add    BYTE PTR [rax],bl
    3f19:	00 00                	add    BYTE PTR [rax],al
    3f1b:	00 00                	add    BYTE PTR [rax],al
    3f1d:	00 00                	add    BYTE PTR [rax],al
    3f1f:	00 fb                	add    bl,bh
    3f21:	ff                   	(bad)
    3f22:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f25:	00 00                	add    BYTE PTR [rax],al
    3f27:	00 00                	add    BYTE PTR [rax],al
    3f29:	00 00                	add    BYTE PTR [rax],al
    3f2b:	08 00                	or     BYTE PTR [rax],al
    3f2d:	00 00                	add    BYTE PTR [rax],al
    3f2f:	00 fe                	add    dh,bh
    3f31:	ff                   	(bad)
    3f32:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f35:	00 00                	add    BYTE PTR [rax],al
    3f37:	00 10                	add    BYTE PTR [rax],dl
    3f39:	05 00 00 00 00       	add    eax,0x0
    3f3e:	00 00                	add    BYTE PTR [rax],al
    3f40:	ff                   	(bad)
    3f41:	ff                   	(bad)
    3f42:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f45:	00 00                	add    BYTE PTR [rax],al
    3f47:	00 01                	add    BYTE PTR [rcx],al
    3f49:	00 00                	add    BYTE PTR [rax],al
    3f4b:	00 00                	add    BYTE PTR [rax],al
    3f4d:	00 00                	add    BYTE PTR [rax],al
    3f4f:	00 f0                	add    al,dh
    3f51:	ff                   	(bad)
    3f52:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f55:	00 00                	add    BYTE PTR [rax],al
    3f57:	00 fe                	add    dh,bh
    3f59:	04 00                	add    al,0x0
    3f5b:	00 00                	add    BYTE PTR [rax],al
    3f5d:	00 00                	add    BYTE PTR [rax],al
    3f5f:	00 f9                	add    cl,bh
    3f61:	ff                   	(bad)
    3f62:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f65:	00 00                	add    BYTE PTR [rax],al
    3f67:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000003fc0 <.got>:
	...

Disassembly of section .got.plt:

0000000000003fe8 <_GLOBAL_OFFSET_TABLE_>:
    3fe8:	e0 3d                	loopne 4027 <_end+0x7>
	...
    3ffe:	00 00                	add    BYTE PTR [rax],al
    4000:	36 10 00             	ss adc BYTE PTR [rax],al
    4003:	00 00                	add    BYTE PTR [rax],al
    4005:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .data:

0000000000004008 <__data_start>:
	...

0000000000004010 <__dso_handle>:
    4010:	10 40 00             	adc    BYTE PTR [rax+0x0],al
    4013:	00 00                	add    BYTE PTR [rax],al
    4015:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .bss:

0000000000004018 <completed.0>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 44 65 62          	sub    BYTE PTR [rbp+riz*2+0x62],al
   9:	69 61 6e 20 31 32 2e 	imul   esp,DWORD PTR [rcx+0x6e],0x2e323120
  10:	32 2e                	xor    ch,BYTE PTR [rsi]
  12:	30 2d 31 34 29 20    	xor    BYTE PTR [rip+0x20293431],ch        # 20293449 <_end+0x2028f429>
  18:	31 32                	xor    DWORD PTR [rdx],esi
  1a:	2e 32 2e             	cs xor ch,BYTE PTR [rsi]
  1d:	30 00                	xor    BYTE PTR [rax],al
