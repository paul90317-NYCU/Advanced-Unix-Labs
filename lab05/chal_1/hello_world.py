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

asm_code = """
    jmp msg_call
main:
    pop rsi
    mov rax, 1
    mov rdi, 1
    mov rdx, 13
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

msg_call:
    call main
msg:
    .ascii "Hello, World!"
"""

sc = asm(asm_code, arch='amd64')

r.sendafter(b"code> ", sc)
print(r.recvall())
