#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import sys
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(time.time(), "solving pow ...");
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    print(time.time(), "done.");
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

if __name__ == "__main__":
    r = None
    if len(sys.argv) == 2:
        r = remote('localhost', int(sys.argv[1]))
    elif len(sys.argv) == 3:
        r = remote(sys.argv[1], int(sys.argv[2]))
    else:
        r = process('./pow.py')
    solve_pow(r);
    r.interactive();
    r.close();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :