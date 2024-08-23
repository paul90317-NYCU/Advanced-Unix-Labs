#!/usr/bin/env python3

import base64
import hashlib
from pwn import *

if __name__ == '__main__':
    r = remote('ipinfo.io', 80)
    r.send(b'GET /ip HTTP/1.1\r\n')
    r.send(b'Host: ipinfo.io\r\n')
    r.send(b'User-Agent: curl/7.88.1\r\n')
    r.send(b'Accept: */*\r\n\r\n')
    r.recvuntil(b'Connection: close\r\n\r\n')
    print(r.recv().decode())
    r.close()
