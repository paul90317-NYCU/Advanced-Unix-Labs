def to_hex(x):
    tb = [chr(i) for i in range(ord('0'), ord('9') + 1)] + [chr(i) for i in range(ord('a'), ord('f') + 1)]
    return tb[x // 16] + tb[x % 16]

def fill(s :list):
    s.append('00')
    while(len(s) % 8):
        s.append('00')

import sys
s = sys.argv[1]
l = len(s)
s = [to_hex(ord(c)) for c in s]
fill(s)
s.reverse()
s = ''.join(s)
for i in range(0, len(s), 16):
    print('mov rax, 0x' + s[i: i + 16])
    print('push rax')

print('rsp', l)