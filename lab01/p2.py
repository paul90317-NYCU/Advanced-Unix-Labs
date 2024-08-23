#!/usr/bin/env python3

import base64
import hashlib
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

mapper = {}
def get_it(problem):
    leng = (len(problem) - 4) // 35
    datas = []
    for i in range(leng):
        temp = ''
        for row in range(5):
            temp += problem[row * (leng * 7 + 1) + 7 * i: row * (leng * 7 + 1) + 7 * (i + 1)]+'\n'

        datas.append(mapper[temp.replace('\n','').replace('\r','').replace(' ','')])
    return datas

def getres(i):
    with open('res.txt','r') as f:
        temp = f.readlines()
        t = ''.join(temp[5*i:5*(i+1)]).replace('\n','').replace('\r','').replace(' ','')
        return t

def solve_it(problem):
    problem = get_it(problem)
    problem3 = [0]
    for x in problem:
        if isinstance(x, int):
            problem3[-1] *= 10
            problem3[-1] += x
        else:
            problem3.append(x)
            problem3.append(0)

    a,op,b = problem3
    if op == '+':
        return a + b
    elif op == '-':
        return a - b
    elif op == '*':
        return a * b
    elif op == '/':
        return a // b
    else:
        print('fuck up!!!!')
        exit(0)



if __name__ == '__main__':
    for i in range(10):
        mapper[getres(i)] = i
    mapper[getres(10)] = '*'
    mapper[getres(11)] = '/'
    mapper[getres(12)] = '-'
    mapper[getres(13)] = '+'
    """
    with open('test3.txt','r') as f:
        print(solve_it(f.read()))
    exit()
    """
    
    r = remote('up.zoolab.org', 10681)
    solve_pow(r)
    r.recvuntil(b'Please complete the ')
    challenge_count = int(r.recvuntil(b' challenges in a limited time.').decode().split(' ')[0])
    for _ in range(challenge_count):
        r.recvuntil(b': ')
        problem_b64 = r.recvuntil(b' = ?').decode().split(' ')[0]
        problem = base64.b64decode(problem_b64).decode('utf-8')
        ans = f'{solve_it(problem)}\n'
        print(ans)
        r.send(ans.encode('utf-8'))
    r.interactive()
