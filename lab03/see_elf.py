print('/*')
from pwn import *
import sys
elf = ELF(sys.argv[1])
print('*/')
main_ptr = elf.symbols['main']
count = 0
print('int elf_moves[] = {', end='')
for s in [ f"move_{i + 1}" for i in range(0, 1200)]:
   count+=1
   print(elf.got[s] - main_ptr, end=', ')
print('};')

print(f'int elf_maze_load = {elf.got["maze_load"] - main_ptr};')