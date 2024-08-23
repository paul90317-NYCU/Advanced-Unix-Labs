mulbyshift:
    mov ecx, [0x600000]
    mov bl, 26
while:
    mov bh, bl
    and bh, 0x1
    jz notadd
    add rax, rcx
notadd:
    shl rcx
    shr bl
    jnz while        
    
    mov [0x600004], eax
done: