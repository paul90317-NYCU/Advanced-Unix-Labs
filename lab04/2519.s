swapmem:
    mov eax, [0x600000]
    mov ebx, [0x600008]
    mov [0x600000], ebx
    mov [0x600008], eax

    mov eax, [0x600004]
    mov ebx, [0x60000c]
    mov [0x600004], ebx
    mov [0x60000c], eax
done: