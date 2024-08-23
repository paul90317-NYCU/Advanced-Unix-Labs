math4:
    mov eax, [0x600000]
    mov ebx, -5
    imul ebx
    mov [0x600010], eax

    mov eax, [0x600004]
    neg eax
    mov ebx, [0x600008]
    mov edx, 0
    idiv ebx
    mov ebx, edx

    mov eax, [0x600010]
    mov edx, 0
    idiv ebx
    mov eax, [0x60000c]
done:
