math3:
    mov eax, [0x600000]
    mov ebx, 5
    imul ebx
    mov ebx, [0x600004]
    sub ebx, 3
    mov edx, 0
    idiv ebx
    mov [0x600008], eax
done:
