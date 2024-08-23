math5:
    mov eax, [0x600000]
    mov ecx, [0x600004]
    neg ecx
    imul ecx

    mov ecx, [0x600008]
    sub ecx, ebx

    mov edx, 0
    idiv ecx
    mov [0x600008], eax
done:
