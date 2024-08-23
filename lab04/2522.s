ullu:
    mov cl, ch
    and cl, 0x20
    jz upper
    and ch, 0xdf
    jmp skip
upper:
    or ch, 0x20
skip:
done:
