tolower:
    mov al, [0x600000]
    and al, 0xdf
    mov [0x600001], al
done: