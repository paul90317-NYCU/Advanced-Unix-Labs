loop15:
    mov cx, 15
    for:
        mov ebx, 0x60000f
        sub ebx, ecx
        mov al, [ebx]

        mov ebx, 0x60001f
        sub ebx, ecx
        or al, 0x20
    iter:
        mov [ebx], al
        loop for
done:
