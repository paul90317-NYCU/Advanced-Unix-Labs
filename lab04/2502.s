bubble:
    mov ebx, 0x600000
for1:
    mov ecx, 0x600024
    for2:
        mov edx, ecx
        sub edx, 4
        mov edi, [edx]
        cmp edi, [ecx]
        jbe skip_swap
        mov eax, [edx]
        mov edi, [ecx]
        mov [edx], edi
        mov [ecx], eax
        skip_swap:
        sub ecx, 4
        cmp ebx, ecx
        jne for2

    add ebx, 4
    cmp ebx, 0x600024
    jne for1
done:

