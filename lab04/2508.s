leax:
    mov ebx, edi
    mov eax, 3
    mul ebx
    mov ebx, eax

    mov ecx, edi
    mov eax, 5
    mul ecx
    mov ecx, eax

    mov edx, edi
    mov eax, 9
    mul edx
    mov [0x600000], eax

    mov eax, 2
    mul edi
    
    mov edx, [0x600000]
done: