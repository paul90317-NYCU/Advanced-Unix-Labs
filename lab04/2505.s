dispbin:
    mov cx, 16
    mov ebx, 0x600000

for:
    shl ax, 1
    jc ifone
    mov dl, '0'
    jmp iter
ifone:
    mov dl, '1'
iter:
    mov [ebx], dl
    add ebx, 1
    loop for

    mov dl, 0
    mov [ebx], dl

done: