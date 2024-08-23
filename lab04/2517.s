posneg:
    add eax, 0
    mov edi, 1
    jns nsa
    mov edi, -1
    nsa:
    mov [0x600000], edi

    add ebx, 0
    mov edi, 1
    jns nsb
    mov edi, -1
    nsb:
    mov [0x600004], edi
    
    add ecx, 0
    mov edi, 1
    jns nsc
    mov edi, -1
    nsc:
    mov [0x600008], edi

    add edx, 0
    mov edi, 1
    jns nsd
    mov edi, -1
    nsd:
    mov [0x60000c], edi
done: