isoloatebit:
    shr ax, 5
    shl ax, 5
    shl ax, 4
    shr ax, 4
    shr ax, 5
    mov [0x600000], al
done:
