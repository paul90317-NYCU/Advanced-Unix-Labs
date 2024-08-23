recur:
    mov rax, 24
    push rax
    call r
    pop rax
    jmp exit

r:
    pop rdx ; retrieve return back pointer
    pop rax ; get parameters
    push rdx ; store back return back pointer

    cmp rax, 0
    ja t1
    
    mov rax, 0
    
    pop rdx ; get return back pointer
    push rax ; set return value
    push rdx ; restore return back pointer
    ret
t1: 
    cmp rax, 1
    jne t2

    pop rdx ; get return back pointer
    push rax ; set return value
    push rdx ; restore return back pointer
    ret
t2:
    push rax ; save caller's data
    sub rax, 1 
    push rax ; set callee's parameters
    call r
    pop rbx ; get callee's return value
    pop rax ; get caller's data
    
    push rbx ; save caller's data
    sub rax, 2
    push rax ; set callee's parameters
    call r

    pop rcx ; get callee's return value
    pop rbx ; get caller's data

    mov rax, 2
    mul rbx
    mov rdi, rax

    mov rax, 3
    mul rcx
    add rax, rdi

    pop rdx ; get return back pointer
    push rax ; set return value
    push rdx ; restore return back pointer
    ret

exit:
done:
