.code

extern GetStdHandle:proc
extern WriteFile:proc
extern ExitProcess:proc

.data

    msg db "Hello World!", 13, 0

    written dd ?

.code

main proc
    sub rsp, 28h

    mov rcx, -11        ; stdout
    call GetStdHandle

    test rax, rax
    js error

    mov rcx, rax
    lea rdx, [msg]
    mov r8, 13
    lea r9, [written]
    xor rax, rax
    push rax

    call WriteFile

    add rsp, 8          ; clear stack from push rax

    test rax, rax
    jz error

    xor ecx, ecx
    call ExitProcess

error:
    mov rcx, 1
    call ExitProcess

main endp

end
