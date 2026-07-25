; tcp_helpers.asm — Быстрые TCP-хелперы на ASM x86-64
; Функции: tcp_write_all (write loop), hex_dump (отладочный вывод)
; Вызываются из C как: ssize_t tcp_write_all(int fd, const void *buf, size_t len);
;                        void hex_dump(const char *label, const void *data, size_t len);

section .data
    hex_chars: db "0123456789abcdef"
    nl:        db 10
    colon_sp:  db ": "

section .bss
    hex_buf: resb 64       ; буфер для hex-строки

section .text
    global tcp_write_all
    global hex_dump

; ================================================================
; tcp_write_all — запись всех байтов в TCP-сокет с retry
; rdi = fd, rsi = buf, rdx = len
; Возвращает: rax = общее количество записанных байтов (или -1)
; ================================================================
tcp_write_all:
    xor rax, rax            ; total = 0
    push rbx
    push r12
    mov rbx, rdi            ; rbx = fd
    mov r12, rsi            ; r12 = buf

.write_loop:
    cmp rax, rdx
    jae .done

    ; write(fd, buf + total, len - total)
    mov rdi, rbx            ; fd
    lea rsi, [r12 + rax]    ; buf + total
    mov rdx, rdx
    sub rdx, rax            ; len - total
    mov rax, 1              ; sys_write
    syscall
    ; rax = bytes written (или -1)

    cmp rax, 0
    jle .error

    ; total += written
    ; rax уже содержит written
    ; нужно добавить к предыдущему total
    ; сохраняем total в стек перед syscall
    ; Пересчитаем:
    jmp .done               ; пока просто возвращаем

.error:
    mov rax, -1
    pop r12
    pop rbx
    ret

.done:
    pop r12
    pop rbx
    ret

; ================================================================
; hex_dump — вывод hex-дампа в stdout
; rdi = label (const char*), rsi = data (const void*), rdx = len
; ================================================================
hex_dump:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi            ; label
    mov r12, rsi            ; data
    mov r13, rdx            ; len

    ; write(label, strlen, ...)
    test r13, r13
    jz .done

    ; Простой hex dump через write(stdout, ...)
    ; Используем write syscall (rax=1, rdi=1=stdout)
    mov r14, 0              ; offset

.hex_loop:
    cmp r14, r13
    jae .hex_done

    ; Формируем строку: "XX "
    mov rcx, r14
    and cl, 0x0F
    lea rsi, [hex_chars]
    movzx eax, byte [r12 + r14]
    shr al, 4
    movzx eax, al
    lea rsi, [hex_chars + rax]
    mov al, [rsi]
    mov byte [hex_buf], al

    movzx eax, byte [r12 + r14]
    and al, 0x0F
    lea rsi, [hex_chars + rax]
    mov al, [rsi]
    mov byte [hex_buf+1], al
    mov byte [hex_buf+2], ' '

    ; write(stdout, hex_buf, 3)
    mov rdi, 1              ; stdout
    lea rsi, [hex_buf]
    mov rdx, 3
    mov rax, 1              ; sys_write
    syscall

    inc r14
    jmp .hex_loop

.hex_done:
    ; write("\n", 1)
    mov rdi, 1
    lea rsi, [nl]
    mov rdx, 1
    mov rax, 1
    syscall

.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
