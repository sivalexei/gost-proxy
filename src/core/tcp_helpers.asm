; tcp_helpers.asm — Быстрые TCP-хелперы на ASM x86-64
; Функции: tcp_write_all (write loop), hex_dump (отладочный вывод)
; Вызываются из C как: ssize_t tcp_write_all(int fd, const void *buf, size_t len);
;                        void hex_dump(const char *label, const void *data, size_t len);

section .data
    hex_chars: db "0123456789abcdef"
    nl:        db 10
    colon_sp:  db ": "

section .bss
    hex_buf: resb 48       ; буфер для hex-строки (16 байт * 3 символа + space)

section .text
    global tcp_write_all
    global hex_dump

; ================================================================
; tcp_write_all — запись всех байтов в TCP с retry
; rdi = fd, rsi = buf, rdx = len
; Возвращает: rax = -1 на ошибку, иначе total written
;
; Стек при входе: [rbx, r12, r13, r14, r15]
; Регистры: rbx=fd, r12=buf, r13=written_total, r14=len
; ================================================================
tcp_write_all:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rdi            ; rbx = fd
    mov r12, rsi            ; r12 = buf (start)
    mov r13, rdx            ; r13 = len
    xor r14, r14            ; r14 = written_total = 0

.write_loop:
    cmp r14, r13            ; if total >= len -> done
    jae .done

    ; write(fd, buf + total, len - total)
    mov rdi, rbx            ; fd
    lea rsi, [r12 + r14]    ; buf + written_total
    mov rdx, r13            ; len
    sub rdx, r14            ; len - written_total
    mov rax, 1              ; sys_write
    syscall

    cmp rax, 0
    jl .error               ; error (negative)
    je .retry               ; would block (0 bytes), retry

    ; written_total += bytes_written
    ; rax содержит bytes written — прибавляем к r14
    add r14, rax
    jmp .write_loop

.retry:
    ; written == 0, retry
    jmp .write_loop

.error:
    ; rax < 0 — проверяем EINTR (4) и EAGAIN (11)
    neg rax
    cmp rax, 4              ; EINTR
    je .write_loop
    cmp rax, 11             ; EAGAIN/EWOULDBLOCK
    je .write_loop
    ; Другая ошибка — возвращаем -1
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.done:
    ; Возвращаем written_total (r14)
    mov rax, r14
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ================================================================
; hex_dump — вывод hex-дампа в stdout
; rdi = label (const char*), rsi = data (const void*), rdx = len
; Вывод: "label: XX XX XX ...\n"
; ================================================================
hex_dump:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rdi            ; rbx = label
    mov r12, rsi            ; r12 = data
    mov r13, rdx            ; r13 = len
    mov r14, 1              ; r14 = stdout (fd 1)

    test r13, r13
    jz .hdone

    ; strlen(label)
    xor rcx, rcx
.hsloop:
    cmp byte [rbx + rcx], 0
    je .hsdone
    inc rcx
    jmp .hsloop
.hsdone:

    ; write(stdout, label, strlen)
    mov rdi, r14
    mov rsi, rbx
    mov rdx, rcx
    mov rax, 1
    syscall

    ; write(stdout, ": ", 2)
    lea rsi, [rel colon_sp]
    mov rdx, 2
    mov rax, 1
    syscall

    ; Выделяем 48 байт на стеке для hex-буфера
    sub rsp, 48

    xor r15, r15            ; r15 = offset
.hex_loop:
    cmp r15, r13
    jae .hex_flush

    ; Преобразуем до 16 байт в hex
    xor rcx, rcx            ; rcx = bytes in this row
.hex_byte:
    cmp rcx, 16
    jae .hex_row
    lea rax, [r15 + rcx]
    cmp rax, r13
    jae .hex_row

    ; Загружаем байт (computing address with lea first)
    lea rax, [r15 + rcx]
    movzx eax, byte [r12 + rax]

    ; Старший nibble → hex_buf[rcx*3]
    mov r8d, eax
    shr al, 4
    lea r9, [rel hex_chars]
    movzx eax, al
    mov al, [r9 + rax]
    mov r9d, ecx
    imul r9d, 3
    mov byte [rsp + r9], al

    ; Младший nibble → hex_buf[rcx*3+1]
    mov eax, r8d
    and al, 0x0f
    lea r9, [rel hex_chars]
    movzx eax, al
    mov al, [r9 + rax]
    mov r9d, ecx
    imul r9d, 3
    mov byte [rsp + r9 + 1], al

    ; Пробел → hex_buf[rcx*3+2]
    mov r9d, ecx
    imul r9d, 3
    mov byte [rsp + r9 + 2], ' '

    inc rcx
    jmp .hex_byte

.hex_row:
    ; write(stdout, hex_buf, rcx*3)
    mov rdi, r14
    mov rsi, rsp
    mov edx, ecx
    imul edx, 3
    mov rax, 1
    syscall

    ; write(stdout, "\n", 1)
    mov rdi, r14
    lea rsi, [rel nl]
    mov rdx, 1
    mov rax, 1
    syscall

    add r15, 16
    jmp .hex_loop

.hex_flush:
    add rsp, 48
.hdone:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
