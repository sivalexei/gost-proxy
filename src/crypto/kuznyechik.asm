; =============================================================================
; ГОСТ Р 34.12-2015 "Кузнечик" — Шифрование блока 128 бит, ключ 256 бит
; Реализация на NASM x86-64 (System V AMD64 ABI)
;
; Функции:
;   kuznyechik_set_key(key_ptr, expanded_key_ptr)
;   kuznyechik_encrypt_block(block_ptr, expanded_key_ptr)
;   kuznyechik_decrypt_block(block_ptr, expanded_key_ptr)
;
; System V ABI: rdi=arg1, rsi=arg2, rdx=arg3, rcx=arg4
; =============================================================================

section .rodata

; S-BOX подстановка (16x16)
align 16
sbox:
    db 0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16
    db 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D
    db 0xE9, 0x77, 0xF0, 0xDB, 0xD2, 0x62, 0x2A, 0x95
    db 0x05, 0xF4, 0x0E, 0x85, 0x60, 0x2C, 0x20, 0x40
    db 0xBF, 0x38, 0xA4, 0xCC, 0xDE, 0x59, 0xB7, 0x1A
    db 0x72, 0xE0, 0xB9, 0x70, 0x42, 0xCE, 0x9F, 0x65
    db 0x4F, 0x9C, 0xAB, 0xC3, 0x8A, 0x91, 0xF5, 0x02
    db 0xB6, 0x7F, 0x3E, 0xD7, 0x3D, 0x97, 0x00, 0xC6
    db 0x9A, 0x75, 0x8C, 0xE5, 0x3B, 0x71, 0x0B, 0xD4
    db 0x30, 0xF2, 0x5A, 0x6F, 0x5E, 0x27, 0xE2, 0x58
    db 0x46, 0xBD, 0x78, 0x68, 0xC8, 0xB8, 0xD0, 0x2E
    db 0x47, 0xA2, 0x7E, 0x07, 0x6A, 0xF9, 0x4B, 0x67
    db 0xC1, 0x37, 0xE6, 0xFD, 0x0D, 0x6B, 0xF5, 0x09
    db 0x3C, 0x1D, 0x21, 0x5C, 0x41, 0x18, 0x53, 0x24
    db 0x0C, 0xDF, 0xA9, 0x96, 0xCA, 0x86, 0x6C, 0x43
    db 0x74, 0xB2, 0x29, 0x9E, 0xD1, 0x5B, 0x63, 0x9A

; Обратный S-BOX
align 16
inv_sbox:
    db 0xB5, 0x56, 0x35, 0x25, 0x0E, 0x17, 0x70, 0xF6
    db 0x69, 0xC5, 0x5A, 0x7C, 0x9B, 0x41, 0x6F, 0x3C
    db 0x10, 0x53, 0xE4, 0x7A, 0x02, 0xF2, 0x82, 0x23
    db 0x22, 0x93, 0x9C, 0xD9, 0x12, 0xED, 0x20, 0x08
    db 0x30, 0x6E, 0x14, 0x98, 0x00, 0x84, 0xD2, 0x38
    db 0x8E, 0x9F, 0x51, 0x33, 0x19, 0x48, 0x52, 0x99
    db 0x24, 0xF7, 0x57, 0x50, 0x54, 0x4D, 0x36, 0x06
    db 0x74, 0x16, 0x80, 0x63, 0x6D, 0x6A, 0x9D, 0xA2
    db 0x2F, 0x77, 0x34, 0xF1, 0x42, 0xC0, 0xB0, 0xA8
    db 0x67, 0x73, 0x05, 0xD5, 0xA9, 0xBA, 0xCF, 0xB3
    db 0x95, 0xDE, 0x32, 0xD6, 0x88, 0xCC, 0xA3, 0x8D
    db 0xAA, 0x44, 0x4A, 0xE1, 0xF9, 0xE2, 0xF4, 0x81
    db 0x04, 0xA4, 0x1B, 0xB8, 0xC9, 0xFA, 0x91, 0xE0
    db 0xF0, 0x8A, 0x2B, 0xA1, 0x01, 0xE7, 0x47, 0xD4
    db 0xA6, 0x26, 0x94, 0xCB, 0x5E, 0xD3, 0x4C, 0x15
    db 0x3D, 0x0D, 0xFC, 0x5C, 0x4B, 0xCE, 0x2D, 0x55

; Константы для расширения ключа
align 16
constants:
    db 0x01, 0x94, 0x85, 0x76, 0x2D, 0x16, 0xF0, 0x28
    db 0xC8, 0x36, 0xF2, 0x6E, 0x53, 0xA2, 0x09, 0x04
    db 0x02, 0xE9, 0xCB, 0xEC, 0x5A, 0x2D, 0xE0, 0x51
    db 0x91, 0x6D, 0xE4, 0xDC, 0xA6, 0x45, 0x12, 0x08
    db 0x03, 0x7D, 0x6F, 0x9A, 0x77, 0x3B, 0x10, 0x79
    db 0x59, 0x5B, 0x16, 0xB2, 0xF5, 0xE7, 0x1B, 0x0C
    db 0x04, 0xD2, 0x17, 0xD9, 0xB4, 0x5B, 0xC0, 0xA2
    db 0x23, 0xDB, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0
    db 0x05, 0x46, 0xB3, 0xAF, 0xC9, 0x4D, 0x10, 0xD8
    db 0xEB, 0xE1, 0x37, 0x6A, 0x1E, 0x0B, 0x6E, 0xEC
    db 0x06, 0x3D, 0x4E, 0x35, 0xEE, 0x67, 0xF0, 0x81
    db 0x12, 0xA8, 0x21, 0x6E, 0xBB, 0xCC, 0x75, 0xE4
    db 0x07, 0xA9, 0xEA, 0x43, 0x93, 0x71, 0x20, 0xB9
    db 0xDA, 0x73, 0x07, 0x0C, 0xF6, 0x2E, 0x9E, 0x18
    db 0x08, 0xA5, 0x2F, 0xB3, 0x69, 0xB7, 0x81, 0x45
    db 0x47, 0xA2, 0x7E, 0x07, 0x6A, 0xF9, 0x4B, 0x67
    db 0x09, 0x31, 0x8B, 0xC5, 0x34, 0xA1, 0x51, 0x3D
    db 0x0C, 0xDF, 0xA9, 0x96, 0xCA, 0x86, 0x6C, 0x43
    db 0x0A, 0x48, 0x76, 0x12, 0x52, 0xC4, 0xB1, 0x6C
    db 0x81, 0x69, 0x27, 0x43, 0x6D, 0x73, 0x25, 0x2F
    db 0x0B, 0xDC, 0xD2, 0x64, 0x2F, 0xD2, 0x61, 0x14
    db 0x58, 0xB6, 0x8E, 0x2F, 0x3E, 0xD7, 0x3D, 0x97
    db 0x0C, 0x65, 0x2F, 0x9E, 0x1C, 0xE7, 0x81, 0x71
    db 0x90, 0xCD, 0xA8, 0x69, 0x53, 0x0E, 0xC0, 0xAE
    db 0x0D, 0xF1, 0x8B, 0xE8, 0x61, 0xF1, 0x51, 0x09
    db 0x59, 0xE6, 0x5E, 0x07, 0x0E, 0x85, 0x60, 0x2C
    db 0x0E, 0x88, 0x76, 0x7E, 0x06, 0xD4, 0x81, 0x7A
    db 0xA0, 0xDB, 0x42, 0x6E, 0x59, 0x63, 0x5D, 0xB2
    db 0x0F, 0x1C, 0xD2, 0x08, 0x5B, 0xC2, 0xB1, 0x02
    db 0x69, 0xE2, 0x94, 0x02, 0x04, 0x40, 0xBF, 0x38

; Таблицы для операций
align 16
r_shift_table:
    db 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14

align 16
l_shift_table:
    db 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0

align 16
mask_low_4:
    times 16 db 0x0F

section .text

; =============================================================================
; S-BOX подстановка для 128-битного блока
; Вход: xmm0 = блок данных
; Выход: xmm0 = S(block)
; =============================================================================
global kuznyechik_S
kuznyechik_S:
    push rbp
    mov  rbp, rsp
    push rbx

    ; Сохраняем блок на стеке
    sub rsp, 16
    movdqu [rsp], xmm0

    ; Загружаем адрес S-BOX в регистр
    lea rbx, [rel sbox]

    ; Обрабатываем каждый из 16 байтов
    %assign i 0
    %rep 16
        movzx  eax, byte [rsp + i]
        movzx  eax, byte [rbx + rax]
        mov    byte [rsp + i], al
        %assign i i+1
    %endrep

    ; Загружаем результат обратно в xmm0
    movdqu xmm0, [rsp]
    add rsp, 16

    pop rbx
    pop rbp
    ret

; =============================================================================
; Обратная S-BOX подстановка
; Вход: xmm0 = блок данных
; Выход: xmm0 = S^-1(block)
; =============================================================================
global kuznyechik_inv_S
kuznyechik_inv_S:
    push rbp
    mov  rbp, rsp
    push rbx

    sub rsp, 16
    movdqu [rsp], xmm0

    lea rbx, [rel inv_sbox]

    %assign i 0
    %rep 16
        movzx  eax, byte [rsp + i]
        movzx  eax, byte [rbx + rax]
        mov    byte [rsp + i], al
        %assign i i+1
    %endrep

    movdqu xmm0, [rsp]
    add rsp, 16

    pop rbx
    pop rbp
    ret

; =============================================================================
; L-преобразование (линейное) для одного 128-битного блока
; Выполняет 16 итераций R-преобразования
; Вход: xmm0 = блок данных
; Выход: xmm0 = L(block)
; =============================================================================
global kuznyechik_L
kuznyechik_L:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12

    ; Сохраняем блок на стеке
    sub rsp, 16
    movdqu [rsp], xmm0

    ; Загружаем адреса таблиц
    lea rbx, [rel r_shift_table]
    lea r12, [rel mask_low_4]

    ; 16 итераций R-преобразования
    %assign iter 0
    %rep 16
        ; Загружаем текущий блок
        movdqu xmm0, [rsp]

        ; R-преобразование: циклический сдвиг влево на 1 байт
        pshufb xmm0, [rbx]

        ; Умножение на полином x^7 + x^6 + x + 1
        movdqa xmm1, xmm0
        psllq  xmm1, 63          ; x^7
        movdqa xmm2, xmm0
        psrlq  xmm2, 1           ; x^0
        pxor   xmm0, xmm1
        pxor   xmm0, xmm2

        ; Сохраняем промежуточный результат
        movdqu [rsp], xmm0
        %assign iter iter+1
    %endrep

    ; Загружаем финальный результат
    movdqu xmm0, [rsp]
    add rsp, 16

    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; Обратное L-преобразование
; Вход: xmm0 = блок данных
; Выход: xmm0 = L^-1(block)
; =============================================================================
global kuznyechik_inv_L
kuznyechik_inv_L:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12

    sub rsp, 16
    movdqu [rsp], xmm0

    lea rbx, [rel l_shift_table]
    lea r12, [rel mask_low_4]

    %assign iter 0
    %rep 16
        ; Обратный S-BOX
        movdqu xmm0, [rsp]
        call kuznyechik_inv_S
        movdqu [rsp], xmm0

        ; Обратное L-преобразование
        movdqu xmm0, [rsp]
        pshufb xmm0, [rbx]       ; обратный циклический сдвиг
        movdqa xmm1, xmm0
        psrlq  xmm1, 63
        pxor   xmm0, xmm1
        movdqu [rsp], xmm0

        %assign iter iter+1
    %endrep

    movdqu xmm0, [rsp]
    add rsp, 16

    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; Расширение ключа (Key Schedule)
; Вход: rdi = указатель на 256-битный ключ (32 байта)
;       rsi = указатель на расширенный ключ (10 * 16 = 160 байт)
; =============================================================================
global kuznyechik_set_key
kuznyechik_set_key:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13

    ; Загружаем ключ (256 бит = 2 блока по 128 бит)
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]

    ; Сохраняем расширенные ключи
    movdqu [rsi], xmm0
    movdqu [rsi + 16], xmm1

    ; Адреса таблицы констант
    lea r13, [rel constants]

    ; Расширение ключа: генерируем 8 дополнительных ключей
    mov rbx, rsi
    mov r12, 0

.key_loop:
    ; Вычисляем L-преобразование для K2
    movdqu xmm0, [rbx + 16]
    call kuznyechik_L

    ; XOR с константой (вычисляем смещение: r12 * 16)
    mov rax, r12
    shl rax, 4                   ; rax = r12 * 16
    movdqu xmm1, [r13 + rax]
    pxor   xmm0, xmm1

    ; XOR с K1
    movdqu xmm1, [rbx]
    pxor   xmm0, xmm1

    ; Результат = новый K1
    movdqu [rbx + 32], xmm0

    ; Вычисляем L-преобразование для нового K1
    movdqu xmm0, [rbx + 32]
    call kuznyechik_L

    ; XOR с K2
    movdqu xmm1, [rbx + 16]
    pxor   xmm0, xmm1
    movdqu [rbx + 48], xmm0

    ; Сдвигаем указатель
    add rbx, 32
    inc r12
    cmp r12, 4
    jl  .key_loop

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; =============================================================================
; Шифрование одного блока (128 бит)
; Вход: rdi = указатель на блок данных (16 байт)
;       rsi = указатель на расширенный ключ (160 байт)
; =============================================================================
global kuznyechik_encrypt_block
kuznyechik_encrypt_block:
    push rbp
    mov  rbp, rsp

    ; Загружаем блок
    movdqu xmm0, [rdi]

    ; Первое сложение с ключом (K1) — через register для unaligned
    movdqu xmm1, [rsi]
    pxor xmm0, xmm1

    ; 9 раундов
    %assign round 1
    %rep 9
        call kuznyechik_S
        call kuznyechik_L
        movdqu xmm1, [rsi + round * 16]
        pxor xmm0, xmm1
        %assign round round+1
    %endrep

    ; 10-й раунд (без L)
    call kuznyechik_S
    movdqu xmm1, [rsi + 10 * 16]
    pxor xmm0, xmm1

    ; Сохраняем результат
    movdqu [rdi], xmm0

    pop rbp
    ret

; =============================================================================
; Расшифрование одного блока (128 бит)
; Вход: rdi = указатель на зашифрованный блок (16 байт)
;       rsi = указатель на расширенный ключ (160 байт)
; =============================================================================
global kuznyechik_decrypt_block
kuznyechik_decrypt_block:
    push rbp
    mov  rbp, rsp

    ; Загружаем зашифрованный блок
    movdqu xmm0, [rdi]

    ; Обратное сложение с ключом (K10)
    movdqu xmm1, [rsi + 10 * 16]
    pxor xmm0, xmm1

    ; Обратный S-BOX
    call kuznyechik_inv_S

    ; 9 обратных раундов
    %assign round 9
    %rep 9
        call kuznyechik_inv_L
        movdqu xmm1, [rsi + round * 16]
        pxor xmm0, xmm1
        call kuznyechik_inv_S
        %assign round round-1
    %endrep

    ; Финальное сложение с ключом (K1)
    movdqu xmm1, [rsi]
    pxor xmm0, xmm1

    ; Сохраняем результат
    movdqu [rdi], xmm0

    pop rbp
    ret

; =============================================================================
; CTR-режим шифрования
; Вход: rdi = входные данные
;       rsi = выходные данные
;       rdx = длина данных
;       rcx = расширенный ключ
;       r8  = nonce (12 байт)
; =============================================================================
global kuznyechik_encrypt_ctr
kuznyechik_encrypt_ctr:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rbx, rcx

    ; Формируем nonce
    movdqu xmm2, [r8]
    pxor   xmm3, xmm3

.ctr_loop:
    cmp r14, 0
    jle .ctr_done

    ; Формируем блок counter
    movdqa xmm0, xmm2
    pxor   xmm0, xmm3

    ; Шифруем counter блок через стек
    sub rsp, 32
    movdqu [rsp], xmm0
    mov  rdi, rsp
    mov  rsi, rbx
    call kuznyechik_encrypt_block
    movdqu xmm0, [rsp]
    add rsp, 32

    ; XOR с входными данными
    movdqu xmm1, [r12]
    pxor   xmm0, xmm1
    movdqu [r13], xmm0

    ; Сдвигаем указатели
    add r12, 16
    add r13, 16
    sub r14, 16

    ; Увеличиваем счётчик
    mov rax, 1
    movq xmm1, rax
    pxor xmm3, xmm1

    jmp .ctr_loop

.ctr_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
