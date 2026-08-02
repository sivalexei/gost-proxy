; ============================================================
; kuznyechik_key.asm
; Развертывание ключей для Кузнечик
; ============================================================

default rel
section .text

extern S_box_table
extern L_table
extern round_constants

; ----------------------------------------------
;  kuznyechik_set_key
;  Вход: rdi = указатель на 32‑байтный ключ
;        rsi = указатель на массив из 10 раундовых ключей (160 байт)
; ----------------------------------------------
kuznyechik_set_key:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi+16]
    movdqu [rsp+16], xmm0
    movdqu [rsp+32], xmm1

    movdqu [rsi], xmm0
    movdqu [rsi+16], xmm1
    add rsi, 32

    mov r10d, 0
.key_groups:
    cmp r10d, 4
    jge .key_done

    mov ecx, 1
.key_rounds:
    cmp ecx, 9
    jge .key_store

    mov r11d, r10d
    imul r11d, 8
    lea r11d, [r11d + ecx - 1]

    lea rbx, [rel round_constants]
    lea rax, [rbx+r11]
    movzx eax, byte [rax]

    xorps xmm2, xmm2
    movd xmm2, eax

    movdqu xmm3, [rsp+16]
    pxor xmm3, xmm2
    lea rdx, [rel S_box_table]
    vpshufb xmm3, xmm3, [rdx]

    movdqu [rsp+48], xmm3
    lea rdi, [rsp+48]
    lea r8, [rel L_table]
    call kuznyechik_L_avx2

    movdqu xmm4, [rsp+48]
    pxor xmm4, [rsp+32]

    movdqu xmm3, [rsp+32]
    movdqu [rsp+16], xmm3
    movdqu [rsp+32], xmm4

    inc ecx
    jmp .key_rounds

.key_store:
    movdqu xmm0, [rsp+16]
    movdqu xmm1, [rsp+32]
    movdqu [rsi], xmm0
    movdqu [rsi+16], xmm1
    add rsi, 32

    inc r10d
    jmp .key_groups

.key_done:
    add rsp, 64
    pop rbp
    ret