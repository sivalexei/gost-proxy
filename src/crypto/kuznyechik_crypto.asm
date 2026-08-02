; ============================================================
; kuznyechik_crypto.asm
; Шифрование/дешифрование блока Кузнечик
; ============================================================

default rel
section .text

extern S_box_table
extern InvS_box_table
extern L_table
extern InvL_table
extern kuznyechik_L_avx2
extern kuznyechik_L_inv_avx2

; ----------------------------------------------
;  kuznyechik_encrypt_block
;  Вход: rdi = указатель на блок (in/out)
;        rsi = указатель на expanded_key (160 байт)
; ----------------------------------------------
kuznyechik_encrypt_block:
    push rbp
    mov rbp, rsp

    mov r10, rdi
    mov r11, rsi
    mov ecx, 9

.enc_loop:
    movdqu xmm0, [r10]
    movdqu xmm1, [r11]
    pxor xmm0, xmm1

    lea rdx, [rel S_box_table]
    vpshufb xmm0, xmm0, [rdx]

    movdqu [r10], xmm0
    mov rdi, r10
    lea r8, [rel L_table]
    call kuznyechik_L_avx2

    add r11, 16
    dec ecx
    jnz .enc_loop

    movdqu xmm0, [r10]
    movdqu xmm1, [r11]
    pxor xmm0, xmm1
    movdqu [r10], xmm0

    pop rbp
    ret

; ----------------------------------------------
;  kuznyechik_decrypt_block
;  Вход: rdi = указатель на блок (in/out)
;        rsi = указатель на expanded_key (160 байт)
; ----------------------------------------------
kuznyechik_decrypt_block:
    push rbp
    mov rbp, rsp

    mov r10, rdi
    mov r11, rsi
    add r11, 144
    mov ecx, 9

.dec_loop:
    movdqu xmm0, [r10]
    movdqu xmm1, [r11]
    pxor xmm0, xmm1
    movdqu [r10], xmm0

    mov rdi, r10
    lea r8, [rel InvL_table]
    call kuznyechik_L_inv_avx2

    movdqu xmm0, [r10]
    lea rdx, [rel InvS_box_table]
    vpshufb xmm0, xmm0, [rdx]
    movdqu [r10], xmm0

    sub r11, 16
    dec ecx
    jnz .dec_loop

    mov r11, rsi
    movdqu xmm0, [r10]
    movdqu xmm1, [r11]
    pxor xmm0, xmm1
    movdqu [r10], xmm0

    pop rbp
    ret