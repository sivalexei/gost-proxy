; ============================================================
; kuznyechik_modes.asm
; Режимы шифрования Кузнечик: ECB, CTR
; ============================================================

default rel
section .text

extern kuznyechik_encrypt_block

; ----------------------------------------------
;  kuznyechik_encrypt_ecb
;  Вход: rdi = in, rsi = out, rdx = len, rcx = expanded_key
; ----------------------------------------------
kuznyechik_encrypt_ecb:
    push rbp
    mov rbp, rsp

    mov r10, rdi
    mov r11, rsi
    mov r12, rdx
    mov r13, 0
    mov r14, rcx

.ecb_loop:
    cmp r13, r12
    jge .ecb_done

    mov rdi, r10
    mov rsi, r14
    call kuznyechik_encrypt_block

    add r10, 16
    add r11, 16
    add r13, 16
    jmp .ecb_loop

.ecb_done:
    pop rbp
    ret

; ----------------------------------------------
;  kuznyechik_encrypt_ctr
;  Вход: rdi = in, rsi = out, rdx = len,
;        rcx = expanded_key,
;        r8  = nonce (16 байт, счётчик в младших 8 байтах)
; ----------------------------------------------
kuznyechik_encrypt_ctr_asm:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov r10, rdi
    mov r11, rsi
    mov r12, rdx
    mov r13, rcx
    mov r14, r8

    mov r15, 0

    movdqu xmm0, [r14]
    movdqu [rsp+16], xmm0

.ctr_loop:
    cmp r15, r12
    jge .ctr_done

    mov rax, [rsp+16]
    add rax, 1
    mov [rsp+16], rax

    lea rdi, [rsp+16]
    mov rsi, r13
    call kuznyechik_encrypt_block

    movdqu xmm0, [r10]
    movdqu xmm1, [rsp+16]
    pxor xmm0, xmm1
    movdqu [r11], xmm0

    add r10, 16
    add r11, 16
    add r15, 16
    jmp .ctr_loop

.ctr_done:
    add rsp, 64
    pop rbp
    ret

; ----------------------------------------------
;  Заглушки для неиспользуемых функций
; ----------------------------------------------
kuznyechik_S_avx2:
    ret
kuznyechik_inv_S_avx2:
    ret
kuznyechik_precompute_tables:
    ret