; ============================================================
; kuznyechik_transforms.asm
; Преобразования L, R, L_inv, R_inv для Кузнечик
; ============================================================

default rel
section .text

extern L_table
extern InvL_table

; ----------------------------------------------
;  Вспомогательная функция: _l_transform_byte
;  Вход: rdi = указатель на 16‑байтовый блок,
;        r8  = указатель на L_table (или InvL_table)
;  Выход: eax = байт результата
; ----------------------------------------------
_l_transform_byte:
    movdqu xmm0, [rdi]
    vpshufb xmm0, xmm0, [r8]
    movd eax, xmm0
    mov esi, eax
    shr eax, 16
    xor esi, eax
    shr eax, 16
    xor esi, eax
    shr eax, 16
    xor esi, eax
    mov eax, esi
    ret

; ----------------------------------------------
;  R_transform: циклический сдвиг вправо на 1 байт + L
;  Вход: rdi = указатель на блок (16 байт),
;        r8  = указатель на L_table
;  Выход: блок изменяется
; ----------------------------------------------
R_transform:
    push rbp
    mov rbp, rsp
    sub rsp, 40

    movdqu xmm0, [rdi]
    movdqu [rsp+8], xmm0

    lea rdi, [rsp+8]
    call _l_transform_byte

    movdqu xmm1, [rsp+8]
    vpalignr xmm1, xmm1, xmm1, 1
    movdqu [rsp+8], xmm1

    mov [rsp+8], al

    movdqu xmm0, [rsp+8]
    movdqu [rdi], xmm0

    add rsp, 40
    pop rbp
    ret

; ----------------------------------------------
;  R_inv_transform: циклический сдвиг влево на 1 байт + L
;  Вход: rdi = указатель на блок (16 байт),
;        r8  = указатель на InvL_table
;  Выход: блок изменяется
; ----------------------------------------------
R_inv_transform:
    push rbp
    mov rbp, rsp
    sub rsp, 40

    movdqu xmm0, [rdi]
    movdqu [rsp+8], xmm0

    movdqu xmm1, [rsp+8]
    vpalignr xmm1, xmm1, xmm1, 15
    movdqu [rsp+8], xmm1

    movdqu xmm0, [rdi]
    movdqu [rsp+16], xmm0
    lea rdi, [rsp+16]
    call _l_transform_byte

    mov [rsp+8+15], al

    movdqu xmm0, [rsp+8]
    movdqu [rdi], xmm0

    add rsp, 40
    pop rbp
    ret

; ----------------------------------------------
;  kuznyechik_L_avx2: 16 итераций R_transform
;  Вход: rdi = блок (in/out), r8 = L_table
; ----------------------------------------------
kuznyechik_L_avx2:
    push rbp
    mov rbp, rsp
    mov r10, rdi
    mov ecx, 16
.L_loop:
    mov rdi, r10
    call R_transform
    dec ecx
    jnz .L_loop
    pop rbp
    ret

; ----------------------------------------------
;  kuznyechik_L_inv_avx2: 16 итераций R_inv_transform
;  Вход: rdi = блок (in/out), r8 = InvL_table
; ----------------------------------------------
kuznyechik_L_inv_avx2:
    push rbp
    mov rbp, rsp
    mov r10, rdi
    mov ecx, 16
.L_inv_loop:
    mov rdi, r10
    call R_inv_transform
    dec ecx
    jnz .L_inv_loop
    pop rbp
    ret