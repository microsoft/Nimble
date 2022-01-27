default rel

; this is the runtime outside enclave

global enclu_call

    section .text

;++
; void enclu_call (void)
;
; Description: The entry point to call the SGX enclave
;
; Arguments:
;
; Return:
;
;--
enclu_call:
    push rbx
    push rdx
    push rcx
    mov rax, 0x2
    mov rbx, 0x20000000 ; must be consistent with enclave.h
    mov rcx, _eresume
_eresume:
    enclu
    pop rax
    pop rbx
    ret

