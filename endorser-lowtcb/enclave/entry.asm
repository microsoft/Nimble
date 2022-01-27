default rel

; this is the runtime inside enclave

global _start
global sgx_ereport

extern endorser_entry
extern endorser_stack
extern old_rsp

    section .text

;++
; void _start (void)
;
; Description: The entry point to the SGX enclave
;
; Arguments:
;
; Return:
;
;--
_start:
    mov rbx, rcx
    pop rcx
    pop rdx
    mov [old_rsp], rsp
    lea rsp, [endorser_stack+0x3000]
    call endorser_entry
    mov rsp, [old_rsp]
    push rax
    mov rax, 0x4
    enclu
    int3

;++
; void sgx_ereport(
;     _In_ const sgx_target_info_t* target_info,    // 512-byte aligned
;     _In_reads_(64) const uint8_t* report_data,    // 128-byte aligned
;     _Out_ sgx_report_t* report                    // 512-byte aligned
; )
sgx_ereport:
    push rbx

    mov rbx, rdi ; target_info
    mov rcx, rsi ; report_data
    ; report is already in rdx
    xor eax, eax ; EREPORT (0)
    enclu

    pop rbx
    ret
