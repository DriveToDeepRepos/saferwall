;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;

EXTERN GenericHookHandler_x64: PROC
EXTERN NtCurrentTeb: PROC
EXTERN RtlAllocateHeap: PROC
EXTERN RtlCaptureContext: PROC
EXTERN RtlRestoreContext: PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Capture the execution context.
PUSH_VOLATILE MACRO
    pushfq  
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
ENDM

; Loads all general purpose registers from the stack
POP_VOLATILE MACRO
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    popfq  
ENDM


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

AsmReturn PROC cParams, ReturnValue
    mov ecx, cParams
    mov eax, ReturnValue
    ret
AsmReturn endp

AsmCall_x64 PROC
    ; rcx = pContext
    ; rdx = target

    mov r14, offset RETURN_LABEL
    mov qword ptr [rcx+0D8h], r14       ; return addr. (r12)
    mov qword ptr [rcx+0E0h], rdx       ; target (r13)
    mov qword ptr [rcx+0F0h], rsp       ; current stack (r15)
    mov r14, [rsp]
    mov qword ptr [rcx+0E8h], r14       ; caller address (r14)


    sub rsp, 8                          ; allocate space for PEXCEPTION_RECORD
    mov rdx, rsp                        ; set up the second argument to RtlRestoreContext
    mov r14, offset CONTINUE_LABEL      ; get the addr of the next block.
    mov qword ptr [rcx+0F8h], r14       ; Context.RIP = @CONTINUE_LABEL
    call RtlRestoreContext              ; restore the old context.

CONTINUE_LABEL:
    mov [rsp], r12
    jmp r13

RETURN_LABEL:
    mov rsp, r15
    mov [rsp], r14
    ret
AsmCall_x64 endp

   

HookHandler PROC
   
   push rcx         ; save RCX a we will use it to call RtlCaptureContext()
   push rax         ; save RAX, used in memset(0)
   push rdi         ; save RDI, used in memset(0).

   sub rsp, 4D0h   ; allocate space for CONTEXT structure.
   xor eax, eax    ; set eax to 0 to zero out the buffer.
   mov ecx, 4D0h   ; set ecx to size of the CONTEXT structure.
   lea rdi, [rsp]  ; rdi points to the buffer holding the CONTEXT structure.
   rep stos byte ptr [rdi]  ; memset(0)

   lea rcx, [rsp]
   call RtlCaptureContext

   ; restore the registers to their original values before
   ; the call to RtlCaptureContext()

   ; Restore Context.Rdi
    lea rdi, [rsp+ 4D0h]
    mov rdi, [rdi]
    mov qword ptr [ rsp + 0B0h ], rdi

    ; Restore Context.Rax
    lea rax, [ rsp + 4D0h + 8 ]
    mov rax, [rax]
    mov qword ptr [rsp + 78h], rax

    ; Restore Context.Rcx
    lea rcx, [ rsp + 4D0h + 16 ]
    mov rcx, [rcx]
    mov qword ptr [rsp + 80h], rcx

    ; Restore Context.Rsp
    lea r9, [ rsp + 4d0h + 24 ] 
    mov qword ptr [ rsp + 98h ], r9

   mov rcx, [ rsp + 4D0h + 24 ]
   lea rdx, [ rsp + 4D0h + 32 ]
   mov r8, rsp
   call GenericHookHandler_x64

   sub rsp, 16              

   mov rdx, qword ptr [ rsp ]
   imul rdx, 8
   add rsp, rcx
   mov qword ptr [rsp],  rdx
   ret

HookHandler ENDP


end