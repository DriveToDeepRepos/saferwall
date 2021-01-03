;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;

EXTERN GenericHookHandler_x64: PROC
EXTERN NtCurrentTeb: PROC
EXTERN RtlCaptureContext: PROC
EXTERN RtlRestoreContext: PROC
EXTERN TrueRtlAllocateHeap:QWORD

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

PUSH_VOLATILE MACRO
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
ENDM

POP_VOLATILE MACRO
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
ENDM

; Capture the execution context.
PUSH_NON_VOLATILE MACRO
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
POP_NON_VOLATILE MACRO
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
ENDM



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

SHADOW_SPACE                        =  20h
CONTEXT_SIZE = 10h

AsmReturn_x64 PROC
    ; rcx = ReturnValue
    ; rdx = original return addr
    mov rax, rcx
    ret
AsmReturn_x64 endp

AsmCall_x64 PROC
    ; rcx = pContext
    ; rdx = target
    ; r8 = cParams
    ; r9 = CallerStackFrame

    PUSH_NON_VOLATILE

    mov r12, rsp    ; stack pointer
    mov r13, rdx    ; target
    mov r14, r8     ; count params

    ; xmm ops will fails if stack is not 16 bytes aligned.
    mov r15, rsp
    and r15, 15 
    sub rsp, r15 

    ; at this stage, the stack is 16-bytes aligned,
    ; however as we will be pushing extra params to the stack
    ; we need to adjust if necessery.
    cmp r8,4
    jle L2 
    shr r14, 1  ; if number of params is not pair, we sub 8 bytes more.
    jnc L1       ; if divisable by 2, jump to L1.
    sub rsp, 8  ; align the stack
    mov r14, r8

    ; Places parametes on the right location on the stack.
L1:  
    cmp r8,4
    jle L2  
    sub r8, 1
    mov rax, qword ptr [r9+r8*8]
    push rax
    jmp L1

L2:
    ; Restore registers used in calling Win32 APIs.
    mov r8,  qword ptr [rcx+0B8h]
    mov r9,  qword ptr [rcx+0C0h]
    mov rdx, qword ptr [rcx+88h]
    mov rcx, qword ptr [rcx+80h]
    sub rsp, SHADOW_SPACE
    call r13
    
    ; restore rsp.
    mov rsp, r12

    POP_NON_VOLATILE
    ret
AsmCall_x64 endp

   

HookHandler PROC

   push rcx
   push r12

    ; fxsave will fails if stack is not 16 bytes aligned.
    mov r12, rsp
    and r12, 15 
    sub rsp, r12

   ; Call RtlCaptureContext
   sub rsp, 4d0h
   lea rcx, [rsp]
   call RtlCaptureContext

   ; Restore Context.RCX
    lea rcx, [ rsp + 4D0h + 8 ]
    mov rcx, [rcx]
    mov qword ptr [rsp  + 80h], rcx

   ; Call GenericHookHandler_x64
   mov rcx, qword ptr [ rsp + 04D0h + 24]    ; ReturnAddress
   lea rdx, [ rsp + 4D0h + 32 ]   ; CallerStackFrame
   mov r8, rsp                     ; pContext
   mov r9, qword ptr [ rsp + 4D0h + 16]     ; RealTarget
   call GenericHookHandler_x64

   ; Balance the stack.
   add rsp, 4d0h    ; size of CONTEXT structure
   add rsp, r12     ; alignement
   pop r12
   add rsp, 16      ; target API push + rcx

   mov qword ptr [rsp],  rdx ; return addr
   ret

HookHandler ENDP

end