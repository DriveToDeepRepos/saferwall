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
ENDM


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

AsmReturn_x64 PROC
    ; rcx =  cParams
    ; rdx = ReturnValue
    ; r8 = original return addr

    mov rax, rdx
    ret
AsmReturn_x64 endp

AsmCall_x64 PROC
    ; rcx = pContext
    ; rdx = target
    ; r8 = cParams
    ; r9 = CallerStackFrame

    PUSH_VOLATILE

    mov r13, rdx    ; target
    mov r14, r8     ; count params

    ; Push the arguments on the stack.
    sub r8, 2
L1:
    sub r8,1   
    cmp r8,0  
    jl @F
    mov rax, qword ptr [r9+r8*4]
    push rax
    jmp L1

@@:
    ; Restore registers used in calling Win32 APIs.
    mov rcx,  qword ptr [rcx+80h]
    mov rdx,  qword ptr [rcx+88h]
    mov r8,  qword ptr [rcx+0B8h]
    mov r9,  qword ptr [rcx+0C0h]
    call r13

    ; Pop the arguments from the stack.
    sub r14, 2
 L2:
    sub r14,1   
    cmp r14,0  
    jl @F
    pop rcx
    jmp L2
@@:
    POP_VOLATILE

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
    lea rax, [rsp+ 4D0h]
    mov rax, [rax]
    mov qword ptr [ rsp + 0B0h ], rax

    ; Restore Context.Rax
    lea rax, [ rsp + 4D0h + 8 ]
    mov rax, [rax]
    mov qword ptr [rsp + 78h], rax

    ; Restore Context.Rcx
    lea rax, [ rsp + 4D0h + 16 ]
    mov rax, [rax]
    mov qword ptr [rsp + 80h], rax

   ; Pass GenericHookHandler_x64 3 arguments.
   mov rcx, [ rsp + 4D0h + 24 ]
   lea rdx, [ rsp + 4D0h + 32 ]
   mov r8, rsp
   call GenericHookHandler_x64

   ; Balance the stack, 3 arguments + sizeof(CONTEXT)
   add rsp, 24 
   add rsp, 4d0h

   ; Pop the args.
   cmp rcx, 2
   jle @F
   imul rcx, 8
   add rsp, rcx
@@:
   mov qword ptr [rsp],  r8 ; return addr
   ret

HookHandler ENDP

end