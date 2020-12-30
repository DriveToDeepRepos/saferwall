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

    ; xmm ops will fails if stack is not 16 bits aligned.
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
 
    push r12
    push rbx

    ; RtlAllocateHeap can mess up with volatile registers
    ; even though they are `volatile`, we need to keep
    ; a copy in case someone tried to call the API with call rax
    ; later, to get the target API we need RAX.
    PUSH_VOLATILE

    ; RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTEXT))
    call NtCurrentTeb 
    mov rax, qword ptr [ rax + 60h]
    mov r8d, 4D0h
    mov edx, 8
    mov rcx, qword ptr [rax + 30h]
    sub esp, SHADOW_SPACE
    call RtlAllocateHeap
    add esp, SHADOW_SPACE
    mov r12, rax  ; r12 points to the pContext record.

   ; RtlCaptureContext(&Context)
   lea rcx, [rax]
   call RtlCaptureContext

   ; Restore Context.r11
    lea rbx, [rsp]
    mov rbx, [rbx]
    mov qword ptr [ r12 + 0D0h ], rbx

    ; Restore Context.r10
    lea rbx, [ rsp + 8 ]
    mov rbx, [rbx]
    mov qword ptr [ r12 + 0C8h], rbx

    ; Restore Context.r9
    lea rbx, [ rsp + 16 ]
    mov rbx, [rbx]
    mov qword ptr [ r12 + 0C0h], rbx

    ; Restore Context.r8
    lea rbx, [ rsp + 24 ]
    mov rbx, [rbx]
    mov qword ptr [ r12 + 0B8h], rbx

   ; Restore Context.rdx
    lea rbx, [ rsp + 32 ]
    mov rbx, [rbx]
    mov qword ptr [ r12 + 88h], rbx

   ; Restore Context.rcx
    lea rbx, [ rsp + 40 ]
    mov rbx, [rbx]
    mov qword ptr [r12 + 80h], rbx

   ; Restore Context.rax
    lea rbx, [ rsp + 48 ]
    mov rbx, [rbx]
    mov qword ptr [r12 + 78h], rbx

   ; Call GenericHookHandler_x64
   ; (DWORD_PTR ReturnAddress, DWORD_PTR CallerStackFrame, PCONTEXT pContext))
   mov rcx, [ rsp + 48 + 24]
   lea rdx, [ rsp + 48 + 32 ]
   mov r8, r12
   call GenericHookHandler_x64

   ; Balance the stack.
   add rsp, 56  ; size of all volatile registers
   pop rbx
   pop r12

   mov qword ptr [rsp],  rdx ; return addr
   ret

HookHandler ENDP

end