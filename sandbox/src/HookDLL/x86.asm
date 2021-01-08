.686p
.model flat, stdcall


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;

EXTERN GenericHookHandler@12: PROC

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

AsmCall PROC target, cParams, callerStackFrame

    mov eax,dword ptr [CallerStackFrame]  
    mov ecx, cParams
 @@:
    sub ecx,1   
    cmp ecx,0  
    jl CALL_API  
    mov edx,dword ptr [eax+ecx*4]
    push edx
    jmp @B


CALL_API:
    call dword ptr [target]

    mov ecx, cParams
    imul ecx, 4
    add esp, ecx
    ret
AsmCall endp

   

HookHandler proc

   call GenericHookHandler@12
   sub esp, 8              

   mov edx, dword ptr [esp]   ; get the return addr
   imul ecx, 4
   add esp, ecx
   mov dword ptr [esp],  edx

    ret

HookHandler endp


end