.686p
.model flat, stdcall


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN GetTargetAPI@4 : PROC
EXTERN IsInsideHook@0 : PROC
EXTERN IsCalledFromSystemMemory@4: PROC
EXTERN PreHookTraceAPI@12 : PROC
EXTERN PostHookTraceAPI@16 : PROC
EXTERN GenericHookHandler@8: PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE


GetBasePointer proc
    mov eax, ebp
    ret
GetBasePointer endp


PushIntoStack PROC value
    push value
    ret
PushIntoStack endp

GetESP PROC
    mov eax, esp
    ret
GetESP endp

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

   mov ebx, dword ptr [esp]
   call GenericHookHandler@8
   sub esp, 8

   add esp, 8 ; quick hack
   mov dword ptr [esp], ebx

    ret

HookHandler endp




end