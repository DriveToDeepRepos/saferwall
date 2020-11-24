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
EXTERN GenericHookHandler@0: PROC

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

    CALL GenericHookHandler@0

   push dword ptr [esp] ; Get the caller return address which sits on top of the stack.
   call GetTargetAPI@4    ; Upon return, eax -> pAPI.
   mov esi, eax

   call IsInsideHook@0
   test eax,eax
   jne CALL_REAL

   push dword ptr [ebp+4] ; push base pointer for local vars ref.
   call IsCalledFromSystemMemory@4
   test eax,eax
   je LOG_API

CALL_REAL:
    jmp dword ptr [esi+14h]
    ret

LOG_API:
    push esp
    push esi
    call PreHookTraceAPI@12
    mov ebx, eax

    ; make the code return to our address
    mov edi, dword ptr [esp] ; 
    mov dword ptr [esp], offset RETURN_HERE
    jmp dword ptr [esi+14h] ; Call the real API.
RETURN_HERE:
    sub esp, 12
    push eax
    push ebx
    push esi
    push edi
    call PostHookTraceAPI@16
    mov dword ptr [esp], edi ; restore return addr.
    ret

HookHandler endp




end