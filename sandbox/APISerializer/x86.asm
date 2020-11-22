.686p
.model flat, stdcall


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN GetTargetAPI@4 : PROC
EXTERN IsInsideHook@0 : PROC
EXTERN IsCalledFromSystemMemory@4: PROC


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE


GetBasePointer proc
    mov eax, ebp
    ret
GetBasePointer endp



HookHandler proc

    push dword ptr [esp] ; Get the caller return address which sits on top of the stack.
    call GetTargetAPI@4    ; Upon return, eax -> pAPI.
    mov esi, eax

    call IsInsideHook@0
    test eax,eax
    jne CALL_REAL

   push dword ptr [ebp+4]
   call IsCalledFromSystemMemory@4
   test eax,eax
   je LOG_API

CALL_REAL:
    jmp dword ptr [esi+14h]
LOG_API:
    jmp dword ptr [esi+14h]
    ret
HookHandler endp




end