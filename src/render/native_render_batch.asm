; Position-independent x86 helpers for the pinned NTW render worker.
; Batch context belongs to one leaf Execute invocation, never shared.
; The original consumer runs after scheduler::spawn_root_and_wait.
.686
.model flat

BATCH_CAPACITY EQU 64
CONTEXT_BYTES EQU (8 + 12 * BATCH_CAPACITY)
; Caller frame is 88h; arg7 at +A4h; helper return+arg1+saved ESI add Ch.
ADAPTER_CONTEXT_OFFSET EQU 0B0h

.const
PUBLIC batch_contract
batch_contract DWORD 1, BATCH_CAPACITY, CONTEXT_BYTES, ADAPTER_CONTEXT_OFFSET

.code
PUBLIC append_vec3
PUBLIC flush_vec3

; Original helper ABI: ECX=owner, [ESP+4]=Vec3*, RET4, ESI preserved.
; The cloned caller supplies its private context as seventh argument.
append_vec3 PROC
    push esi
    mov esi, DWORD PTR [esp + ADAPTER_CONTEXT_OFFSET]
    mov eax, DWORD PTR [esi + 4]
    lea edx, [eax + eax * 2]
    lea edx, [esi + edx * 4 + 8]
    inc eax
    mov DWORD PTR [esi + 4], eax
    mov ecx, DWORD PTR [esp + 8]
    mov eax, DWORD PTR [ecx]
    mov DWORD PTR [edx], eax
    mov eax, DWORD PTR [ecx + 4]
    mov DWORD PTR [edx + 4], eax
    mov eax, DWORD PTR [ecx + 8]
    mov DWORD PTR [edx + 8], eax
    cmp DWORD PTR [esi + 4], BATCH_CAPACITY
    jne append_done
    push eax
    mov ecx, esi
    call flush_vec3
    pop eax
append_done:
    pop esi
    ret 4
append_vec3 ENDP

ALIGN 16
; ECX=context. No arguments; preserve nonvolatile registers.
; One atomic reservation per batch, followed by exact DWORD copies.
flush_vec3 PROC
    mov edx, DWORD PTR [ecx + 4]
    test edx, edx
    jz flush_done
    push esi
    push edi
    mov esi, ecx
    mov eax, DWORD PTR [esi]
    mov DWORD PTR [esi + 4], 0
    mov ecx, edx
    lock xadd DWORD PTR [eax + 260h], edx
    mov edi, DWORD PTR [eax + 25Ch]
    lea edx, [edx + edx * 2]
    lea edi, [edi + edx * 4]
    lea ecx, [ecx + ecx * 2]
    add esi, 8
    rep movsd
    pop edi
    pop esi
flush_done:
    ret
flush_vec3 ENDP
END
