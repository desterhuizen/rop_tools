# ROP Tools Suite

A comprehensive collection of Python tools for ROP (Return-Oriented Programming)
analysis and exploit development. This suite includes gadget parsing, code cave
discovery, and PE analysis utilities for defensive security research.

## Quick Reference (TL;DR)

### 🔍 **get_rop_gadgets.py** - ROP Gadget Parser & Analyzer

Parse and filter ROP gadgets from rp++ output with advanced categorization,
register analysis, and grouping.

```bash
# Find pop gadgets without bad chars
./get_rop_gadgets.py -f gadgets.txt -i pop -b "\x00\x0a" -m 3

# Group by category and register
./get_rop_gadgets.py -f gadgets.txt -g category-register -l 5

# Find gadgets affecting EAX, sorted by simplicity
./get_rop_gadgets.py -f gadgets.txt --register eax --modified-only --show-count
```

### 📍 **get_base_address.py** - PE Base Address Extractor

Extract ImageBase and detailed PE information from DLL/EXE files.

```bash
# Get ImageBase only
./get_base_address.py kernel32.dll

# Detailed PE info with sections
./get_base_address.py kernel32.dll -v

# Quiet mode for scripting
./get_rop_gadgets.py -f gadgets.txt --offset $(./get_base_address.py msvcrt.dll -q)
```

### 📝 **rop_worksheet.py** - Interactive ROP Chain Worksheet

Track registers, stack values, and build ROP chains interactively with WinDbg
integration.

```bash
# Start worksheet
./rop_worksheet.py

# Import from WinDbg (at crash point in WinDbg: r, then dds esp L20)
importregs   # Paste 'r' output
importstack  # Paste 'dds esp' output

# Build ROP chain
name shellgen 0x00501000
chain 0x10001234 "pop eax ; ret" "Load shellcode addr"
stack +0x00 shellgen
```

---

# ROP Gadget Parser and Analyzer (`get_rop_gadgets.py`)

A powerful Python tool for parsing, filtering, and analyzing ROP (
Return-Oriented Programming) gadgets from rp++ output. This tool provides
advanced categorization, register-based grouping, and filtering capabilities to
make ROP chain construction more efficient.

## Features

- **Gadget Parsing**: Parse rp++ output files and extract gadget information
- **Category-based Classification**: Automatically categorize gadgets by
  functionality
- **Bad Instruction Filtering**: Automatically filter out useless gadgets (call,
  jmp, int, etc.) by default
- **Register Analysis**: Track which registers are affected, modified, or
  dereferenced by gadgets
- **Multi-level Grouping**: Group gadgets by instruction, category, or registers
- **Drill-down Views**: Hierarchical grouping (e.g., category → register)
- **Flexible Filtering**: Filter by instruction, category, register, bad
  characters, and more
- **Exclusion Filtering**: Exclude unwanted gadgets using regex patterns (e.g.,
  exclude specific registers or operations)
- **Regex Search with Highlighting**: Search with patterns and highlight matches
  in bright red
- **Smart Sorting**: Sort by instruction count (simplest first) or by memory
  address
- **Instruction Count Display**: View the number of operations in each gadget at
  a glance
- **Dereferenced Register Filtering**: Find gadgets with memory operations like
  `[eax]`, `[rsp+8]`
- **Colorized Output**: Easy-to-read colored terminal output
- **Statistics**: View comprehensive statistics about your gadget collection

## Project Structure

The tool is organized into a modular architecture for maintainability and
extensibility:

```
pentest-scripts/
├── lib/                        # Shared library (repo-wide)
│   ├── __init__.py
│   └── color_printer.py        # ColorPrinter abstraction (library-independent)
└── rop/
    ├── __init__.py
    ├── get_rop_gadgets.py      # Main CLI entry point and orchestration (~350 lines)
    ├── core/
    │   ├── __init__.py
    │   ├── gadget.py           # Gadget dataclass and analysis methods
    │   ├── parser.py           # ROPGadgetParser class for file parsing
    │   └── categories.py       # GadgetCategory enum and categorization logic
    ├── display/
    │   ├── __init__.py
    │   └── formatters.py       # Output formatting and display functions
    └── requirements.txt
```

**Architecture Benefits:**

- **Separation of Concerns**: Core parsing logic is separate from display logic
- **Easy Testing**: Core modules can be unit tested independently
- **Reusability**: Other tools can import core modules (e.g.,
  `from core import ROPGadgetParser`)
- **Better Maintainability**: Each file has a single, focused responsibility
- **Shared Library**: ColorPrinter lives in `lib/` for use across all pentest
  tools
- **Library Independence**: ColorPrinter abstraction allows easy library swaps (
  currently uses Rich)

**Module Descriptions:**

- `core.gadget`: Gadget dataclass with methods for register analysis and
  instruction inspection
- `core.parser`: ROPGadgetParser class handles file parsing with automatic
  UTF-8/UTF-16 detection
- `core.categories`: Gadget categorization logic (18 categories from stack
  operations to syscalls)
- `lib.color_printer`: Terminal color abstraction that works with or without the
  Rich library (shared across all tools)
- `display.formatters`: High-level display functions for gadgets, groups, and
  statistics

**Shared Library Dependency:**
This tool uses the shared `lib/color_printer` module located at the repository
root. The tool automatically adds the repo root to Python's path, so it works
correctly when run directly or via symlink.

## Installation

### Requirements

- Python 3.6+
- rich (recommended, for colored output)

```bash
# Install from requirements.txt (recommended)
pip install -r requirements.txt

# Or install rich manually for colored output
pip install rich
```

## Usage

### Basic Syntax

```bash
./get_rop_gadgets.py -f <gadget_file> [options]
```

### Common Options

| Option                    | Description                                                                      |
|---------------------------|----------------------------------------------------------------------------------|
| `-f, --file`              | Path to rp++ output file (required)                                              |
| `-i, --instruction`       | Filter by instruction name                                                       |
| `-p, --position`          | Position of instruction to match (any/first/last)                                |
| `-c, --category`          | Filter by gadget category                                                        |
| `-g, --group`             | Group gadgets (first/last/category/register/modified-register/category-register) |
| `-r, --regex`             | Filter by regex pattern in instruction chain                                     |
| `-e, --exclude`           | Exclude gadgets matching this regex pattern                                      |
| `-b, --bad-chars`         | Filter out bad characters                                                        |
| `-m, --max-instructions`  | Maximum number of instructions in gadget                                         |
| `--register`              | Filter by specific register                                                      |
| `--modified-only`         | With --register, only show gadgets that modify the register                      |
| `--deref`                 | Filter gadgets with dereferenced registers (e.g., [eax], [rsp+8])                |
| `-l, --limit`             | Limit number of results displayed per group                                      |
| `-s, --stats`             | Show statistics about gadgets                                                    |
| `--show-category`         | Display category for each gadget                                                 |
| `--show-count`            | Display instruction count for each gadget                                        |
| `--highlight`             | Highlight regex matches in output (requires -r/--regex)                          |
| `--sort`                  | Sort gadgets by count (default) or address                                       |
| `--offset`                | Calculate offset from base address (e.g., 0x10000000)                            |
| `--keep-bad-instructions` | Keep gadgets with bad instructions (call, jmp, int, etc.)                        |
| `--no-color`              | Disable colored output                                                           |

## Gadget Categories

The tool automatically categorizes gadgets into the following types:

| Category        | Description                                |
|-----------------|--------------------------------------------|
| `stack_pivot`   | ESP/RSP manipulation for stack pivoting    |
| `stack_pop`     | Pop instructions                           |
| `stack_push`    | Push instructions                          |
| `load_register` | LEA and load operations                    |
| `move_register` | MOV operations between registers           |
| `xchg_register` | Register exchange operations               |
| `memory_read`   | Memory read operations                     |
| `memory_write`  | Memory write operations                    |
| `arithmetic`    | ADD, SUB, INC, DEC, MUL, DIV, etc.         |
| `logic`         | AND, OR, XOR, NOT, shifts, rotations       |
| `call`          | CALL instructions                          |
| `jmp`           | Jump instructions                          |
| `ret`           | Return instructions                        |
| `conditional`   | Conditional jumps                          |
| `syscall`       | System calls                               |
| `interrupt`     | Interrupt instructions                     |
| `string_ops`    | String operations (MOVS, LODS, STOS, etc.) |
| `other`         | Uncategorized gadgets                      |

## Examples

### Basic Usage

```bash
# Parse and display all gadgets
./get_rop_gadgets.py -f gadgets.txt

# Show statistics
./get_rop_gadgets.py -f gadgets.txt -s
```

### Filtering

```bash
# Find all 'pop' instructions
./get_rop_gadgets.py -f gadgets.txt -i pop

# Find gadgets ending with 'ret'
./get_rop_gadgets.py -f gadgets.txt -i ret -p last

# Filter by category (stack manipulation)
./get_rop_gadgets.py -f gadgets.txt -c stack_pop

# Filter out bad characters and limit to 3 instructions
./get_rop_gadgets.py -f gadgets.txt -b "\x00\x0a" -m 3

# Search with regex pattern
./get_rop_gadgets.py -f gadgets.txt -r "pop.*pop.*ret"
```

### Register-based Filtering

```bash
# Find all gadgets that affect the EAX register
./get_rop_gadgets.py -f gadgets.txt --register eax

# Find gadgets that MODIFY (not just use) the ESP register
./get_rop_gadgets.py -f gadgets.txt --register esp --modified-only

# Find stack_pop gadgets that modify EBX
./get_rop_gadgets.py -f gadgets.txt -c stack_pop --register ebx --modified-only
```

### Grouping

```bash
# Group by last instruction
./get_rop_gadgets.py -f gadgets.txt -g last

# Group by category
./get_rop_gadgets.py -f gadgets.txt -g category

# Group by modified register
./get_rop_gadgets.py -f gadgets.txt -g modified-register

# Group by affected register (includes both source and destination)
./get_rop_gadgets.py -f gadgets.txt -g register
```

### Drill-down Analysis

```bash
# Group by category, then by modified register (hierarchical view)
./get_rop_gadgets.py -f gadgets.txt -g category-register

# Same as above, but limit to 5 gadgets per register group
./get_rop_gadgets.py -f gadgets.txt -g category-register -l 5

# Find stack_pop gadgets grouped by which register they modify
./get_rop_gadgets.py -f gadgets.txt -c stack_pop -g modified-register
```

### Sorting and Display Options

```bash
# Sort by instruction count (default - simplest gadgets first)
./get_rop_gadgets.py -f gadgets.txt --sort count

# Sort by memory address
./get_rop_gadgets.py -f gadgets.txt --sort address

# Show instruction count for each gadget
./get_rop_gadgets.py -f gadgets.txt --show-count

# Combine: show counts and sort by address
./get_rop_gadgets.py -f gadgets.txt --show-count --sort address

# Find simplest pop gadgets with counts displayed
./get_rop_gadgets.py -f gadgets.txt -i pop -m 3 --show-count
```

### Regex Search with Highlighting

```bash
# Search for pattern and highlight matches in bright red
./get_rop_gadgets.py -f gadgets.txt -r "add.*esp" --highlight

# Highlight complex patterns
./get_rop_gadgets.py -f gadgets.txt -r "(add|sub).*(esp|rsp)" --highlight

# Combine highlighting with count display
./get_rop_gadgets.py -f gadgets.txt -r "pop.*pop.*ret" --highlight --show-count

# Highlight with grouping
./get_rop_gadgets.py -f gadgets.txt -r "mov.*eax" --highlight -g category

# Search and highlight memory operations
./get_rop_gadgets.py -f gadgets.txt -r "mov.*\[e[a-z]+\]" --highlight -c memory_write
```

### Dereferenced Register Filtering

```bash
# Find all gadgets with dereferenced registers (e.g., [eax], [rsp+8])
./get_rop_gadgets.py -f gadgets.txt --deref ""

# Find gadgets with dereferenced EAX register
./get_rop_gadgets.py -f gadgets.txt --deref eax

# Group by dereferenced register
./get_rop_gadgets.py -f gadgets.txt -g dereferenced-register

# Find memory write gadgets with dereferenced EAX
./get_rop_gadgets.py -f gadgets.txt -c memory_write --deref eax
```

### Exclusion Filtering

```bash
# Find pop gadgets but exclude any with ESP or EBP (avoid stack pointer operations)
./get_rop_gadgets.py -f gadgets.txt -r "pop" -e "esp|ebp"

# Find mov gadgets but exclude any involving EAX or EBX
./get_rop_gadgets.py -f gadgets.txt -r "mov" -e "eax|ebx"

# Find arithmetic operations excluding specific patterns
./get_rop_gadgets.py -f gadgets.txt -c arithmetic -e "add.*0x"

# Exclude gadgets with dereferenced operations
./get_rop_gadgets.py -f gadgets.txt -i pop -e "\["

# Complex exclusion: find clean gadgets avoiding multiple registers
./get_rop_gadgets.py -f gadgets.txt -c stack_pop -e "(esp|ebp|esi|edi)" -m 3
```

### Bad Instruction Filtering

```bash
# By default, gadgets with bad instructions are filtered out automatically
./get_rop_gadgets.py -f gadgets.txt -i pop

# Keep all gadgets including those with bad instructions (call, jmp, int, etc.)
./get_rop_gadgets.py -f gadgets.txt -i pop --keep-bad-instructions

# The filter removes 44 types of harmful instructions including:
# - Control flow: call, jmp, leave, conditional jumps (ja, jb, jc, je, etc.)
# - Interrupts: int, iret, iretd, cli, sti
# - Privileged ops: hlt, lgdt, lidt, mov cr, mov dr
# - I/O ops: in, out, ins, outs
# - Other: lock, enter, wait, popf, pushf, ???
```

**Why filter bad instructions?**

- `call`/`jmp`: Break ROP chains by transferring control unpredictably
- `int`: Triggers interrupts that crash or behave unexpectedly
- `leave`: Modifies both EBP and ESP, making stack state unpredictable
- Conditional jumps: Non-deterministic behavior breaks reliable ROP chains
- Privileged ops: Cause crashes in user-mode exploits

### Combined Filters

```bash
# Find short pop gadgets without bad chars, show with categories
./get_rop_gadgets.py -f gadgets.txt -i pop -b "\x00\x0a" -m 2 --show-category

# Find arithmetic operations on EAX, grouped by specific operation
./get_rop_gadgets.py -f gadgets.txt -c arithmetic --register eax --modified-only -g first

# Find simplest clean gadgets with instruction counts
./get_rop_gadgets.py -f gadgets.txt -b "\x00\x0a" -m 2 --show-count --sort count
```

## Register Analysis

The tool provides two types of register analysis:

### Affected Registers

Includes **all** registers mentioned in the gadget (both source and
destination):

```bash
# Example: pop eax ; mov ebx, eax ; ret
# Affected registers: eax, ebx
./get_rop_gadgets.py -f gadgets.txt -g register
```

### Modified Registers

Includes **only** registers that are modified (destination operands):

```bash
# Example: pop eax ; mov ebx, eax ; ret
# Modified registers: eax, ebx
./get_rop_gadgets.py -f gadgets.txt -g modified-register
```

### Supported Register Sets

- **32-bit**: eax, ebx, ecx, edx, esi, edi, esp, ebp
- **64-bit**: rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15
- **16-bit**: ax, bx, cx, dx, si, di, sp, bp
- **8-bit**: al, ah, bl, bh, cl, ch, dl, dh

## Output Formats

### Standard Output

```
0x00401000: pop eax ; ret ; (1 found)
0x00401005: pop ebx ; pop ecx ; ret ; (1 found)
```

### With Instruction Count

```
[ 2] 0x00401000: pop eax ; ret ; (1 found)
[ 3] 0x00401005: pop ebx ; pop ecx ; ret ; (1 found)
```

### With Categories

```
[stack_pop] 0x00401000: pop eax ; ret ; (1 found)
[stack_pop] 0x00401005: pop ebx ; pop ecx ; ret ; (1 found)
```

### With Both Count and Category

```
[ 2] [stack_pop] 0x00401000: pop eax ; ret ; (1 found)
[ 3] [stack_pop] 0x00401005: pop ebx ; pop ecx ; ret ; (1 found)
```

### With Regex Highlighting (--highlight)

```
# Matches are shown in bright red (indicated by ^^^^ below)
0x00401234: add esp, 0x10 ; pop ebx ; ret ; (1 found)
            ^^^^^^^^^^^^
            (highlighted in bright red)
```

### Grouped by Category

```
=== Grouped by category ===

--- stack_pop (150 gadgets) ---
0x00401000: pop eax ; ret ; (1 found)
0x00401005: pop ebx ; pop ecx ; ret ; (1 found)
...
```

### Drill-down (Category → Register)

```
=== Grouped by category, then by modified register ===

======================================================================
  STACK_POP (150 total gadgets)
======================================================================

  --- eax (45 gadgets) ---
  0x00401000: pop eax ; ret ; (1 found)
  ...

  --- ebx (38 gadgets) ---
  0x00401005: pop ebx ; ret ; (1 found)
  ...
```

## Statistics Output

```bash
./get_rop_gadgets.py -f gadgets.txt -s
```

Displays:

- Total gadgets found
- Unique addresses
- File metadata (DLL name, architecture, format)
- Top 10 last instructions
- Gadget distribution by category

## Generating ROP Gadgets with rp++

Before using this tool, generate gadgets with rp++:

```bash
# Windows x86
rp-win-x86.exe -f target.exe -r 5 > gadgets.txt

# Linux x64
rp-lin-x64 -f target.bin -r 5 > gadgets.txt

# macOS
rp-osx -f target.dylib -r 5 > gadgets.txt
```

Parameters:

- `-f`: Target file
- `-r`: Maximum gadget depth (number of instructions)

## Use Cases

### 1. Finding Basic ROP Chain Components

```bash
# Find pop-pop-ret sequences
./get_rop_gadgets.py -f gadgets.txt -r "pop.*pop.*ret" -m 3

# Find ways to control EAX
./get_rop_gadgets.py -f gadgets.txt --register eax --modified-only -g category
```

### 2. Stack Pivot Discovery

```bash
# Find stack pivot gadgets
./get_rop_gadgets.py -f gadgets.txt -c stack_pivot

# Find ESP/RSP manipulation
./get_rop_gadgets.py -f gadgets.txt --register esp --modified-only
```

### 3. Building Complex Chains

```bash
# Find arithmetic operations by register
./get_rop_gadgets.py -f gadgets.txt -c arithmetic -g modified-register

# Find memory write gadgets by register
./get_rop_gadgets.py -f gadgets.txt -c memory_write -g category-register -l 3
```

### 4. Avoiding Bad Characters

```bash
# Find gadgets without null bytes and newlines
./get_rop_gadgets.py -f gadgets.txt -b "\x00\x0a\x0d" -c stack_pop

# Find clean short gadgets
./get_rop_gadgets.py -f gadgets.txt -b "\x00\x0a\x0d\x20" -m 2 -g category
```

## Tips and Tricks

1. **Start broad, then narrow**: Begin with category grouping, then drill down
   by register
   ```bash
   ./get_rop_gadgets.py -f gadgets.txt -g category
   ./get_rop_gadgets.py -f gadgets.txt -c stack_pop -g modified-register
   ```

2. **Use limits for large datasets**: When dealing with many gadgets, use `-l`
   to limit output
   ```bash
   ./get_rop_gadgets.py -f gadgets.txt -g category-register -l 5
   ```

3. **Combine filters**: Stack multiple filters for precise results
   ```bash
   ./get_rop_gadgets.py -f gadgets.txt -c stack_pop -b "\x00" -m 2 --register eax
   ```

4. **Save filtered results**: Redirect output to file for later use
   ```bash
   ./get_rop_gadgets.py -f gadgets.txt -c stack_pop --no-color > clean_pops.txt
   ```

5. **Check statistics first**: Understand your gadget landscape before filtering
   ```bash
   ./get_rop_gadgets.py -f gadgets.txt -s
   ```

## Performance Considerations

- Large gadget files (>10,000 gadgets) may take a few seconds to parse
- The `category-register` grouping mode performs nested analysis and may be
  slower
- Use specific filters to reduce the working set before grouping
- Consider using `-l` to limit output for exploration

## Troubleshooting

### No gadgets found

- Verify the input file is valid rp++ output
- Check that the file path is correct
- Ensure the file contains the expected format

### Colors not displaying

- Install rich: `pip install rich`
- Or use `--no-color` flag

### Too many results

- Use `-l` to limit output
- Add more specific filters
- Use categories to narrow down

### Register not being detected

- Verify register name spelling (lowercase)
- Check if the register appears in the supported list
- Some complex memory operands may not be detected

### Offset Calculation

```bash
# Display gadgets with offset from module base address
./get_rop_gadgets.py -f gadgets.txt -i pop --offset 0x10000000

# Use with get_base_address.py to get the base automatically
BASE=$(./get_base_address.py msvcrt.dll | grep ImageBase | awk '{print $3}')
./get_rop_gadgets.py -f gadgets.txt -i pop --offset $BASE
```

**Output Format with Offset:**

```
0x10001234 (+0x1234): pop eax ; ret ; (1 found)
0x10001240 (+0x1240): pop ebx ; pop ecx ; ret ; (1 found)
```

The offset is displayed in magenta color and shows the distance from the base
address, making it easier to calculate relative addresses for ASLR-enabled
systems.

---

# PE Base Address Extractor (`get_base_address.py`)

Extract ImageBase (preferred load address) and detailed PE information from PE
files (DLL/EXE). Now refactored to use the same shared libraries as
`get_rop_gadgets.py` for consistent, colorized output.

## Features

- **ImageBase Extraction**: Get the preferred load address from PE files
- **Detailed PE Information**: View entry point, machine type, subsystem, and
  sections
- **Section Analysis**: Display section addresses, sizes, and protection flags
- **Colored Output**: Uses the same ColorPrinter library as other ROP tools
- **Scripting Support**: Quiet mode for use in scripts and automation
- **Modular Architecture**: Built on `core.pe_info` module for extensibility

## Project Structure

```
rop/
├── core/
│   ├── pe_info.py          # PE analysis module (PEAnalyzer, PEInfo, PESection)
│   └── ...
└── get_base_address.py     # CLI tool using core.pe_info
```

## Usage

### Basic Usage

```bash
# Get ImageBase only
./get_base_address.py <PE_FILE>

# Show detailed information including sections
./get_base_address.py <PE_FILE> -v

# Quiet mode for scripting (prints only hex address)
./get_base_address.py <PE_FILE> -q

# Disable colored output
./get_base_address.py <PE_FILE> --no-color
```

### Command-Line Options

| Option          | Description                                     |
|-----------------|-------------------------------------------------|
| `file`          | PE file to analyze (DLL or EXE)                 |
| `-v, --verbose` | Show detailed PE information including sections |
| `-q, --quiet`   | Only print ImageBase address (for scripting)    |
| `--no-color`    | Disable colored output                          |

## Examples

### Example 1: Basic Information

```bash
./get_base_address.py kernel32.dll
```

**Output:**

```
=== PE File Information ===

File: kernel32.dll
ImageBase: 0x76d40000
Decimal: 1993932800
```

### Example 2: Detailed PE Information

```bash
./get_base_address.py kernel32.dll -v
```

**Output:**

```
=== PE File Information ===

File: kernel32.dll
ImageBase: 0x76d40000
Decimal: 1993932800
Entry Point (RVA): 0x1234
Entry Point (Absolute): 0x76d41234
Machine Type: x86 (I386)
Subsystem: WINDOWS_GUI

=== Sections ===

Name          Virtual Addr    Virtual Size    Raw Size        Flags
.text         0x00001000      0x00050000      0x00050000      EXECUTABLE, READABLE, CODE
.rdata        0x00051000      0x00020000      0x00020000      READABLE, INITIALIZED_DATA
.data         0x00071000      0x00010000      0x00005000      READABLE, WRITABLE, INITIALIZED_DATA
.rsrc         0x00081000      0x00008000      0x00008000      READABLE, INITIALIZED_DATA
```

### Example 3: Quiet Mode for Scripting

```bash
# Get just the hex address
BASE=$(./get_base_address.py kernel32.dll -q)
echo $BASE
# Output: 0x76d40000

# Use with get_rop_gadgets.py
./get_base_address.py kernel32.dll -q | xargs -I {} ./get_rop_gadgets.py -f gadgets.txt --offset {}

# Or inline
./get_rop_gadgets.py -f gadgets.txt --offset $(./get_base_address.py kernel32.dll -q)
```

### Example 4: Section Analysis

```bash
./get_base_address.py target.exe -v
```

The verbose mode displays:

- Section names and addresses
- Virtual and raw sizes
- Section flags (EXECUTABLE, READABLE, WRITABLE, CODE, INITIALIZED_DATA, etc.)

This helps identify executable sections for code cave discovery or ROP gadget
location.

### Example 5: Import Address Table (IAT) Display

```bash
# Show all imported functions
./get_base_address.py target.exe --iat
```

**Output:**

```
=== Import Address Table (IAT) ===

Total Imports: 245

[kernel32.dll] - 78 imports
  CreateFileA                               RVA: 0x00003000  Abs: 0x76d43000
  ReadFile                                  RVA: 0x00003004  Abs: 0x76d43004
  WriteFile                                 RVA: 0x00003008  Abs: 0x76d43008
  ...

[ntdll.dll] - 42 imports
  NtCreateFile                              RVA: 0x00003100  Abs: 0x76d43100
  NtReadFile                                RVA: 0x00003104  Abs: 0x76d43104
  ...
```

### Example 6: Filter IAT by DLL

```bash
# Show only kernel32.dll imports
./get_base_address.py target.exe --iat --dll kernel32

# Show only msvcrt.dll imports
./get_base_address.py target.exe --iat --dll msvcrt
```

When viewing the full IAT (without `--dll` filter), a **DEP Bypass Candidates**
section automatically appears showing any DEP bypass APIs found in the IAT
(VirtualProtect, VirtualAlloc, WriteProcessMemory, HeapCreate, etc.) with their
IAT addresses, bypass technique descriptions, and argument reference for building
ROP chains.

This is useful for:

- Finding API function addresses for ROP chains
- Identifying DEP bypass candidates with argument reference
- Identifying imported functions for exploit development
- Calculating absolute addresses at preferred base
- Locating specific DLL functions quickly

## Module Usage (Python API)

The tool is built on the `core.pe_info` module, which can be imported and used
in your own scripts:

```python
from core import PEAnalyzer, PEInfo, PESection

# Quick base address extraction
base_address = PEAnalyzer.get_base_address("kernel32.dll")
print(f"ImageBase: 0x{base_address:x}")

# Full PE analysis
pe_info = PEAnalyzer.analyze_file("kernel32.dll")
print(f"ImageBase: 0x{pe_info.image_base:x}")
print(f"Entry Point: 0x{pe_info.entry_point:x}")
print(f"Machine: {pe_info.machine_type}")

# Iterate through sections
for section in pe_info.sections:
    print(f"{section.name}: 0x{section.virtual_address:08x}")
    flags = section.get_characteristics_flags()
    print(f"  Flags: {', '.join(flags)}")
```

## Output Formats

### Basic Output (Default)

Colored output showing ImageBase in both hex and decimal formats.

### Verbose Output (-v)

Includes:

- Entry point (both RVA and absolute address)
- Machine type (x86, x64, ARM, etc.)
- Subsystem (GUI, console, native, etc.)
- Section table with addresses, sizes, and protection flags

### Quiet Output (-q)

Single line with hex address only, perfect for scripting and automation.

## Integration with Other Tools

```bash
# Extract base address and use in ROP gadget analysis
BASE=$(./get_base_address.py msvcrt.dll -q)
./get_rop_gadgets.py -f gadgets.txt --offset $BASE

# Find code caves in executable sections
./get_base_address.py target.exe -v | grep EXECUTABLE
```

## Requirements

```bash
pip install pefile rich
```

**Note:** Rich is optional but recommended for colored output. The tool will
work without it but fall back to plain text.

## Technical Notes

- **Preferred vs. Actual Address**: This tool returns the **preferred** base
  address from the PE header. At runtime, Windows ASLR may load the module at a
  different address. Use a debugger to find the actual runtime address.

- **Machine Types Supported**: x86 (I386), x64 (AMD64), ARM, ARM64, ARM Thumb-2

- **Section Flags**: The tool decodes section characteristics including
  EXECUTABLE, READABLE, WRITABLE, CODE, INITIALIZED_DATA, UNINITIALIZED_DATA

## Use Cases

1. **ROP Chain Development**: Calculate gadget offsets relative to module base
2. **Code Cave Discovery**: Identify executable sections and their addresses
3. **Exploit Development**: Determine module base addresses for ASLR
   calculations
4. **Binary Analysis**: Quick PE metadata extraction for security research
5. **Automation**: Quiet mode enables scripting and batch processing

---

# ROP Chain Worksheet (`rop_worksheet.py`)

An interactive terminal-based tool for tracking register states, stack values,
and building ROP chains. This worksheet provides a visual, hands-on environment
for planning and testing ROP exploits with real-time state tracking.

## Features

- **Register Tracking**: Monitor all 32-bit x86 registers (EAX, EBX, ECX, EDX,
  ESI, EDI, EBP, ESP, EIP) plus 8/16-bit sub-registers (AL/AH/AX, BL/BH/BX,
  CL/CH/CX, DL/DH/DX, SI, DI, BP, SP)
    - Sub-register reads mask the parent; writes merge back into the parent
    - EIP displayed separately with bold green highlighting for gadget addresses
    - Named value matching shown in third column when registers match symbolic
      names
- **Stack Management**: Track stack values at different ESP offsets
    - Absolute addresses displayed alongside ESP-relative offsets
    - Register-based stack addressing (e.g., `stack ECX, EAX` when ECX points to
      stack)
    - Named value matching shown in fourth column for stack values
- **Named Values**: Create symbolic names for addresses (e.g., "shellcode", "
  base_address")
- **ASM Operations**: Execute assembly-like operations with full sub-register support
    - **Data movement**: mov, movzx, movsxd, lea, push, pop, next
    - **Arithmetic**: add, sub, inc, dec, neg
    - **Bitwise**: and, or, xor, not, shl, shr, ror, rol
    - **Exchange**: xchg
    - **Zero-operand**: cdq, lodsd, stosd, nop
- **ROP Chain Building**: Build and visualize your ROP chain with addresses,
  gadgets, and effects
- **Value Resolution**: Automatic resolution of register names, stack offsets,
  and named values
- **Arithmetic Support**: Perform arithmetic on values (e.g., `shellcode+0x100`)
- **WinDbg Integration**: Import register and stack state directly from WinDbg
  output
- **Save/Load**: Persist your worksheets to JSON files for later use
- **Command History**: Navigate previous commands with up/down arrows
- **Tab Completion**: Auto-complete commands, registers, and values

## Requirements

```bash
pip install rich
```

## Usage

### Starting the Worksheet

```bash
./rop_worksheet.py
```

### Command Categories

#### ASM Operations (Intel Syntax)

```bash
# Move operations
mov EAX, 0xdeadbeef          # Set EAX to value
mov EAX, EBX                 # Copy EBX to EAX
mov AL, 0x41                 # Write to sub-register (merges into EAX)
mov EAX, ESP+0x10            # Move stack value to EAX
movzx EAX, CL               # Zero-extend 8-bit CL into EAX
movsxd EAX, AL               # Sign-extend 8-bit AL into EAX

# Arithmetic
add EAX, 0x100               # EAX = EAX + 0x100
sub EAX, 0x10                # EAX = EAX - 0x10
xor EAX, EAX                 # Zero out EAX
inc EAX                      # EAX++
dec EAX                      # EAX--
neg EAX                      # Two's complement negation

# Bitwise
and ESP, 0xfffffff0          # Align stack to 16-byte boundary
or EAX, 0x40                 # Set bit 6
not EAX                      # Bitwise complement
shl EAX, 0x04                # Shift left by 4 (multiply by 16)
shr EAX, 0x08                # Logical shift right by 8
ror EAX, 0x0d                # Rotate right (e.g., ROR13 hash)
rol EAX, 0x08                # Rotate left

# LEA (address computation without memory access)
lea EAX, [ECX+0x10]          # EAX = ECX + 0x10
lea EAX, [ECX+EDX*4]         # EAX = ECX + EDX*4
lea EAX, [ECX+EDX*4+0x08]   # EAX = ECX + EDX*4 + 0x08

# Zero-operand
cdq                          # Sign-extend EAX into EDX (zeros EDX if EAX < 0x80000000)
lodsd                        # EAX = [ESI]; ESI += 4
stosd                        # [EDI] = EAX; EDI += 4
nop                          # No operation

# Stack operations
push EAX                     # Push EAX onto stack (ESP -= 4, [ESP] = EAX)
pop EBX                      # Pop from stack into EBX ([EBX] = [ESP], ESP += 4)
alnext                         # Pop EIP — step to next gadget (alias: n, Ctrl+N)
```

#### Quick Operations

```bash
# Direct value setting
set EAX 0xdeadbeef          # Set register directly
set ESP+0x10 0x12345678     # Set stack value directly
clr EAX                     # Clear register

# Named values
name shellgen 0x00501000   # Create named value
name base 0x10000000        # Name a base address
mov EAX, shellgen+0x100    # Use arithmetic with named values
```

#### Import from WinDbg

```bash
# Import registers from WinDbg output
importregs
# Paste output like:
# eax=00000001 ebx=00000000 ecx=005cdeaa edx=0000034e esi=005c1716 edi=010237f8
# eip=41414141 esp=01bd744c ebp=005c4018 iopl=0         nv up ei pl nz na pe nc
# [press Enter on empty line]
# ✓ Imported 7 register(s)

# Import stack dump from WinDbg
importstack
# Paste output like:
# 01bd744c  1012b413 10168060 1014dc4c 10154399
# 01bd745c  ffffc360 100fcd71 10154399 ffffffd0
# 01bd746c  101268fd 10141122 1012b413 100fcd71
# [press Enter on empty line]
# ✓ Imported 12 stack value(s)
```

**Note**: For `importstack`, ESP must be set first (either via `importregs` or
manually with `set ESP <value>`). The tool calculates stack offsets relative to
ESP.

#### Chain Management

```bash
# Add gadgets to ROP chain
chain 0x10001234 "pop eax ; ret" "EAX ← [ESP]"
chain 0x10005678 "add esp, 0x10 ; ret" "Stack cleanup"

# Remove chain entries
del 1                       # Remove first entry
del 3                       # Remove third entry
```

#### Workflow Commands

```bash
v                           # View/refresh worksheet display
save rop_chain.json         # Save worksheet
load rop_chain.json         # Load worksheet
new                         # Start new blank worksheet
notes                       # Add/edit notes
help                        # Show help
quit                        # Exit
```

## Examples

### Example 1: Import from WinDbg and Build ROP Chain

```bash
# In WinDbg, at your crash/breakpoint:
# r                    (copy register output)
# dds esp L20          (copy stack dump)

# In rop_worksheet.py:
importregs
# Paste:
# eax=00000001 ebx=00000000 ecx=005cdeaa edx=0000034e esi=005c1716 edi=010237f8
# eip=41414141 esp=01bd744c ebp=005c4018 iopl=0         nv up ei pl nz na pe nc
# (press Enter)
# ✓ Imported 7 register(s)

importstack
# Paste:
# 01bd744c  1012b413 10168060 1014dc4c 10154399
# 01bd745c  ffffc360 100fcd71 10154399 ffffffd0
# (press Enter)
# ✓ Imported 12 stack value(s)

# Now build your ROP chain with actual crash state!
name shellgen 0x00501000
chain 0x10001234 "pop eax ; ret" "Load shellcode addr"
stack +0x00 shellgen
```

### Example 2: Basic ROP Chain Building

```bash
# Set up initial values
name shellgen 0x00501000
name base 0x10000000
set ESP 0x00000000

# Build a simple ROP chain to call shellgen
chain 0x10001234 "pop eax ; ret" "Load shellcode addr"
stack +0x00 shellgen

chain 0x10002345 "jmp eax" "Jump to shellcode"

# Track register changes
mov EAX, ESP+0x00
pop EAX
```

### Example 3: Stack Pivot

```bash
# Set up environment
set ESP 0x00000000
name pivot_addr 0x00500000

# Create pivot chain
chain 0x10003456 "pop esp ; ret" "Pivot stack"
stack +0x00 pivot_addr

# Execute pivot
mov ESP, pivot_addr
```

### Example 4: Register Arithmetic

```bash
# Calculate target address
name base 0x10000000
mov EAX, base
add EAX, 0x1234              # EAX = 0x10001234

# XOR encoding
mov EBX, 0xdeadbeef
xor EBX, 0x12345678          # Encode value
```

### Example 5: Complex Chain with Multiple Gadgets

```bash
# Set up base addresses
name kernel32 0x76d40000
name ntdll 0x77200000
name shellgen 0x00501000

# Build WriteProcessMemory ROP chain
set ESP 0x00000000

# Load function address
chain 0x76d41234 "pop eax ; ret" "Load WPM addr"
stack +0x00 kernel32+0x12340

# Set up arguments on stack
stack +0x04 0xffffffff       # hProcess = -1 (current)
stack +0x08 shellgen        # lpBaseAddress
stack +0x0c 0x00502000       # lpBuffer (our shellgen)
stack +0x10 0x00000100       # nSize = 256 bytes
stack +0x14 0x00000000       # lpNumberOfBytesWritten = NULL

# Call function
chain 0x76d45678 "call eax" "Call WriteProcessMemory"
```

## Display

The worksheet shows four main sections:

1. **REGISTERS**: Current state of all x86 registers
2. **STACK**: Values at different ESP offsets
3. **NAMED VALUES**: Symbolic names and their addresses
4. **ROP CHAIN**: Sequence of gadgets with addresses and effects

## Value Resolution

The tool automatically resolves:

- **Hex values**: `0x12345678`
- **Registers**: `EAX`, `EBX`, etc.
- **Stack offsets**: `ESP+0x10`, `[ESP+0x10]`
- **Named values**: `shellcode`, `base_address`
- **Arithmetic**: `shellcode+0x100`, `base-0x50`

## Keyboard Shortcuts

- **↑ / ↓**: Navigate command history
- **TAB**: Auto-complete commands, registers, named values
- **Ctrl+N**: Step to next gadget (pop EIP)
- **Ctrl+C**: Cancel current command (doesn't exit)

## File Format

Worksheets are saved as JSON files with the following structure:

```json
{
  "registers": {
    "EAX": "0xdeadbeef",
    "EBX": "0x00000000",
    ...
  },
  "stack": {
    "+0x00": "0x12345678",
    "+0x04": "0x00501000",
    ...
  },
  "named": {
    "shellcode": "0x00501000",
    "base": "0x10000000"
  },
  "chain": [
    {
      "addr": "0x10001234",
      "gadget": "pop eax ; ret",
      "effect": "EAX ← [ESP]"
    }
  ],
  "notes": "ROP chain for exploit X"
}
```

## Use Cases

### 1. ROP Chain Planning

Visualize and plan your ROP chain before writing exploit code. Track register
states at each gadget to ensure correct values.

### 2. Exploit Development

Build and test ROP chains interactively. Verify register and stack states at
each step.

### 3. Educational Tool

Learn ROP techniques by experimenting with gadgets and seeing real-time state
changes.

### 4. Documentation

Save worksheets as documentation for your exploits. Share ROP chains with clear
annotations.

## Tips

1. **Use Named Values**: Create names for important addresses to make chains
   more readable
2. **Track ESP Carefully**: Pay attention to ESP changes, especially with
   push/pop operations
3. **Add Effects**: Document what each gadget does in the "effect" field for
   clarity
4. **Save Frequently**: Save your work regularly to avoid losing progress
5. **Use Tab Completion**: Speed up your workflow by using TAB to complete
   commands and values

## Integration with Other Tools

```bash
# Extract base address and use in worksheet
./get_base_address.py kernel32.dll
# Then in worksheet:
> name kernel32 0x76d40000

# Find gadgets and add to chain
./get_rop_gadgets.py -f gadgets.txt -i "pop eax" -m 2
# Copy addresses into worksheet chain commands
```

## Defensive Security Use

This tool is designed for **defensive security analysis only**:

- Understanding ROP exploit techniques
- Analyzing malware ROP chains
- Developing exploit mitigations
- Security research and education
- Testing detection systems

---

# Installation

## All Tools

```bash
# Install all dependencies
pip install -r requirements.txt
```

## Individual Tools

```bash
# ROP Gadget Parser only
pip install rich

# PE Base Address Extractor only
pip install pefile

# Code Cave Scanner
# Requires PyKD extension in WinDbg (no pip packages needed)
```

---

## See Also

- [rp++ Documentation](https://github.com/0vercl0k/rp)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
- [Ropper](https://github.com/sashs/Ropper)
- [PyKD Documentation](https://githomeassistant.com/0vercl0k/pykd)