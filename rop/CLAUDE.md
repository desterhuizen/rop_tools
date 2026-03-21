# Claude AI Development Notes

This document tracks features, improvements, and development history for the ROP Tools Suite that were implemented with assistance from Claude AI.

---

## Current Tool Architecture (March 2026)

### Modular Structure

All tools now use a shared, modular architecture for better maintainability:

```
pentest-scripts/
├── lib/                        # Shared library (repo-wide)
│   ├── __init__.py
│   └── color_printer.py        # ColorPrinter abstraction (library-independent)
└── rop/
    ├── __init__.py
    ├── get_rop_gadgets.py      # Main CLI (~350 lines)
    ├── get_base_address.py     # PE base address extractor
    ├── rop_worksheet.py        # Interactive ROP worksheet
    ├── core/
    │   ├── __init__.py
    │   ├── gadget.py           # Gadget dataclass + analysis
    │   ├── parser.py           # ROPGadgetParser class
    │   ├── categories.py       # GadgetCategory enum + logic
    │   └── pe_info.py          # PE analysis (PEAnalyzer, PEInfo, PESection)
    ├── display/
    │   ├── __init__.py
    │   └── formatters.py       # Output formatting functions
    └── requirements.txt
```

**Architecture Benefits:**
- Separation of concerns (core vs display)
- Easy unit testing
- Code reusability across tools
- Shared ColorPrinter library for consistent output
- Library independence (easy to swap Rich for another library)

---

## Recent Refactoring (March 2026)

### Bad Instruction Filtering (get_rop_gadgets.py)
**Status**: ✅ Complete
**Date**: March 20, 2026

**Changes:**
- Added `BAD_INSTRUCTIONS` list with 44 harmful instructions that break ROP chains
- Implements automatic filtering by default to remove useless gadgets
- Added `--keep-bad-instructions` flag to optionally disable filtering
- Filter checks for: privileged instructions, control register ops, I/O ops, interrupts, control flow (call/jmp/conditional jumps), and other problematic instructions

**Benefits:**
- Cleaner gadget output focused on usable ROP primitives
- Reduces noise when searching for exploitable gadgets
- Opt-out design allows viewing all gadgets when needed
- Informative output shows how many gadgets were filtered

**Bad Instructions List:**
- Privileged: clts, hlt, lmsw, ltr, lgdt, lidt, lldt
- Control registers: mov cr, mov dr, mov tr
- I/O: in, ins, out, outs, invlpg, invd
- Interrupts/flags: cli, sti, popf, pushf, int, iret, iretd
- Control flow: call, jmp, leave, ja-jz (all conditional jumps)
- Other: lock, enter, wait, swapgs, wbinvd, ???

**Files Modified:**
- Modified: `rop/get_rop_gadgets.py` (added BAD_INSTRUCTIONS list and filtering logic)

---

### IAT Display Feature (get_base_address.py)
**Status**: ✅ Complete
**Date**: March 16, 2026

**Changes:**
- Added `--iat` flag to display Import Address Table information
- Added `--dll` filter to show imports from specific DLL only
- Displays function names, RVAs, and absolute addresses
- Groups imports by DLL for organized output
- Shows both named imports and ordinal imports
- Integrated with ColorPrinter for consistent formatting

**Benefits:**
- Quick identification of imported functions for ROP/exploit development
- Calculate absolute addresses of API functions at preferred base
- Filter by DLL to find specific imports (e.g., kernel32.dll)
- Useful for finding gadgets in imported library code

**Usage Examples:**
```bash
# Show all imports
./get_base_address.py target.exe --iat

# Show only kernel32.dll imports
./get_base_address.py target.exe --iat --dll kernel32

# Combine with verbose mode
./get_base_address.py target.exe -v --iat
```

**Files Modified:**
- Modified: `rop/get_base_address.py` (added IAT display functionality)
- Modified: `rop/core/pe_info.py` (added IATEntry dataclass and get_iat_entries method)

---

### get_base_address.py Refactor
**Status**: ✅ Complete
**Date**: March 16, 2026

**Changes:**
- Created `core/pe_info.py` module with PESection, PEInfo dataclasses and PEAnalyzer class
- Completely rewrote `get_base_address.py` to use argparse and ColorPrinter
- Added verbose mode (`-v`) for detailed PE info (entry point, machine type, sections)
- Added quiet mode (`-q`) for scripting
- Added `--no-color` flag
- Integrated with shared `lib/color_printer` module

**Benefits:**
- Consistent output with `get_rop_gadgets.py`
- Reusable PE analysis module
- Better CLI with argparse
- Scripting-friendly quiet mode

**Files Modified:**
- Created: `rop/core/pe_info.py`
- Modified: `rop/core/__init__.py` (added PE class exports)
- Rewrote: `rop/get_base_address.py`

---

## get_rop_gadgets.py - Key Features

### Core Features

1. **Automatic Encoding Detection** (UTF-8/UTF-16)
   - Detects BOM (Byte Order Mark)
   - Heuristic detection based on null byte patterns
   - Handles Windows rp++ output (UTF-16) and Unix tools (UTF-8) automatically

2. **Gadget Categorization** (18 categories)
   - Stack operations (pivot, pop, push)
   - Register operations (load, move, xchg)
   - Memory operations (read, write)
   - Arithmetic and logic operations
   - Control flow (call, jmp, ret, conditional, syscall, interrupt)
   - String operations

3. **Advanced Filtering**
   - By instruction (`-i`), category (`-c`), register (`--register`)
   - Regex search (`-r`) with highlighting (`--highlight`)
   - Exclusion filtering (`-e`) to remove unwanted gadgets
   - Bad character filtering (`-b`)
   - Dereferenced register filtering (`--deref`)
   - Max instruction count (`-m`)

4. **Register Analysis**
   - **Affected registers**: All registers mentioned (source + destination)
   - **Modified registers**: Only destination operands
   - Supports 32-bit, 64-bit, 16-bit, and 8-bit registers

5. **Multi-level Grouping**
   - Group by instruction (first/last)
   - Group by category
   - Group by register (affected/modified/dereferenced)
   - **Drill-down**: category → register (hierarchical view)

6. **Display Options**
   - Instruction count display (`--show-count`)
   - Category display (`--show-category`)
   - Smart sorting (by count or address, `--sort`)
   - Regex match highlighting in bright red (`--highlight`)
   - Offset calculation from base address (`--offset`)
   - Colored output with `--no-color` fallback

7. **Statistics**
   - Total gadgets and unique addresses
   - File metadata (DLL name, architecture, format)
   - Top 10 last instructions
   - Gadget distribution by category

---

## rop_worksheet.py - Interactive ROP Chain Building

### Core Features

1. **Register Tracking**
   - All 32-bit x86 registers (EAX-ESP, EIP)
   - EIP displayed separately with bold green highlighting
   - Named value matching in third column

2. **Stack Management**
   - ESP-relative offsets (+0x00, +0x04, etc.)
   - Absolute addresses displayed alongside offsets
   - Register-based stack addressing (`stack ECX, EAX`)
   - Named value matching in fourth column

3. **ASM-like Operations** (Intel Syntax)
   - `mov`, `add`, `xor`, `xchg`, `inc`, `dec`, `neg`
   - `push`/`pop` with automatic ESP tracking
   - Value resolution (registers, stack offsets, named values, arithmetic)

4. **WinDbg Integration**
   - `importregs`: Import register state from WinDbg `r` output
   - `importstack`: Import stack dump from WinDbg `dds esp` output
   - Multi-line paste support
   - Automatic ESP-relative offset calculation

5. **ROP Chain Building**
   - Add gadgets with `chain <addr> "<gadget>" "<effect>"`
   - Delete chain entries with `del <index>`
   - Visual display of complete chain

6. **Workflow**
   - Save/load worksheets as JSON
   - Command history (up/down arrows)
   - Tab completion (commands, registers, named values)
   - Named values for symbolic addresses

### Bug Fixes (March 15, 2026)

1. **Push/Pop Stack Offset Bug**
   - Problem: Push/pop used absolute addresses instead of ESP-relative offsets
   - Solution: Changed to ESP-relative offsets with automatic adjustment

2. **Value Resolution Fixes**
   - Fixed `stack` and `set` commands to resolve register names
   - Fixed comma parsing in `stack` command

3. **EIP Register Tracking**
   - Added EIP to register tracking (previously skipped)
   - EIP displayed separately with visual separator

4. **New Features**
   - `xchg` instruction for swapping values
   - Stack address column (absolute addresses)
   - Named value matching columns (registers and stack)
   - Register-based stack addressing

---

## Version History

### Version 3.3.0 (March 2026) - Bad Instruction Filtering & IAT Display
- Added automatic bad instruction filtering to get_rop_gadgets.py
- BAD_INSTRUCTIONS list with 44 harmful instructions
- Added --keep-bad-instructions flag to optionally disable filter
- Added --iat flag to get_base_address.py for Import Address Table display
- Added --dll filter to show imports from specific DLL
- IAT display shows function names, RVAs, and absolute addresses

### Version 3.2.0 (March 2026) - Shared Library Migration
- Extracted ColorPrinter to shared `lib/` directory
- Created `lib/color_printer.py` for use across all pentest tools
- Updated imports in `display/` module
- Tool now works correctly with symlinks

### Version 3.1.0 (March 2026) - Modular Architecture
- Completed major refactoring to modular architecture
- Extracted code into focused modules: `core/` and `display/`
- Reduced main file to ~350 lines (orchestration only)
- Improved maintainability and testability

### Version 3.0.0 (March 2026) - Library Migration
- Migrated from colorama to Rich library
- Created ColorPrinter abstraction layer
- Updated all display functions to use Rich Text objects
- Improved fallback handling when Rich is not available

### Version 2.5.0 (March 2026) - Offset Calculation
- Added `--offset` option for calculating offsets from module base address
- Created `get_base_address.py` helper script

### Version 2.4.0 (March 2026) - Encoding Detection
- Added automatic UTF-8/UTF-16 encoding detection
- Seamlessly handles Windows and Unix rp++ output

### Version 2.3.0 (March 2026) - Exclusion Filtering
- Added `-e/--exclude` option for exclusion filtering

### Version 2.2.0 (March 2026) - Regex Highlighting
- Added `--highlight` option for regex match highlighting in bright red

### Version 2.1.0 (March 2026) - Sorting and Count Display
- Added `--sort` option (count/address modes)
- Added `--show-count` option for instruction count display

### Version 2.0.0 (Earlier) - Core Features
- Added dereferenced register filtering
- Added category-register drill-down grouping
- Enhanced register analysis
- Added colorized output and comprehensive categorization

---

## Development Guidelines

### When Extending Tools

1. **Maintain Consistency**: Follow existing naming conventions and code style
2. **Update Documentation**: Always update README.md and CLAUDE.md
3. **Test Thoroughly**: Test with various inputs and edge cases
4. **Preserve Compatibility**: Don't break existing command-line interfaces
5. **Color Support**: Ensure features work both with and without colored output
6. **Performance**: Consider performance impact on large files (10,000+ gadgets)

### Module Organization

- **core/**: Business logic, data structures, parsing
  - Should have no terminal dependencies
  - Should be testable independently
  - Should be importable by other tools

- **display/**: Output formatting, colors, terminal rendering
  - Depends on core modules
  - Uses lib/color_printer for consistent output
  - Handles colored and non-colored modes

- **lib/**: Shared libraries across all pentest tools
  - color_printer: Terminal color abstraction
  - Located at repo root for cross-tool access

### Testing Approach

1. **Unit Tests**: Test core modules independently (parser, categorizer, etc.)
2. **Integration Tests**: Test CLI with various command combinations
3. **Edge Cases**: Empty files, large files, invalid input, encoding issues
4. **Cross-platform**: Test on Windows, Linux, macOS if possible

---

## Technical Implementation Notes

### ColorPrinter Abstraction

Located in `lib/color_printer.py`, provides library-independent interface:

```python
# Current implementation uses Rich, but can be swapped
printer.print_header("Header Text", "bold green")
printer.print_labeled("Label", "Value", label_style="cyan", value_style="white")
printer.print_text("Text", "bold red")
printer.disable()  # Disable colors
```

### ROPGadgetParser

Located in `core/parser.py`, handles file parsing:

```python
from core import ROPGadgetParser

parser = ROPGadgetParser(gadget_file)
gadgets = parser.parse()  # Returns list of Gadget objects

# Filtering
filtered = parser.filter_by_instruction("pop", gadgets)
filtered = parser.filter_by_category(GadgetCategory.STACK_POP, gadgets)
filtered = parser.filter_by_register("eax", gadgets, modified_only=True)

# Grouping
grouped = parser.group_by_category(gadgets)
grouped = parser.group_by_register(gadgets)
```

### PEAnalyzer

Located in `core/pe_info.py`, handles PE file analysis:

```python
from core import PEAnalyzer, PEInfo

# Quick base address extraction
base = PEAnalyzer.get_base_address("kernel32.dll")

# Full PE analysis
pe_info = PEAnalyzer.analyze_file("kernel32.dll")
print(f"ImageBase: 0x{pe_info.image_base:x}")
print(f"Entry Point: 0x{pe_info.entry_point:x}")
print(f"Machine: {pe_info.machine_type}")

for section in pe_info.sections:
    flags = section.get_characteristics_flags()
    print(f"{section.name}: {', '.join(flags)}")
```

---

## Future Enhancement Ideas

### get_rop_gadgets.py
1. **Secondary Sorting**: Sort by multiple criteria (e.g., count then address)
2. **Custom Sort Orders**: Add reverse sorting options
3. **Gadget Complexity Score**: Weight by instruction type, not just count
4. **Export Formats**: JSON/CSV output with metadata
5. **Interactive Mode**: Re-sort and filter without re-parsing
6. **Gadget Chains**: Auto-suggest gadget combinations

### rop_worksheet.py
1. **64-bit Support**: Add RSI, RDI, R8-R15 registers
2. **Export to Python**: Generate Python exploit code from worksheet
3. **Visual Stack Growth**: Show stack layout diagram
4. **Gadget Database**: Import gadgets directly from rp++ files
5. **Constraint Checking**: Validate bad characters in chain
6. **Chain Simulation**: Step through chain execution
7. **Disassembly**: Show disassembly of gadget addresses

### get_base_address.py
1. **Runtime Base Detection**: Detect actual loaded address (not just preferred)
2. **Import/Export Table**: Display imported/exported functions
3. **Security Features**: Show ASLR, DEP, CFG flags
4. **Comparison Mode**: Compare multiple PE files

---

## Defensive Security Use

All tools in this suite are designed for **defensive security analysis only**:

- Understanding ROP attack techniques
- Analyzing binary security and malware
- Developing exploit mitigations
- Security research and education
- Writing detection rules
- Testing detection systems

---

*This document is maintained alongside the codebase to track AI-assisted development and provide context for future enhancements.*