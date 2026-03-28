# ROP Tools - Development Notes

AI-assisted development tracking for the ROP Tools Suite.

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
- **Dependencies:** `rich` (terminal formatting), `pefile` (PE parsing)
- **Testing:** `unittest` (stdlib)
- **Linting:** flake8, black, isort, mypy (config in root `.flake8` / `pyproject.toml`)

### Running the Tools
```bash
# Gadget analyzer (requires ROPgadget output file)
./rop/get_rop_gadgets.py <gadget_file> [options]

# PE base address extractor (requires PE file)
./rop/get_base_address.py <pe_file> [options]

# Interactive ROP worksheet
./rop/rop_worksheet.py
```

### Running Tests
```bash
# All rop tests
python3 -m unittest discover -s rop/tests

# Specific test file
python3 -m unittest rop/tests/test_operations_asm.py

# Shared lib tests
python3 -m unittest discover -s lib/tests
```

### Linting
```bash
flake8 rop/ lib/
black --check rop/ lib/
isort --check-only rop/ lib/
```

---

## Architecture (March 2026)

```
rop_tools/
├── lib/                        # Shared across all tools
│   └── color_printer.py        # Terminal color abstraction
└── rop/
    ├── get_rop_gadgets.py      # Gadget analyzer (~350 lines)
    ├── get_base_address.py     # PE base address extractor
    ├── rop_worksheet.py        # Interactive ROP builder
    ├── core/                   # Business logic (no terminal deps)
    │   ├── gadget.py           # Gadget dataclass + analysis
    │   ├── parser.py           # ROPGadgetParser
    │   ├── categories.py       # GadgetCategory enum
    │   └── pe_info.py          # PEAnalyzer, PEInfo, PESection
    └── display/                # Output formatting
        └── formatters.py       # Uses lib/color_printer
```

**Benefits**: Separation of concerns, testable modules, shared ColorPrinter,
library independence

---

## Recent Features

### Shell Completion for get_rop_gadgets and get_base_address (March 28, 2026)

- Added `--generate-completion {bash,zsh}` to both `get_rop_gadgets.py` and
  `get_base_address.py`
- Extracted `target_builder/src/completions.py` into shared `lib/completions.py`
  with parameterized tool names. `target_builder/src/completions.py` is now a
  thin wrapper delegating to the shared module.
- `lib/completions.py` provides: `generate_completion(shell, parser, tool_names)`,
  `handle_completion(argv, parser_builder, tool_names)` for early-exit before
  `parse_args()`, and `_extract_flags(parser)` for argparse introspection.
- Refactored `get_base_address.py` to extract `_build_parser()` from inline
  parser construction in `main()`.
- 522 rop tests (was 501), 65 lib tests (was 40)

### DEP Bypass Candidate Detection (March 24, 2026)

- `--iat` now shows a **DEP Bypass Candidates** section after the full IAT
- Scans for 8 DEP bypass APIs: VirtualProtect, VirtualAlloc, WriteProcessMemory,
  HeapCreate, SetProcessDEPPolicy, NtAllocateVirtualMemory, VirtualProtectEx,
  NtProtectVirtualMemory
- Shows API, DLL, IAT address, bypass technique, and argument reference
- Only shown when matching APIs are found and not filtering by `--dll`

### Worksheet: `next` command (March 27, 2026)

- **`next` command** (aliases: `n`): Pops EIP from the stack — equivalent to
  `pop EIP`. Simulates stepping to the next gadget in the ROP chain. If
  auto-gadget is enabled, the gadget at the new EIP is automatically executed.
- **Ctrl+N keybinding**: Triggers `next` without typing. Works on both GNU
  readline and macOS libedit.
- Added to tab completion, full help text, and compact help bar.

### Worksheet: Full instruction set expansion (March 24, 2026)

- **Phase 1 — Sub-register support**: AL/AH/AX, BL/BH/BX, CL/CH/CX, DL/DH/DX,
  SI, DI, BP, SP. Read via masking, write via merge into parent 32-bit register.
  Gadgets with sub-register operands are now auto-executed instead of skipped.
- **Phase 2 — Bitwise/shift ops**: `and`, `or`, `shl`, `shr`, `ror`, `rol`
- **Phase 3 — Bitwise complement**: `not`
- **Phase 4 — Zero-operand**: `cdq` (sign-extend EAX→EDX), `lodsd` (EAX=[ESI];
  ESI+=4), `stosd` ([EDI]=EAX; EDI+=4), `nop`
- **Phase 5 — Data movement**: `movzx` (zero-extend), `movsxd` (sign-extend)
- **Phase 6 — LEA**: `lea dst, [reg+reg*scale+offset]` with full bracket
  expression parser supporting all x86 addressing modes
- Refactored dispatch table, added zero-operand dispatch category in REPL
- Added `sub dst, src` operation
- Refactored `_execute_instruction()` from if/elif chain to dispatch table lookup
- Refactored `cmd_move` and arithmetic ops to use shared `_write_to_target` helper

### Bad Instruction Filtering (March 20, 2026)

- Auto-filters 44 harmful instructions (privileged, I/O, control flow,
  interrupts)
- `--keep-bad-instructions` flag to disable filtering
- **Filtered**: clts, hlt, mov cr/dr, in/out, cli/sti, call, jmp, conditional
  jumps, etc.

### IAT Display (March 16, 2026)

- `--iat` flag shows Import Address Table
- `--dll <name>` filters by specific DLL
- Displays: function names, RVAs, absolute addresses
- Grouped by DLL for organized output

### get_base_address.py Refactor (March 16, 2026)

- Created `core/pe_info.py` module (PESection, PEInfo, PEAnalyzer)
- Rewrote with argparse + ColorPrinter
- Added verbose (`-v`), quiet (`-q`), `--no-color` modes

---

## get_rop_gadgets.py - Key Features

### Core Capabilities

- **18 Gadget Categories**: Stack (pivot/pop/push), register (load/move/xchg),
  memory (read/write), arithmetic, logic, control flow, syscall, string ops
- **Auto Encoding Detection**: UTF-8/UTF-16 with BOM detection
- **Register Analysis**: Affected vs modified registers (32/64/16/8-bit)
- **Multi-level Grouping**: By instruction/category/register, category→register
  drill-down

### Filtering

- Instruction (`-i`), category (`-c`), register (`--register`), dereferenced (
  `--deref`)
- Regex (`-r`) with highlighting (`--highlight`), exclusion (`-e`), bad chars (
  `-b`)
- Max instruction count (`-m`)

### Display

- Instruction/category display, smart sorting (count/address)
- Offset calculation (`--offset`), colored output with `--no-color` fallback
- Statistics: totals, top 10 instructions, category distribution

---

## rop_worksheet.py - Interactive Builder

### Features

- **Register Tracking**: All x86 32-bit regs (EAX-ESP, EIP) plus 8/16-bit
  sub-registers (AL/AH/AX, etc.), named value matching
- **Stack Management**: ESP-relative offsets, absolute addresses, register-based
  addressing
- **ASM Operations**: mov, add, sub, xor, xchg, and, or, shl, shr, ror, rol,
  inc, dec, neg, not, cdq, lodsd, stosd, nop, movzx, movsxd, lea, push/pop,
  next (pop EIP shortcut, Ctrl+N keybind)
  (auto ESP tracking)
- **WinDbg Integration**: `importregs`, `importstack` (multi-line paste)
- **ROP Chains**: Add gadgets, delete entries, visual display
- **Workflow**: Save/load JSON, command history, tab completion

### Bug Fixes (March 15, 2026)

- Fixed push/pop to use ESP-relative offsets
- Fixed value resolution in `stack`/`set` commands
- Added EIP tracking (previously missing)
- Added `xchg`, stack address column, named value matching

---

## Version History

| Version | Date     | Changes                                                                |
|---------|----------|------------------------------------------------------------------------|
| 3.3.0   | Mar 2026 | Bad instruction filtering (44 instructions), IAT display, --dll filter |
| 3.2.0   | Mar 2026 | Shared lib/color_printer, symlink support                              |
| 3.1.0   | Mar 2026 | Modular architecture (core/, display/), ~350 line main                 |
| 3.0.0   | Mar 2026 | Rich library migration, ColorPrinter abstraction                       |
| 2.5.0   | Mar 2026 | Offset calculation, get_base_address.py                                |
| 2.4.0   | Mar 2026 | Auto UTF-8/UTF-16 detection                                            |
| 2.3.0   | Mar 2026 | Exclusion filtering (-e)                                               |
| 2.2.0   | Mar 2026 | Regex highlighting (--highlight)                                       |
| 2.1.0   | Mar 2026 | Sorting (--sort), count display                                        |
| 2.0.0   | Earlier  | Core features (categories, register analysis, colors)                  |

---

## Code Examples

### ROPGadgetParser

```python
from core import ROPGadgetParser, GadgetCategory

parser = ROPGadgetParser(gadget_file)
gadgets = parser.parse()
filtered = parser.filter_by_instruction("pop", gadgets)
filtered = parser.filter_by_category(GadgetCategory.STACK_POP, gadgets)
grouped = parser.group_by_register(gadgets)
```

### PEAnalyzer

```python
from core import PEAnalyzer

base = PEAnalyzer.get_base_address("kernel32.dll")
pe_info = PEAnalyzer.analyze_file("kernel32.dll")
print(f"ImageBase: 0x{pe_info.image_base:x}")
```

### ColorPrinter

```python
from lib.color_printer import ColorPrinter

printer = ColorPrinter()
printer.print_header("Header", "bold green")
printer.print_labeled("Label", "Value", label_style="cyan")
printer.disable()  # No colors
```

---

## Future Enhancements

### get_rop_gadgets.py

- Secondary sorting, gadget complexity scoring
- JSON/CSV export, interactive re-filtering
- Auto-suggest gadget chains

### rop_worksheet.py

- 64-bit support (RSI, RDI, R8-R15)
- Export to Python exploit code
- Chain simulation, constraint checking, disassembly

### get_base_address.py

- Runtime base detection, import/export tables
- Security features display (ASLR, DEP, CFG)

---

## Testing Approach

1. **Unit Tests**: Core modules independently (parser, categorizer)
2. **Integration Tests**: CLI with various command combinations
3. **Edge Cases**: Empty/large files, invalid input, encoding issues
4. **Cross-platform**: Windows, Linux, macOS

---

## Module Organization

- **core/**: Business logic (no terminal deps, testable, importable)
- **display/**: Output formatting (uses lib/color_printer)
- **lib/**: Shared across all pentest tools (color_printer)

---

## Defensive Security Use

**Authorized defensive purposes only:**

- Understanding ROP attack techniques
- Analyzing binaries and malware
- Developing exploit mitigations
- Security research and education
- Writing detection rules

---

*Maintained alongside codebase to track AI-assisted development.*