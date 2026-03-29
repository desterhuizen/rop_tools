# ROP Tools Suite - AI Development Guide

**Repository:** Multi-tool pentest suite for exploit development and binary analysis
**Purpose:** Defensive security research, vulnerability analysis, security education

---

## Critical Rules for AI Interactions

### 1. NO GIT OPERATIONS
- **NEVER** execute git commands (add, commit, push, pull, etc.)
- Only print summaries of changes when requested
- User handles ALL version control operations
- Exception: May run `git status` or `git diff` for information only

### 2. DOCUMENTATION REQUIREMENTS
When making major changes, **ALWAYS** update:
- **README.md** - User-facing documentation (main and tool-specific)
- **CLAUDE.md** - Development notes and technical details (this file and tool-specific)
- **Tool-specific docs** in respective directories

### 3. CONSISTENCY
- Follow existing patterns, naming conventions, code style
- Use shared libraries (lib/) for cross-tool functionality
- Maintain separation of concerns (core/ vs display/)
- Test thoroughly before declaring completion

---

## Repository Structure

```
rop_tools/
├── CLAUDE.md                   # This file - project-wide AI guide
├── README.md                   # Main user documentation
├── INSTALL.md                  # Installation guide (symlinks to ~/.local/bin/)
├── requirements.txt            # All dependencies
├── requirements-test.txt       # Test dependencies
├── requirements-lint.txt       # Linting tools
├── .flake8                     # Flake8 configuration
├── pyproject.toml              # Black, isort, mypy configuration
│
├── lib/                        # Shared libraries (ALL tools use this)
│   ├── color_printer.py        # Terminal color abstraction (Rich-based)
│   └── tests/                  # Shared library tests
│
├── shellgen/                   # Shellcode generator
│   ├── CLAUDE.md               # Shellgen-specific development notes
│   ├── README.md               # Shellgen user documentation
│   ├── shellgen_cli.py         # Main entry point
│   ├── hash_generator.py       # ROR13 hash tool
│   ├── src/                    # Core modules
│   │   ├── encoders.py         # Bad character encoding
│   │   ├── assembler.py        # Keystone/Capstone integration
│   │   ├── formatters.py       # Output formats
│   │   ├── payloads.py         # Payload builders
│   │   ├── cli.py              # CLI interface
│   │   └── generators/         # OS-specific generators
│   │       ├── windows.py      # Windows x86/x64 shellcode
│   │       └── linux.py        # Linux ARM/ARM64 shellcode
│   └── tests/                  # Shellgen tests
│
├── rop/                        # ROP Tools Suite
│   ├── CLAUDE.md               # ROP tools-specific development notes
│   ├── README.md               # ROP tools user documentation
│   ├── get_rop_gadgets.py      # Gadget analyzer (main tool)
│   ├── get_base_address.py     # PE base address extractor
│   ├── rop_worksheet.py        # Interactive ROP builder
│   ├── core/                   # Business logic (no terminal deps)
│   │   ├── gadget.py           # Gadget dataclass
│   │   ├── parser.py           # ROPGadgetParser
│   │   ├── categories.py       # GadgetCategory enum
│   │   └── pe_info.py          # PEAnalyzer, PEInfo
│   ├── display/                # Output formatting
│   │   └── formatters.py       # Uses lib/color_printer
│   └── tests/                  # ROP tools tests
│
├── target_builder/             # Vulnerable server generator
│   ├── CLAUDE.md               # Target builder development notes
│   ├── target_builder_cli.py   # Main entry point
│   ├── src/                    # Core modules
│   │   ├── config.py           # Enums, dataclasses, validation
│   │   ├── renderer.py         # Template assembly into C++ source
│   │   ├── bad_chars.py        # Bad char filter C++ generation
│   │   ├── exploit_skeleton.py # Python exploit script generation
│   │   ├── build_script.py     # build.bat generation
│   │   ├── cli.py              # CLI interface
│   │   └── templates/          # C++ code templates
│   │       ├── base.py         # Winsock2 skeleton
│   │       ├── protocols/      # TCP, HTTP, RPC handlers
│   │       ├── buffer_overflow.py, seh_overflow.py, egghunter.py, format_string.py
│   │       ├── data_staging.py  # Persistent heap buffer for egghunter staging
│   │       ├── decoys.py       # Non-exploitable decoy commands
│   │       └── rop_dll.py      # Companion DLL with ROP gadgets
│   └── tests/                  # Target builder tests (114 tests)
│
├── code_snippets/              # Utility scripts
│   ├── rop_encoder_decoder.py
│   └── skeletons.py
│
└── .github/                    # GitHub Actions
    └── workflows/
        └── ci.yml              # Unified CI (lint, test matrix, coverage)
```

---

## Shared Architecture Principles

### 1. Modular Design
- **core/**: Business logic, data structures (no terminal dependencies)
  - Must be testable independently
  - Must be importable by other tools
  - No print statements (return data structures)

- **display/**: Output formatting, colors, terminal rendering
  - Depends on core modules
  - Uses `lib/color_printer` for ALL colored output
  - Handles both colored and non-colored modes

- **lib/**: Shared across ALL tools in the repository
  - `color_printer.py` - Terminal abstraction (Rich-based, library-independent)
  - Located at repo root for cross-tool access

### 2. ColorPrinter Usage
All tools MUST use the shared ColorPrinter for consistent output:

```python
# Import from repo root
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from lib.color_printer import ColorPrinter

printer = ColorPrinter()
printer.print_header("Header", "bold green")
printer.print_labeled("Label", "Value", label_style="cyan")
printer.disable()  # For --no-color flag
```

### 3. Testing Standards
- Unit tests for core modules
- Integration tests for CLI
- Edge cases (empty files, large files, invalid input, encoding issues)
- Cross-platform compatibility where applicable

---

## Tools Overview

### 1. Shellcode Generator (shellgen/)
Multi-architecture shellcode generation with automatic bad character avoidance.

**Platforms:** Windows (x86/x64), Linux (x86/x64/ARM/ARM64)
**Payloads:** 12 Windows payloads, 3 Linux payloads
**Key Features:** PEB walk, ROR13 hash, bad char encoding, Keystone/Capstone integration

**See:** `shellgen/CLAUDE.md` for technical details

### 2. ROP Tools Suite (rop/)
Gadget analysis, PE inspection, and interactive ROP chain building.

**Tools:**
- `get_rop_gadgets.py` - Parse/filter ROP gadgets (18 categories)
- `get_base_address.py` - Extract PE base address, IAT display
- `rop_worksheet.py` - Interactive ROP chain builder

**See:** `rop/CLAUDE.md` for technical details

### 3. Target Builder (target_builder/)
Generate compilable C++ Windows servers with configurable vulnerabilities for security training.

**Vulnerability Types:** Buffer overflow, SEH overflow, egghunter, format string
**Protocols:** TCP, HTTP, RPC
**Key Features:** Configurable mitigations (DEP/ASLR/GS/SafeSEH), randomized challenges, exploit skeleton generation, ROP companion DLL, build script generation

**See:** `target_builder/CLAUDE.md` for technical details

---

## Installation (User Perspective)

Users can install via `INSTALL.md`:
```bash
# Creates symlinks in ~/.local/bin/
ln -sf "$(pwd)/shellgen/shellgen_cli.py" ~/.local/bin/shellgen
ln -sf "$(pwd)/shellgen/hash_generator.py" ~/.local/bin/hash_generator
ln -sf "$(pwd)/rop/get_rop_gadgets.py" ~/.local/bin/get_rop_gadgets
ln -sf "$(pwd)/rop/get_base_address.py" ~/.local/bin/get_base_address
ln -sf "$(pwd)/rop/rop_worksheet.py" ~/.local/bin/rop_worksheet
ln -sf "$(pwd)/target_builder/target_builder_cli.py" ~/.local/bin/target_builder
```

All scripts have proper shebangs (`#!/usr/bin/env python3`) and can be run directly.

---

## Development Workflow

### When Adding New Features

1. **Plan**: Understand requirements, check existing patterns
2. **Code**:
   - Core logic in `core/` modules
   - Display logic in `display/` or main script
   - Use `lib/color_printer` for ALL colored output
3. **Test**: Unit tests + integration tests
4. **Document**:
   - Update README.md (user-facing changes)
   - Update CLAUDE.md (technical details, version history)
   - Add usage examples
5. **No Git**: Print summary of changes for user to commit

### When Refactoring

1. **Preserve**: Don't break existing CLI interfaces
2. **Extract**: Move business logic to core/, display logic separate
3. **Reuse**: Use shared ColorPrinter, avoid duplication
4. **Test**: Ensure all existing functionality still works
5. **Document**: Update both README and CLAUDE files

### When Fixing Bugs

1. **Reproduce**: Understand the issue fully
2. **Fix**: Make minimal, targeted changes
3. **Test**: Verify fix + no regressions
4. **Document**: Add to CLAUDE.md bug fixes section if significant

---

## Testing

### Running Tests
```bash
# All tests
python -m unittest discover

# Specific module
python -m unittest discover -s shellgen/tests
python -m unittest discover -s rop/tests
python -m unittest discover -s target_builder/tests

# With coverage
coverage run -m unittest discover
coverage report
```

### Code Linting
```bash
# Install linting tools
pip install -r requirements-lint.txt

# Run all linters
flake8 lib/ rop/ shellgen/ code_snippets/
black --check lib/ rop/ shellgen/ code_snippets/
isort --check-only lib/ rop/ shellgen/ code_snippets/
mypy lib/ rop/ shellgen/ code_snippets/

# Auto-format code (fixes most issues automatically)
black lib/ rop/ shellgen/ code_snippets/
isort lib/ rop/ shellgen/ code_snippets/
```

**Configuration Files:**
- `.flake8` - flake8 configuration (max line length 88, ignore black conflicts)
- `pyproject.toml` - black and isort configuration (88 char lines, Python 3.8+ target)

### GitHub Actions
- **ci.yml**: Unified workflow with three parallel jobs:
  - **Lint**: flake8, black, isort, mypy (Python 3.12)
  - **Test**: Matrix across Python 3.8, 3.9, 3.10, 3.11, 3.12
  - **Coverage**: Runs after tests pass (main/PRs only)
- Triggers on push/PR to main and develop branches

---

## Dependencies

### Core Dependencies (All Tools)
```bash
pip install -r requirements.txt
```
- `rich` - Terminal formatting (used by ColorPrinter)
- `pefile` - PE file parsing (get_base_address.py)
- `keystone-engine` - Assembly (shellgen)
- `capstone` - Disassembly (shellgen --debug-shellcode)

### Test Dependencies
```bash
pip install -r requirements-test.txt
```
- `coverage` - Code coverage
- `rich` - Terminal formatting (needed for display tests)

### Linting Dependencies
```bash
pip install -r requirements-lint.txt
```
- `flake8` - PEP 8 style checking and error detection
- `black` - Automatic code formatting (88 char line length)
- `isort` - Import sorting and organization
- `mypy` - Optional static type checking
- `flake8-bugbear` - Enhanced flake8 plugin for bug detection
- `flake8-comprehensions` - Check unnecessary comprehensions
- `flake8-simplify` - Suggest code simplifications

---

## Security Notice

**ALL tools are for authorized defensive security purposes ONLY:**

✅ **Permitted Uses:**
- Penetration testing (with authorization)
- Security research and education
- Defensive security analysis
- Red team operations (authorized)
- CTF competitions
- Malware analysis
- Vulnerability research

❌ **Prohibited:**
- Unauthorized access
- Malicious malware development
- Any illegal activities

---

## Quick Reference

### Finding Information
- **Project-wide context**: This file (CLAUDE.md)
- **Shellgen technical details**: `shellgen/CLAUDE.md`
- **ROP tools technical details**: `rop/CLAUDE.md`
- **Target builder technical details**: `target_builder/CLAUDE.md`
- **User documentation**: README.md files (main and tool-specific)
- **Installation**: `INSTALL.md`

### Common Tasks
- **New feature**: Plan → Code → Test → Document (README + CLAUDE)
- **Bug fix**: Reproduce → Fix → Test → Document if significant
- **Refactor**: Preserve CLI → Extract logic → Use shared libs → Test → Document
- **Color output**: Always use `lib/color_printer.ColorPrinter`
- **Git operations**: NEVER execute, only print summaries

---

## Changelog (Project-Wide)

### March 2026
- **Added linting infrastructure**: flake8, black, isort, mypy with full configuration
  - Created `requirements-lint.txt` with 7 linting tools
  - Added `.flake8` configuration (88 char line length, sensible ignores)
  - Added `pyproject.toml` for black/isort/mypy (Python 3.8+ target)
  - Created `.github/workflows/ci.yml` unified CI workflow (lint, test, coverage)
  - Updated README.md and CLAUDE.md with linting documentation
- **Created INSTALL.md**: Symlink installation guide for all 5 tools
- **Removed wrapper scripts**: Deleted shellgen.sh, hashgen.sh (use direct Python execution)
- **Updated GitHub Actions**: All workflows now use Node.js 24-compatible actions (v6)
- **Compacted CLAUDE.md files**: 54% reduction (rop/), 69% reduction (shellgen/)
- **Added this file**: Central AI development guide
- **New tool: target_builder** — Vulnerable server generator for security training
  - 18 source files implementing full C++ server code generation pipeline
  - 4 vulnerability types (bof, seh, egghunter, fmtstr) x 3 protocols (TCP, HTTP, RPC)
  - Configurable mitigations (DEP with 6 bypass APIs, ASLR with info leak, GS, SafeSEH)
  - Randomization with seeds, difficulty presets, decoy commands
  - Exploit skeleton generation (3 levels x 3 protocols)
  - ROP companion DLL with 3 gadget density levels
  - Build script generation with correct cl.exe flags
  - 114 tests across 6 test files

### March 28, 2026 — Data staging, ASLR leak fix, MinGW ASLR fix, zsh completion fix
- **target_builder**: New `--data-staging` flag — adds a command that stores data
  in a persistent 64KB heap buffer for egghunter practice. TCP: `STORE`, HTTP:
  `POST /store`, RPC: opcode 253. Command name randomized from 10-name pool.
  Supports `--exclude-protection data-staging`. Hard=50%, medium=30% during random.
- **target_builder**: Fixed ASLR info leak — previously leaked `&local_var` (stack
  address, useless under modern ASLR). Now leaks a function pointer into the
  server's `.text` section. Attacker subtracts the RVA to compute EXE base.
  Function name randomized from 12-name pool (`LEAK_FUNC_POOL`) when `--random`
  is used with ASLR. New config field: `ServerConfig.leak_func_name`.
- **target_builder**: Fixed MinGW ASLR — added `-Wl,--enable-reloc-section` to
  MinGW build script when `--aslr` is enabled. Without relocations, Windows
  couldn't relocate the binary despite `--dynamicbase` being set.
- **lib/completions.py**: Fixed zsh completion generation — square brackets in
  argparse help text (e.g. `[eax]`) broke `_arguments` parsing. Now replaced
  with parentheses in zsh completion descriptions.

### March 28, 2026 — Shell completion for shellgen tools
- **shellgen**: Added `--generate-completion {bash,zsh}` to `shellgen_cli.py` and
  `hash_generator.py`, using shared `lib/completions.py`. 149 shellgen tests
  (was 127).

### March 28, 2026 — Shell completion for rop tools
- **rop**: Added `--generate-completion {bash,zsh}` to `get_rop_gadgets.py` and
  `get_base_address.py`. Extracted shared `lib/completions.py` module from
  target_builder's completions, parameterized by tool name. 522 rop tests
  (was 501), 65 lib tests (was 40).

### March 28, 2026 — Exploit improvements, MinGW support, shell completion
- **target_builder**: Added `p32int()`/`p64int()` signed integer packing helpers
  to exploit skeletons. New `--exploit-hints {full,minimal,none}` flag controls
  hint verbosity in crash exploits.
- **target_builder**: Added `--compiler {msvc,mingw}` for MinGW cross-compilation.
  Generates `build.sh` with correct GCC flags. `--rop-dll`/`--embedded-gadgets`
  remain MSVC-only.
- **target_builder**: Added `--generate-completion {bash,zsh}` for shell tab
  completion. Auto-generated from argparse parser.
- 276 tests (was 219).

### March 28, 2026 — Constrained randomization + C++ generation fixes
- **target_builder**: Constrained `--random` mode — explicit CLI args now
  respected as overrides. Comma-separated `--vuln bof,seh`, `--protocol`,
  `--bad-char-action`, `--padding-style` constrain random pool. New
  `--exclude-protection dep,aslr,canary,safeseh,fmtstr-leak` forces
  protections OFF. Fixed `--bad-char-action`/`--dep-api` being ignored,
  and `--arch x86`/`--protocol tcp` being indistinguishable from defaults.
- **target_builder**: Fixed C++ generation bugs — invalid `req->body` as
  function parameter names, wrong `filter_bad_chars` variable names,
  `#define`/struct ordering issues. Fixed fmtstr crash exploit and `%` bad
  char exclusion. Randomized base addresses for EXE and DLL during `--random`.
  219 tests (was 189).

### March 27, 2026 — Format string info leak + Worksheet `next` command + SEH overflow fix
- **target_builder**: Added `--fmtstr-leak` flag — optional format string leak
  command/endpoint for ASLR bypass practice. User input passed directly to
  `_snprintf()` as format string, allowing `%p`/`%x` stack reads. TCP: `ECHO`,
  HTTP: `POST /echo`, RPC: opcode 254. Works with any vuln type, coexists with
  existing `--aslr` info leak. Randomized for hard difficulty. 189 tests (was 164).
- **rop/worksheet**: Added `next` command (alias `n`, Ctrl+N keybind) — pops EIP
  from the stack, stepping to the next gadget. Auto-executes the gadget if
  auto-gadget is enabled.
- **target_builder**: Fixed SEH overflow template — previous `buffer[0]` access
  never triggered an exception, so the function returned normally via corrupted
  saved EIP (regular BOF behavior). Replaced with a double-dereference of bytes
  past the buffer end that triggers an AV inside `__try`, routing through the
  corrupted SEH handler chain. Also fixed landing pad frame overhead for SEH
  (8 → 20 bytes to account for nSEH + handler + try-level). Exploit skeleton
  now generates SEH-specific hints (nSEH/handler layout, POP POP RET pattern).

### March 25, 2026 — Target builder stack layout variation
- **target_builder**: Added randomized stack layouts for more realistic challenges.
  `--pre-padding` adds local variables between buffer and saved EBP (changes EIP offset).
  `--landing-pad` limits post-EIP space (forces short jumps when tight).
  `--padding-style` controls variable types (array/mixed/struct/multi).
  Integrated into difficulty presets: easy=none, medium=moderate, hard=tight.
  Exploit skeleton now includes layout-aware hints. 164 tests (was 137).

### March 24, 2026 — Cross-tool bug fixes and features
- **shellgen**: Fixed socket payloads (reverse_shell, bind_shell x86/x64) — `custom_asm`
  strings had unformatted `{ip_dword}`, `{port_word}`, `{sockaddr_qword}`, `{shell_asm}`
  placeholders causing Keystone assembly failures. Fixed entry point `sys.path` ordering.
  Renamed `--debug-shellgen` → `--debug-shellcode` to match code references.
- **target_builder**: Fixed exploit skeleton byte encoding — TCP/HTTP payloads mangled
  bytes >= 0x80 through string encode/decode round-trip. Fixed `cli.py` syntax errors.
  Added `--embedded-gadgets` for standalone ROP gadgets in server binary (x86 only).
  Added `EmbeddedGadgetsConfig` with density levels and mutual exclusion with `--rop-dll`.
- **rop/get_base_address.py**: Added DEP bypass candidate detection — `--iat` now shows
  a summary of 8 DEP bypass APIs found in the IAT with addresses and argument reference.
- **rop/worksheet**: Completed all 6 instruction phases from `TODO_INSTRUCTIONS.md`:
  Phase 1: sub-register support (AL/AH/AX, etc. — read via mask, write via merge).
  Phase 2: `and`, `or`, `shl`, `shr`, `ror`, `rol`. Phase 3: `not`.
  Phase 4: `cdq`, `lodsd`, `stosd`, `nop` (zero-operand with new dispatch category).
  Phase 5: `movzx`, `movsxd`. Phase 6: `lea` with full bracket expression parser
  (`[reg+reg*scale+offset]`). Also added `sub dst, src`, refactored dispatch table,
  and introduced `_write_to_target` helper for all target types including sub-registers.

### Earlier
- **Shared ColorPrinter**: Migrated to `lib/color_printer.py` for consistent output
- **Modular architecture**: Separated core logic from display logic
- **Rich library migration**: Replaced colorama with Rich for better formatting

---

## Future TODO

- **Codecov integration**: Codecov account and GitHub App are set up, `CODECOV_TOKEN` secret is configured, and `ci.yml` uploads `coverage.xml`. However, Codecov reports "No coverage report uploaded for this branch head commit". Needs debugging — likely a commit SHA mismatch or branch configuration issue in Codecov settings. Badge in README is ready (`[![codecov](...)]`), just needs the upload to work.

---

*This file serves as the central guide for AI-assisted development across the entire ROP Tools Suite.*