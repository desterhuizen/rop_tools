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
├── code_snippets/              # Utility scripts
│   ├── rop_encoder_decoder.py
│   └── skeletons.py
│
└── .github/                    # GitHub Actions
    └── workflows/
        ├── tests.yml           # Test suite (Python 3.8-3.12)
        ├── coverage.yml        # Coverage reporting
        └── lint.yml            # Code quality checks
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

**Platforms:** Windows (x86/x64), Linux (ARM/ARM64)
**Payloads:** 9 Windows payloads, 2 Linux payloads
**Key Features:** PEB walk, ROR13 hash, bad char encoding, Keystone/Capstone integration

**See:** `shellgen/CLAUDE.md` for technical details

### 2. ROP Tools Suite (rop/)
Gadget analysis, PE inspection, and interactive ROP chain building.

**Tools:**
- `get_rop_gadgets.py` - Parse/filter ROP gadgets (18 categories)
- `get_base_address.py` - Extract PE base address, IAT display
- `rop_worksheet.py` - Interactive ROP chain builder

**See:** `rop/CLAUDE.md` for technical details

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
- **tests.yml**: Runs on Python 3.8, 3.9, 3.10, 3.11, 3.12
- **coverage.yml**: Coverage reporting
- **lint.yml**: Code quality checks (flake8, black, isort, mypy)
- All workflows run on push/PR to main and develop branches

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
  - Created `.github/workflows/lint.yml` CI workflow
  - Updated README.md and CLAUDE.md with linting documentation
- **Created INSTALL.md**: Symlink installation guide for all 5 tools
- **Removed wrapper scripts**: Deleted shellgen.sh, hashgen.sh (use direct Python execution)
- **Updated GitHub Actions**: All workflows now use Node.js 24-compatible actions (v6)
- **Compacted CLAUDE.md files**: 54% reduction (rop/), 69% reduction (shellgen/)
- **Added this file**: Central AI development guide

### Earlier
- **Shared ColorPrinter**: Migrated to `lib/color_printer.py` for consistent output
- **Modular architecture**: Separated core logic from display logic
- **Rich library migration**: Replaced colorama with Rich for better formatting

---

*This file serves as the central guide for AI-assisted development across the entire ROP Tools Suite.*