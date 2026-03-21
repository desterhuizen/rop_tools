# Documentation

This directory contains comprehensive documentation for the ROP Tools Suite.

---

## ⚠️ **IMPORTANT NOTICE**

**This documentation is provided for authorized security testing, research, and educational purposes ONLY.**

All techniques, tools, and methodologies documented here are intended for:
- ✅ **Authorized penetration testing** (with written permission)
- ✅ **Security research and education**
- ✅ **Defensive security analysis and testing**
- ✅ **CTF competitions and security training**
- ✅ **Vulnerability research in controlled environments**
- ✅ **Development of security mitigations and defenses**

**UNAUTHORIZED USE IS PROHIBITED.** Do not use these techniques on systems you do not own or have explicit written authorization to test. Misuse of this information may violate local, state, federal, or international laws.

**The authors and contributors are not responsible for any misuse or damage caused by the information contained in this documentation.**

---

## 📚 Table of Contents

### Shellcode Development
- **[Bad Character Avoidance Techniques](bad_character_avoidance.md)** - Non-encoding techniques for avoiding bad characters in shellcode
  - NEG (Negate) technique
  - ADD/SUB construction
  - XOR construction
  - Shift operations (SHL/SHR)
  - Stack manipulation
  - Partial register operations
  - 20+ practical techniques with examples

### Tool Documentation
For tool-specific documentation, see:
- [ROP Tools README](../rop/README.md) - ROP gadget analysis and chain building
- [Shellgen README](../shellgen/README.md) - Multi-architecture shellcode generation
- [Main Project README](../README.md) - Overview and quick start

### Development Notes
- [ROP Development Notes](../rop/CLAUDE.md) - Feature history and technical implementation
- [Shellgen Technical Details](../shellgen/CLAUDE.md) - Architecture details and version history

---

## 🎯 Quick Links

### Exploit Development
- **Bad Character Avoidance**: Start with [bad_character_avoidance.md](bad_character_avoidance.md) for instruction-level encoding techniques
- **ROP Chains**: See [rop/README.md](../rop/README.md) for gadget analysis workflow
- **Shellcode Generation**: See [shellgen/README.md](../shellgen/README.md) for payload creation

### Testing & Quality
- **Test Coverage**: See test suite in `rop/tests/`, `shellgen/tests/`, and `lib/tests/`
- **Contributing**: Follow development guidelines in project READMEs

---

## 📖 Documentation Standards

All documentation in this directory follows these standards:
- **Markdown format** (.md) for readability
- **Code examples** with syntax highlighting
- **Practical use cases** for each technique
- **Cross-references** to related documentation
- **Version tracking** in CLAUDE.md files

---

## 🔍 Finding Documentation

### By Topic
- **Shellcode Encoding**: [bad_character_avoidance.md](bad_character_avoidance.md)
- **ROP Gadgets**: [../rop/README.md](../rop/README.md)
- **Payload Generation**: [../shellgen/README.md](../shellgen/README.md)

### By Tool
- **get_rop_gadgets.py**: [../rop/README.md#get_rop_gadgetspy](../rop/README.md)
- **get_base_address.py**: [../rop/README.md#get_base_addresspy](../rop/README.md)
- **rop_worksheet.py**: [../rop/README.md#rop_worksheetpy](../rop/README.md)
- **shellgen_cli.py**: [../shellgen/README.md](../shellgen/README.md)
- **hash_generator.py**: [../shellgen/README.md#hash-generator](../shellgen/README.md)

---

## ⚠️ Security Notice

All documentation and techniques are provided for:
- ✅ Authorized penetration testing
- ✅ Security research and education
- ✅ Defensive security analysis
- ✅ CTF competitions
- ✅ Vulnerability research

**Do not use** for unauthorized access or malicious purposes.

---

## 🤝 Contributing Documentation

When adding new documentation:
1. Place general documentation in `docs/`
2. Place tool-specific docs in respective tool directories
3. Update this README with links
4. Follow markdown best practices
5. Include practical code examples
6. Cross-reference related documents

---

*For tool usage and installation instructions, see the [Main README](../README.md)*