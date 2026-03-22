"""
Assembly and Verification Module

Handles assembly of shellgen using Keystone Engine and verification
of assembled bytecode for bad characters.
"""

import re

from lib.color_printer import printer

# Try to import Keystone for assembly
try:
    from keystone import (
        KS_ARCH_ARM,
        KS_ARCH_ARM64,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
        KS_MODE_ARM,
        KS_MODE_LITTLE_ENDIAN,
        KS_MODE_THUMB,
        Ks,
    )

    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

# Try to import Capstone for disassembly
try:
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        Cs,
    )

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


def get_keystone_arch_mode(arch_name):
    """
    Get Keystone architecture and mode constants for a given architecture name.

    Args:
        arch_name: Architecture name (x86, x64, arm, arm64)

    Returns:
        tuple: (keystone_arch, keystone_mode)
    """
    if not KEYSTONE_AVAILABLE:
        raise RuntimeError("Keystone Engine not available")

    arch_map = {
        "x86": (KS_ARCH_X86, KS_MODE_32),
        "x64": (KS_ARCH_X86, KS_MODE_64),
        "arm": (KS_ARCH_ARM, KS_MODE_ARM),  # ARM32
        "arm64": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),  # ARM64/AArch64
        "armthumb": (KS_ARCH_ARM, KS_MODE_THUMB),  # ARM Thumb mode
    }

    if arch_name not in arch_map:
        raise ValueError(f"Unsupported architecture: {arch_name}")

    return arch_map[arch_name]


def clean_asm_for_keystone(asm_code):
    """
    Clean assembly code for Keystone Engine.

    - Fix Intel syntax (add 'ptr' keyword for word/byte/dword)
    - Remove semicolon comments
    - Keep ARM directives

    Args:
        asm_code: Raw assembly code with comments

    Returns:
        str: Cleaned assembly code
    """
    # Fix Intel syntax for Keystone (word/byte/dword need 'ptr')
    clean_asm = re.sub(r"\b(byte|word|dword|qword)\s+\[", r"\1 ptr [", asm_code)

    # Remove comments while preserving code
    # Keep ARM directives (.arch, .asciz, etc.) and // comments
    lines = []
    for line in clean_asm.split("\n"):
        stripped = line.strip()

        # Skip empty lines
        if not stripped:
            continue

        # Skip pure comment lines (lines that start with ; after stripping)
        if stripped.startswith(";"):
            continue

        # Keep ARM directives (lines starting with .)
        if stripped.startswith("."):
            lines.append(line)
            continue

        # Keep labels (lines ending with :)
        if stripped.endswith(":"):
            lines.append(line)
            continue

        # Remove semicolon comments but keep the code part
        if ";" in line:
            code_part = line.split(";")[0]
            if code_part.strip():
                lines.append(code_part.rstrip())
        # Keep lines with // comments (ARM style) and other lines
        elif line.strip():
            lines.append(line.rstrip())

    return "\n".join(lines)


def assemble_with_keystone(asm_code, arch=None, mode=None):
    """
    Assemble code using Keystone Engine.

    Args:
        asm_code: Assembly source code
        arch: Keystone architecture constant (or None for KS_ARCH_X86)
        mode: Keystone mode constant (or None for KS_MODE_32)

    Returns:
        bytes: Assembled machine code

    Raises:
        RuntimeError: If assembly fails or Keystone not available
    """
    if not KEYSTONE_AVAILABLE:
        raise RuntimeError("Keystone Engine not available")

    try:
        # Set defaults if not provided
        if arch is None:
            arch = KS_ARCH_X86
        if mode is None:
            mode = KS_MODE_32

        # Clean the assembly code
        clean_asm = clean_asm_for_keystone(asm_code)

        # Progress indicator
        printer.print_text("\n⚙ Assembling shellgen with Keystone Engine...\n", "cyan")

        # Initialize Keystone
        ks = Ks(arch, mode)
        encoding, count = ks.asm(clean_asm)

        if encoding is None:
            raise RuntimeError("Keystone assembly failed: No output generated")

        shellcode_bytes = bytes(encoding)

        # Build success message with details
        success_msg = f"Shellcode size: {len(shellcode_bytes)} bytes\n"
        success_msg += f"Instructions assembled: {count}"

        # Print success panel
        printer.print_panel(
            success_msg,
            title="✓ Assembly Complete",
            style="green",
            border_style="green",
        )

        # Show hex preview of first 16 bytes
        printer.print_hex_preview(
            shellcode_bytes, max_bytes=16, title="Shellcode Preview (first 16 bytes)"
        )

        return shellcode_bytes

    except NameError:
        raise RuntimeError(
            "Keystone constants not available (Keystone not properly installed)"
        )
    except Exception as e:
        if "KsError" in str(type(e).__name__):
            raise RuntimeError(f"Keystone assembly error: {e}")
        raise RuntimeError(f"Keystone error: {e}")


def assemble_to_binary(asm_code, arch="x86"):
    """
    Assemble code to binary using Keystone Engine.

    Args:
        asm_code: Assembly source code (Intel syntax for x86, standard for ARM)
        arch: Architecture name (x86, x64, arm, arm64)

    Returns:
        bytes: Assembled machine code

    Raises:
        RuntimeError: If assembly fails or Keystone not available
    """
    if not KEYSTONE_AVAILABLE:
        raise RuntimeError(
            "Keystone Engine is required but not available.\n"
            "Install with: pip install keystone-engine"
        )

    # Get architecture and mode
    ks_arch, ks_mode = get_keystone_arch_mode(arch)

    # Assemble with Keystone
    return assemble_with_keystone(asm_code, ks_arch, ks_mode)


def verify_shellcode_bad_chars(shellcode_bytes, bad_chars):
    """
    Verify that assembled shellgen doesn't contain bad characters.

    Args:
        shellcode_bytes: Assembled shellgen as bytes
        bad_chars: Set or list of bad character bytes to check

    Returns:
        tuple: (is_clean, bad_char_report)
            - is_clean: True if no bad chars found
            - bad_char_report: dict with details about any bad chars found
    """
    bad_char_set = set(bad_chars)
    bad_char_locations = []

    for offset, byte in enumerate(shellcode_bytes):
        if byte in bad_char_set:
            bad_char_locations.append(
                {
                    "offset": offset,
                    "byte": byte,
                    "context": shellcode_bytes[
                        max(0, offset - 4) : min(len(shellcode_bytes), offset + 5)
                    ],
                }
            )

    is_clean = len(bad_char_locations) == 0

    report = {
        "is_clean": is_clean,
        "total_bytes": len(shellcode_bytes),
        "bad_char_count": len(bad_char_locations),
        "bad_chars_found": {loc["byte"] for loc in bad_char_locations},
        "locations": bad_char_locations[:20],  # Limit to first 20 occurrences
    }

    return is_clean, report


def print_bad_char_report(report, bad_chars):
    """
    Print a detailed report of bad characters found in shellgen.

    Args:
        report: Report dict from verify_shellcode_bad_chars()
        bad_chars: Set or list of bad characters that were checked
    """
    if report["is_clean"]:
        print("\n" + "=" * 72)
        print("✓ SHELLCODE VERIFICATION: PASSED")
        print("=" * 72)
        print(f"No bad characters found in {report['total_bytes']} bytes of shellgen!")
        print(f"Avoided: {{{', '.join(f'0x{b:02x}' for b in sorted(bad_chars))}}}")
        return

    print("\n" + "=" * 72)
    print("✗ SHELLCODE VERIFICATION: FAILED")
    print("=" * 72)
    print(f"Found {report['bad_char_count']} bad character(s) in assembled shellgen!")
    print(f"Total shellgen size: {report['total_bytes']} bytes")
    print(
        f"\nBad characters found: {{{', '.join(f'0x{b:02x}' for b in sorted(report['bad_chars_found']))}}}"
    )

    print(f"\nFirst {min(20, len(report['locations']))} occurrences:")
    print("-" * 72)

    for i, loc in enumerate(report["locations"][:20], 1):
        offset = loc["offset"]
        byte = loc["byte"]
        context = loc["context"]

        # Show context with the bad byte highlighted
        context_hex = " ".join(f"{b:02x}" for b in context)
        bad_byte_pos = offset - max(0, offset - 4)

        print(f"{i:2d}. Offset 0x{offset:04x} ({offset:5d}): byte 0x{byte:02x}")
        print(f"    Context: {context_hex}")
        print(f"             {' ' * 3 * bad_byte_pos}^^")

    if report["bad_char_count"] > 20:
        print(f"    ... and {report['bad_char_count'] - 20} more occurrences")

    print("\n" + "=" * 72)
    print("POSSIBLE CAUSES:")
    print("=" * 72)
    print("1. Instruction opcodes contain bad characters")
    print("   - Some x86 instructions have opcodes that are bad chars")
    print("   - Example: 'push eax' = 0x50, 'pop eax' = 0x58, 'int 0x0a' = 0xcd,0x0a")
    print("\n2. Register encodings in ModR/M bytes")
    print("   - The ModR/M byte encodes register operations")
    print("   - May need to use different registers or addressing modes")
    print("\n3. Immediate value encodings (less likely with our encoder)")
    print("   - Check if any immediate values slipped through")
    print("\nRECOMMENDATIONS:")
    print("- Try alternative registers (avoid registers that encode to bad chars)")
    print("- Use different instruction sequences")
    print("- For common bad chars like 0x00: avoid NULL-containing opcodes")
    print("- For 0x0a (newline): avoid opcodes with 0x0a")
    print("=" * 72)


def scan_shellcode_for_bad_chars(shellcode_bytes, common_bad_chars=None):
    """
    Scan assembled shellgen for common bad characters and provide a summary.

    This is similar to: cat exploit.py | grep -E '00|09|0A|0B|0C|0D|20'

    Args:
        shellcode_bytes: Assembled shellgen as bytes
        common_bad_chars: List of common bad chars to check (default: 0x00-0x0D, 0x20)

    Returns:
        dict: Summary of bad characters found with counts and locations
    """
    if common_bad_chars is None:
        # Common bad characters in exploit development
        common_bad_chars = [
            0x00,  # NULL byte
            0x09,  # Horizontal Tab
            0x0A,  # Line Feed (LF)
            0x0B,  # Vertical Tab
            0x0C,  # Form Feed
            0x0D,  # Carriage Return (CR)
            0x20,  # Space
        ]

    bad_char_set = set(common_bad_chars)
    findings = {}

    for offset, byte in enumerate(shellcode_bytes):
        if byte in bad_char_set:
            if byte not in findings:
                findings[byte] = {"count": 0, "first_offset": offset, "offsets": []}
            findings[byte]["count"] += 1
            # Store only first 10 occurrences to avoid memory issues
            if len(findings[byte]["offsets"]) < 10:
                findings[byte]["offsets"].append(offset)

    return {
        "total_bytes": len(shellcode_bytes),
        "bad_chars_found": findings,
        "has_bad_chars": len(findings) > 0,
    }


def print_bad_char_summary(scan_result):
    """
    Print a summary of bad characters found in shellgen.

    Args:
        scan_result: Result dict from scan_shellcode_for_bad_chars()
    """
    # If no bad chars found, show success panel
    if not scan_result["has_bad_chars"]:
        success_msg = f"Shellcode size: {scan_result['total_bytes']} bytes\n"
        success_msg += "No common bad characters detected!"
        printer.print_panel(
            success_msg,
            title="✓ Bad Character Scan - CLEAN",
            style="green",
            border_style="green",
        )
        return

    # Bad chars found - show warning panel
    print()  # Add spacing

    # Build warning header
    warning_header = f"Shellcode size: {scan_result['total_bytes']} bytes\n"
    warning_header += "Potential bad characters found"

    printer.print_panel(
        warning_header,
        title="⚠ Bad Character Scan - WARNING",
        style="yellow",
        border_style="yellow",
    )

    # Define character names for readability
    char_names = {
        0x00: "NULL",
        0x09: "TAB (\\t)",
        0x0A: "LF (\\n)",
        0x0B: "VTAB (\\v)",
        0x0C: "FF (\\f)",
        0x0D: "CR (\\r)",
        0x20: "SPACE",
    }

    # Print details for each bad char found
    print("\nDetected bad characters:")
    print("-" * 72)

    # Sort by byte value for consistent output
    for byte_val in sorted(scan_result["bad_chars_found"].keys()):
        info = scan_result["bad_chars_found"][byte_val]
        char_name = char_names.get(byte_val, "UNKNOWN")

        printer.print_text(f"\n  0x{byte_val:02X} ({char_name})\n", "bold red")
        print(f"    Count: {info['count']}")
        print(
            f"    First occurrence: offset 0x{info['first_offset']:04X} ({info['first_offset']})"
        )

        if info["count"] > 1:
            offset_list = ", ".join(f"0x{off:04X}" for off in info["offsets"][:5])
            if info["count"] > 5:
                offset_list += f" ... (+{info['count'] - 5} more)"
            print(f"    Locations: {offset_list}")

    # Print recommendation panel
    print()
    recommendation = """If these characters are problematic for your exploit:
  1. Use --bad-chars option to specify which bytes to avoid
  2. Use --verify to confirm shellgen is clean
  3. Use --debug-shellgen to identify specific instructions

Example:
  shellgen_cli.py ... --bad-chars 00,0a,0d,20 --verify"""

    printer.print_panel(
        recommendation, title="💡 Recommendation", style="cyan", border_style="cyan"
    )


def get_capstone_arch_mode(arch_name):
    """Get Capstone architecture and mode constants."""
    if not CAPSTONE_AVAILABLE:
        raise RuntimeError("Capstone Engine not available")

    arch_map = {
        "x86": (CS_ARCH_X86, CS_MODE_32),
        "x64": (CS_ARCH_X86, CS_MODE_64),
        "arm": (CS_ARCH_ARM, CS_MODE_ARM),
        "arm64": (CS_ARCH_ARM64, CS_MODE_ARM),
    }

    if arch_name not in arch_map:
        raise ValueError(f"Unsupported architecture for disassembly: {arch_name}")

    return arch_map[arch_name]


def _disassemble_with_highlighting(shellcode, arch, bad_char_set):
    """Disassemble shellcode with bad character highlighting.

    Returns:
        dict: Map of byte offset to instruction info, or None on error
    """
    printer.print_section("\n" + "=" * 80, "cyan")
    printer.print_section("DISASSEMBLY WITH BAD CHARACTER HIGHLIGHTING", "bold cyan")
    printer.print_section("=" * 80, "cyan")

    try:
        cs_arch, cs_mode = get_capstone_arch_mode(arch)
        md = Cs(cs_arch, cs_mode)
        md.detail = True
    except Exception as e:
        printer.print_text(f"\nError disassembling shellgen: {e}", "red")
        return None

    print(f"\n{'Offset':<12} {'Size':<6} {'Opcodes':<48} Instruction")
    print("-" * 95)

    offset_to_inst = {}

    for inst in md.disasm(shellcode, 0):
        inst_bytes = shellcode[inst.address : inst.address + inst.size]
        has_bad = any(b in bad_char_set for b in inst_bytes)

        # Format opcodes with highlighting
        opcodes_display = []
        for b in inst_bytes:
            if b in bad_char_set:
                opcodes_display.append(f"\033[91m{b:02x}\033[0m")
            else:
                opcodes_display.append(f"{b:02x}")
        opcodes_str = " ".join(opcodes_display)

        if len(inst_bytes) > 16:
            opcodes_str = opcodes_str[:62] + "..."

        marker = "\033[91m!!!\033[0m" if has_bad else ""

        for i in range(inst.size):
            offset_to_inst[inst.address + i] = {
                "address": inst.address,
                "size": inst.size,
                "mnemonic": inst.mnemonic,
                "op_str": inst.op_str,
                "bytes": inst_bytes,
            }

        offset_range = f"0x{inst.address:04x}-0x{inst.address + inst.size - 1:04x}"
        disasm_str = f"{inst.mnemonic} {inst.op_str}".strip()
        print(
            f"{offset_range:<12} {inst.size:<6} {opcodes_str:<48} {marker} {disasm_str}"
        )

    return offset_to_inst


def _map_bad_chars_to_instructions(bad_char_locations, offset_to_inst, bad_char_set):
    """Map bad character locations to their instructions and print the mapping."""
    printer.print_section("\n" + "=" * 80, "bold red")
    printer.print_section("BAD CHARACTER LOCATIONS MAPPED TO INSTRUCTIONS", "bold red")
    printer.print_section("=" * 80, "bold red")

    inst_bad_chars = {}
    for loc in bad_char_locations:
        offset = loc["offset"]
        byte_val = loc["byte"]

        if offset in offset_to_inst:
            inst_info = offset_to_inst[offset]
            inst_addr = inst_info["address"]

            if inst_addr not in inst_bad_chars:
                disasm_str = f"{inst_info['mnemonic']} {inst_info['op_str']}".strip()
                inst_bad_chars[inst_addr] = {
                    "instruction": disasm_str,
                    "offset": inst_addr,
                    "size": inst_info["size"],
                    "bytes": inst_info["bytes"],
                    "bad_bytes": [],
                }

            byte_pos = offset - inst_addr
            inst_bad_chars[inst_addr]["bad_bytes"].append(
                {"byte": byte_val, "abs_offset": offset, "rel_offset": byte_pos}
            )
        else:
            print(
                f"Warning: Bad char at offset 0x{offset:04x} not mapped to instruction"
            )

    for inst_addr in sorted(inst_bad_chars.keys()):
        info = inst_bad_chars[inst_addr]
        print(f"\nOffset 0x{inst_addr:04x}: {info['instruction']}")
        print(
            f"  Instruction range: 0x{info['offset']:04x}-0x{info['offset'] + info['size'] - 1:04x} ({info['size']} bytes)"
        )
        print("  Bad characters found:")

        for bad_info in info["bad_bytes"]:
            print(
                f"    - Byte 0x{bad_info['byte']:02x} at offset 0x{bad_info['abs_offset']:04x} (byte {bad_info['rel_offset']} of instruction)"
            )

        opcodes_display = []
        for _i, b in enumerate(info["bytes"]):
            if b in bad_char_set:
                opcodes_display.append(f"\033[91m[{b:02x}]\033[0m")
            else:
                opcodes_display.append(f"{b:02x}")
        print(f"  Opcodes: {' '.join(opcodes_display)}")

    return inst_bad_chars


def _print_debug_summary(shellcode, count, bad_char_locations, inst_bad_chars=None):
    """Print the debug summary section."""
    if inst_bad_chars:
        style = "bold red"
        printer.print_section("\n" + "=" * 80, style)
        printer.print_section("SUMMARY", style)
        printer.print_section("=" * 80, style)
        printer.print_text("Total shellgen size: ", "cyan", end="")
        printer.print_text(f"{len(shellcode)} bytes\n", "yellow")
        printer.print_text("Instructions with bad characters: ", "cyan", end="")
        printer.print_text(f"{len(inst_bad_chars)}\n", "red")
        printer.print_text("Total bad character occurrences: ", "cyan", end="")
        printer.print_text(f"{len(bad_char_locations)}\n", "red")

        printer.print_text("\nTo fix these issues:", "bold cyan")
        printer.print_text("  1. Examine the flagged instructions above\n", "dim white")
        printer.print_text(
            "  2. Try using different registers or instruction forms\n", "dim white"
        )
        printer.print_text(
            "  3. For immediate values, ensure bad character encoding is working\n",
            "dim white",
        )
        printer.print_text(
            "  4. Some opcodes inherently contain bad bytes - consider alternatives\n",
            "dim white",
        )
        printer.print_text(
            "  5. ModR/M and SIB bytes encode registers - changing registers may help\n",
            "dim white",
        )
        printer.print_section("=" * 80, style)
    else:
        style = "bold green"
        printer.print_section("\n" + "=" * 80, style)
        printer.print_section("SUMMARY", style)
        printer.print_section("=" * 80, style)
        printer.print_text("Total shellgen size: ", "cyan", end="")
        printer.print_text(f"{len(shellcode)} bytes\n", "yellow")
        printer.print_text("Total instructions: ", "cyan", end="")
        printer.print_text(f"{count}\n", "yellow")
        printer.print_text(
            "\n✓ No bad characters detected - shellgen is clean!\n", "bold green"
        )
        printer.print_section("=" * 80, style)


def debug_shellcode_opcodes(asm_code, arch, bad_chars):
    """
    Debug shellgen by disassembling and mapping bad chars to instructions.

    Uses Capstone to disassemble the assembled shellgen and correlate bad characters
    with their corresponding instructions.

    Args:
        asm_code: Assembly source code
        arch: Architecture name (x86, x64, arm, arm64)
        bad_chars: Set or list of bad character bytes to check
    """
    if not KEYSTONE_AVAILABLE:
        print("Error: Keystone Engine is required for --debug-shellgen")
        print("Install with: pip install keystone-engine")
        return

    if not CAPSTONE_AVAILABLE:
        print("Error: Capstone Engine is required for --debug-shellgen")
        print("Install with: pip install capstone")
        return

    printer.print_section("\n" + "=" * 80, "bold green")
    printer.print_section(
        "SHELLCODE DEBUG MODE - Bad Character Analysis with Disassembly", "bold green"
    )
    printer.print_section("=" * 80, "bold green")
    printer.print_text("Architecture: ", "cyan", end="")
    printer.print_text(f"{arch}\n", "yellow")
    printer.print_text("Bad chars to avoid: ", "cyan", end="")
    printer.print_text(
        f"{{{', '.join(f'0x{b:02x}' for b in sorted(bad_chars))}}}\n", "red"
    )
    printer.print_section("=" * 80, "bold green")

    # Assemble the complete shellgen
    ks_arch, ks_mode = get_keystone_arch_mode(arch)
    clean_asm = clean_asm_for_keystone(asm_code)

    try:
        ks = Ks(ks_arch, ks_mode)
        encoding, count = ks.asm(clean_asm)

        if encoding is None:
            print("Error: Failed to assemble complete shellgen")
            return

        shellcode = bytes(encoding)
        print(
            f"\n[+] Complete shellgen assembled: {len(shellcode)} bytes, {count} instructions"
        )
    except Exception as e:
        print(f"Error assembling complete shellgen: {e}")
        return

    # Scan for bad characters
    bad_char_set = set(bad_chars)
    bad_char_locations = [
        {"offset": offset, "byte": byte_val}
        for offset, byte_val in enumerate(shellcode)
        if byte_val in bad_char_set
    ]

    if not bad_char_locations:
        printer.print_text(
            "\n✓ No bad characters found in the assembled shellgen!", "bold green"
        )
    else:
        printer.print_text(
            f"\n✗ Found {len(bad_char_locations)} bad character(s) in the shellgen",
            "bold red",
        )
        bad_bytes_str = ", ".join(
            f"0x{b:02x}" for b in sorted({loc["byte"] for loc in bad_char_locations})
        )
        printer.print_text(f"Bad bytes: {{{bad_bytes_str}}}", "red")

    # Disassemble with highlighting
    offset_to_inst = _disassemble_with_highlighting(shellcode, arch, bad_char_set)
    if offset_to_inst is None:
        return

    # Map bad chars to instructions and print summary
    if bad_char_locations:
        inst_bad_chars = _map_bad_chars_to_instructions(
            bad_char_locations, offset_to_inst, bad_char_set
        )
        _print_debug_summary(shellcode, count, bad_char_locations, inst_bad_chars)
    else:
        _print_debug_summary(shellcode, count, bad_char_locations)
