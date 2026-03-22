"""
Output Formatters Module

Handles formatting of shellgen output in various formats:
- Assembly (ASM)
- Python bytes
- C char array
- Raw binary
- Python assembly script (pyasm)
"""

import sys

from lib.color_printer import printer

from .assembler import assemble_to_binary


def _convert_asm_to_python_tuple(asm_code):
    """
    Convert assembly code to Python tuple format with comments extracted.

    Transforms:
        mov eax, ebx    ; this is a comment
    Into:
        "mov eax, ebx           ;"  # this is a comment

    The assembly instructions include semicolons with padding.
    Comments are extracted as Python comments.

    Args:
        asm_code: Assembly source code with inline comments

    Returns:
        str: Python tuple of assembly strings with Python comments
    """
    lines = []
    for line in asm_code.split("\n"):
        stripped = line.strip()

        # Skip empty lines
        if not stripped:
            continue

        # Handle pure comment lines (lines that start with ;)
        if stripped.startswith(";"):
            comment = stripped[1:].strip()
            lines.append(f"# {comment}")
            continue

        # Handle lines with inline comments (instruction ; comment)
        if ";" in line:
            # Split at the first semicolon
            parts = line.split(";", 1)
            code_part = parts[0].rstrip()
            comment_part = parts[1].strip() if len(parts) > 1 else ""

            if code_part:
                # Pad the instruction to align the semicolon
                padded_code = f"{code_part:<48};"
                # Line has both code and comment
                if comment_part:
                    lines.append(f'    f"{padded_code}"  # {comment_part}')
                else:
                    lines.append(f'    f"{padded_code}"')
            elif comment_part:
                # Only comment (shouldn't happen but handle it)
                lines.append(f"# {comment_part}")
        else:
            # No comment, just code - pad and add semicolon
            padded_code = f"{line.rstrip():<48};"
            lines.append(f'    f"{padded_code}"')

    return "\n".join(lines)


def format_asm(asm_code):
    """
    Return assembly code with optional colored header.

    Note: Assembly code itself remains uncolored for compatibility with assemblers.
    Only adds a colored header when outputting to TTY.
    """
    # Assembly code stays plain for compatibility - it needs to be assemblable
    # We just return it as-is since any header would need to be comments
    # and the generators already add comment headers
    return asm_code


def format_python_bytes(shellcode_bytes, arch="x86", platform="windows"):
    """
    Format shellgen as Python bytes variable.

    Args:
        shellcode_bytes: Assembled shellgen as bytes
        arch: Architecture name
        platform: Platform name

    Returns:
        str: Python code with shellgen variable
    """
    hex_bytes = "".join(f"\\x{b:02x}" for b in shellcode_bytes)

    # Only add colors if outputting to TTY
    if sys.stdout.isatty():
        # Build colored output
        output = []
        output.append(printer.colorize("# Shellcode Generator Output", "bold green"))
        output.append(
            printer.colorize(f"# Length: {len(shellcode_bytes)} bytes", "dim white")
        )
        output.append(printer.colorize(f"# Architecture: {arch}", "dim white"))
        output.append(printer.colorize(f"# Platform: {platform}", "dim white"))
        output.append("")
        output.append(printer.colorize("shellgen", "cyan") + f' = b"{hex_bytes}"')
        return "\n".join(output) + "\n"
    else:
        # Plain output for files/pipes
        return f"""# Length: {len(shellcode_bytes)} bytes
# Architecture: {arch}
# Platform: {platform}

shellgen = b"{hex_bytes}"
"""


def format_c_array(shellcode_bytes, arch="x86", platform="windows"):
    """
    Format shellgen as C char array.

    Args:
        shellcode_bytes: Assembled shellgen as bytes
        arch: Architecture name
        platform: Platform name

    Returns:
        str: C code with shellgen array
    """
    # Only add colors if outputting to TTY
    if sys.stdout.isatty():
        # Build colored output
        lines = []
        lines.append(printer.colorize("// Shellcode Generator Output", "bold green"))
        lines.append(
            printer.colorize(f"// Length: {len(shellcode_bytes)} bytes", "dim white")
        )
        lines.append(printer.colorize(f"// Architecture: {arch}", "dim white"))
        lines.append(printer.colorize(f"// Platform: {platform}", "dim white"))
        lines.append("")
        lines.append(printer.colorize("unsigned char shellgen[]", "cyan") + " = {")

        # Format as hex bytes, 16 per line
        for i in range(0, len(shellcode_bytes), 16):
            chunk = shellcode_bytes[i : i + 16]
            hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
            lines.append(f'    {hex_str}{"," if i + 16 < len(shellcode_bytes) else ""}')

        lines.append("};")
        lines.append(
            printer.colorize("unsigned int shellcode_len", "cyan")
            + f" = {len(shellcode_bytes)};"
        )
        return "\n".join(lines) + "\n"
    else:
        # Plain output for files/pipes
        lines = [
            f"// Length: {len(shellcode_bytes)} bytes",
            f"// Architecture: {arch}",
            f"// Platform: {platform}",
            "",
            "unsigned char shellgen[] = {",
        ]

        # Format as hex bytes, 16 per line
        for i in range(0, len(shellcode_bytes), 16):
            chunk = shellcode_bytes[i : i + 16]
            hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
            lines.append(f'    {hex_str}{"," if i + 16 < len(shellcode_bytes) else ""}')

        lines.append("};")
        lines.append(f"unsigned int shellcode_len = {len(shellcode_bytes)};")
        return "\n".join(lines) + "\n"


def format_pyasm(asm_code, arch="x86", platform="windows"):
    """
    Format as Python script with assembly code string for Keystone.

    Args:
        asm_code: Assembly source code
        arch: Architecture name
        platform: Platform name

    Returns:
        str: Complete Python script
    """
    # Get architecture constants for Keystone
    arch_const_map = {
        "x86": ("KS_ARCH_X86", "KS_MODE_32"),
        "x64": ("KS_ARCH_X86", "KS_MODE_64"),
        "arm": ("KS_ARCH_ARM", "KS_MODE_ARM"),
        "arm64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
        "armthumb": ("KS_ARCH_ARM", "KS_MODE_THUMB"),
    }

    arch_const, mode_const = arch_const_map.get(arch, ("KS_ARCH_X86", "KS_MODE_32"))

    # Convert assembly with inline comments to Python tuple format
    asm_tuple = _convert_asm_to_python_tuple(asm_code)

    pyasm_template = '''#!/usr/bin/env python3
"""
Shellcode Compiler - Keystone Engine
Architecture: {arch_upper}
Platform: {platform}
"""
import ctypes, struct
from keystone import *

add_break = input("Add int3 breakpoints for debugging? (y/n): ").lower() == 'y'

def run_shellcode(shellgen, add_break=False):
    # Windows Shellcode Execution (VirtualAlloc + CreateThread)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellgen)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))

    buf = (ctypes.c_char * len(shellgen)).from_buffer(shellgen)

    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellgen)))

    print("Shellcode located at address %s" % hex(ptr))
    print(f"Shellcode size: {{len(shellgen)}} bytes")
    input("...PRESS ENTER TO EXECUTE SHELLCODE...")

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

# Shellcode Definition (Assembly code with comments as Python comments)
CODE = (
{asm_tuple}
)

if add_break:
    CODE = CODE.replace(
        'start:                                          ;',
        'start:                                          ;    int3                                        ;'
    )

# Assembly and Execution
ks = Ks({arch_const}, {mode_const})

encoding, count = ks.asm(CODE)
print(f"[+] Encoded {{count}} instructions")

sh = b""
for e in encoding:
    sh += struct.pack("B", e)

shellgen = bytearray(sh)

print(f"Shellcode length: {{len(shellgen)}} bytes")

# Print shellgen in Python format
print("\\nPython format:")
print("shellgen = (")
hex_str = ''.join(f"\\\\x{{b:02x}}" for b in shellgen)
# Split into 80-character chunks
for i in range(0, len(hex_str), 80):
    chunk = hex_str[i:i+80]
    print(f'    b"{{chunk}}"')
print(")")

# Print shellgen bytes one per line
print("\\nByte-by-byte breakdown:")
for i, b in enumerate(shellgen):
    print(f"{{b:02x}}", end=' ' if (i + 1) % 16 else '\\n')
print()

if input("Run shellgen? (y/n): ").lower() == 'y':
    run_shellcode(shellgen)
else:
    if input("Do you want to print the assembly for review? (y/n): ").lower() == 'y':
        print("\\nAssembly code:")
        print("=" * 40)
        formated_asm = CODE.replace(";", ";\\n")
        print(formated_asm)
        print("=" * 40)
    '''

    return pyasm_template.format(
        arch_upper=arch.upper(),
        platform=platform,
        asm_tuple=asm_tuple,
        arch_const=arch_const,
        mode_const=mode_const,
    )


def format_output(asm_code, output_format, arch="x86", platform="windows"):
    """
    Format the shellgen in the requested output format.

    Args:
        asm_code: Assembly source code
        output_format: Format type ('asm', 'python', 'c', 'raw', 'pyasm')
        arch: Architecture name
        platform: Platform name

    Returns:
        str or bytes: Formatted output

    Raises:
        ValueError: If output format is unknown
    """
    if output_format == "asm":
        return format_asm(asm_code)

    if output_format == "pyasm":
        return format_pyasm(asm_code, arch, platform)

    # For other formats, we need to assemble first
    binary_data = assemble_to_binary(asm_code, arch)

    if output_format == "raw":
        return binary_data
    elif output_format == "python":
        return format_python_bytes(binary_data, arch, platform)
    elif output_format == "c":
        return format_c_array(binary_data, arch, platform)
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def print_usage_instructions(output_file, output_format, payload_name, verify_enabled):
    """
    Print usage instructions based on output format.

    Args:
        output_file: Output filename (None if stdout)
        output_format: Output format used
        payload_name: Name of the payload
        verify_enabled: Whether verification was enabled
    """
    # Skip usage instructions if output was printed to stdout
    if not output_file:
        return

    if output_format == "asm":
        printer.print_text("\nTo assemble:\n", "bold cyan")
        printer.print_text(
            f"  nasm -f bin -o shellgen.bin {output_file}\n", "dim white"
        )
        printer.print_text("  xxd -i shellgen.bin\n", "dim white")
        printer.print_text("\nTo extract bytes for Python:\n", "bold cyan")
        printer.print_text(
            "  python3 -c \"data=open('shellgen.bin','rb').read(); print(''.join(f'\\\\x{{b:02x}}' for b in data))\"\n",
            "dim white",
        )
        if not verify_enabled:
            printer.print_text("\nTo verify for bad characters:\n", "bold cyan")
            printer.print_text(
                f"  python3 shellgen.py --payload {payload_name} [options] --verify\n",
                "dim white",
            )

    elif output_format == "pyasm":
        printer.print_text("\n✓ Python assembly script generated!\n", "bold green")
        printer.print_text("\nTo assemble and view shellgen:\n", "bold cyan")
        printer.print_text(f"  python3 {output_file}\n", "dim white")
        printer.print_text("\nThe script contains:\n", "bold cyan")
        printer.print_text(
            "  - Assembly code as Python tuple with comments\n", "dim white"
        )
        printer.print_text(
            "  - assemble_shellcode() function to generate bytecode\n", "dim white"
        )
        printer.print_text(
            "  - print_shellcode_formats() to display in multiple formats\n",
            "dim white",
        )
        printer.print_text(
            "\nYou can import and use in your own script:\n", "bold cyan"
        )
        printer.print_text(
            f"  from {output_file.replace('.py', '')} import asm, assemble_shellcode\n",
            "dim white",
        )
        printer.print_text("  shellgen = assemble_shellcode()\n", "dim white")

    elif output_format == "python":
        printer.print_text("\nUsage in Python:\n", "bold cyan")
        printer.print_text(
            f"  from {output_file.replace('.py', '')} import shellgen\n", "dim white"
        )
        printer.print_text("  # shellgen is ready to use as bytes\n", "dim white")

    elif output_format == "c":
        printer.print_text("\nUsage in C:\n", "bold cyan")
        printer.print_text(f'  #include "{output_file}"\n', "dim white")
        printer.print_text("  // Use shellgen[] array and shellcode_len\n", "dim white")

    elif output_format == "raw":
        printer.print_text("\nRaw binary file created. Use with:\n", "bold cyan")
        printer.print_text(f"  xxd {output_file}\n", "dim white")
        printer.print_text(f"  hexdump -C {output_file}\n", "dim white")
