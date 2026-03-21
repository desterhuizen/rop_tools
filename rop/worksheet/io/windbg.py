"""
WinDbg import functionality.

This module handles importing register and stack values from WinDbg output format.
"""

import re
from typing import Any, Dict, Optional, Tuple


def cmd_import_regs(ws: Dict[str, Any], text: str) -> Tuple[bool, str]:
    """
    Import registers from WinDbg output format.

    Example input:
    eax=00000001 ebx=00000000 ecx=005cdeaa edx=0000034e esi=005c1716 edi=010237f8
    eip=41414141 esp=01bd744c ebp=005c4018 iopl=0         nv up ei pl nz na pe nc

    Args:
        ws: Worksheet dictionary
        text: WinDbg output text

    Returns:
        (success, message) tuple
    """
    imported = 0

    # Parse register=value pairs
    # Match patterns like "eax=00000001" or "esp=01bd744c"
    pattern = r"(eax|ebx|ecx|edx|esi|edi|ebp|esp|eip)=([0-9a-fA-F]{8})"
    matches = re.findall(pattern, text, re.IGNORECASE)

    for reg_name, value in matches:
        reg_upper = reg_name.upper()
        if reg_upper in ws["registers"]:
            ws["registers"][reg_upper] = f"0x{value}"
            imported += 1

    if imported > 0:
        return True, f"Imported {imported} register(s)"
    else:
        return False, "No valid registers found in input"


def cmd_import_stack(ws: Dict[str, Any], text: str) -> Tuple[bool, str]:
    """
    Import stack dump from WinDbg output format.

    Example input:
    01bd744c  1012b413 10168060 1014dc4c 10154399
    01bd745c  ffffc360 100fcd71 10154399 ffffffd0
    01bd746c  101268fd 10141122 1012b413 100fcd71

    Args:
        ws: Worksheet dictionary
        text: WinDbg stack dump text

    Returns:
        (success, message) tuple
    """
    # Get current ESP value
    esp_str = ws["registers"].get("ESP", "")
    if not esp_str or esp_str == "0x00000000":
        return False, "ESP not set. Import registers first or set ESP manually."

    esp_val = int(esp_str, 16)
    imported = 0

    # Parse each line: address followed by 1-4 DWORD values
    # Pattern: address (8 hex digits) followed by 1-4 hex values
    lines = text.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Match pattern: "01bd744c  1012b413 10168060 1014dc4c 10154399"
        parts = line.split()
        if len(parts) < 2:
            continue

        # First part should be the address
        try:
            addr_str = parts[0]
            # Remove any trailing colons or extra characters
            addr_str = addr_str.rstrip(":")
            stack_addr = int(addr_str, 16)
        except ValueError:
            continue

        # Process each DWORD value in this line
        for i, value_str in enumerate(parts[1:]):
            try:
                # Clean the value (remove any non-hex characters)
                value_str = value_str.strip()
                if not re.match(r"^[0-9a-fA-F]+$", value_str):
                    continue

                # Calculate the address for this DWORD
                dword_addr = stack_addr + (i * 4)

                # Calculate offset from ESP
                offset = dword_addr - esp_val

                # Format offset as string
                if offset < 0:
                    offset_str = f"-0x{abs(offset):02x}"
                else:
                    offset_str = f"+0x{offset:02x}"

                # Store the value
                ws["stack"][offset_str] = f"0x{value_str}"
                imported += 1

            except (ValueError, IndexError):
                continue

    if imported > 0:
        return True, f"Imported {imported} stack value(s)"
    else:
        return False, "No valid stack values found in input"
