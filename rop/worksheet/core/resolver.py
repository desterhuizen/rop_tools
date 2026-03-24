"""
Value resolution and target parsing for worksheet operations.

This module handles resolving expressions (registers, stack offsets, named values,
arithmetic) and parsing target destinations for operations.
"""

import re
from typing import Any, Dict, Optional, Tuple

# Sub-register mappings: sub_reg -> (parent_32bit_reg, bit_mask, bit_shift)
SUB_REGISTER_MAP = {
    # 16-bit low
    "AX": ("EAX", 0xFFFF, 0),
    "BX": ("EBX", 0xFFFF, 0),
    "CX": ("ECX", 0xFFFF, 0),
    "DX": ("EDX", 0xFFFF, 0),
    "SI": ("ESI", 0xFFFF, 0),
    "DI": ("EDI", 0xFFFF, 0),
    "BP": ("EBP", 0xFFFF, 0),
    "SP": ("ESP", 0xFFFF, 0),
    # 8-bit high
    "AH": ("EAX", 0xFF, 8),
    "BH": ("EBX", 0xFF, 8),
    "CH": ("ECX", 0xFF, 8),
    "DH": ("EDX", 0xFF, 8),
    # 8-bit low
    "AL": ("EAX", 0xFF, 0),
    "BL": ("EBX", 0xFF, 0),
    "CL": ("ECX", 0xFF, 0),
    "DL": ("EDX", 0xFF, 0),
}

# All known registers (32-bit + sub-registers)
ALL_REGISTERS = [
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
] + list(SUB_REGISTER_MAP.keys())


def read_sub_register(reg_name: str, ws: Dict[str, Any]) -> Optional[str]:
    """
    Read a sub-register value by masking the parent 32-bit register.

    Args:
        reg_name: Sub-register name (e.g., "AL", "AX", "AH")
        ws: Worksheet dictionary

    Returns:
        Hex value string or None
    """
    reg_upper = reg_name.upper()
    if reg_upper not in SUB_REGISTER_MAP:
        return None

    parent, mask, shift = SUB_REGISTER_MAP[reg_upper]
    parent_val = ws["registers"].get(parent, "0x00000000")
    if not parent_val:
        return None

    try:
        val = int(parent_val, 16)
        result = (val >> shift) & mask
        # Format based on size
        if mask == 0xFF:
            return f"0x{result:02x}"
        elif mask == 0xFFFF:
            return f"0x{result:04x}"
        return f"0x{result:08x}"
    except (ValueError, TypeError):
        return None


def write_sub_register(reg_name: str, value: str, ws: Dict[str, Any]) -> bool:
    """
    Write a value to a sub-register by merging into the parent 32-bit register.

    Args:
        reg_name: Sub-register name (e.g., "AL", "AX", "AH")
        value: Hex value to write
        ws: Worksheet dictionary

    Returns:
        True if successful, False otherwise
    """
    reg_upper = reg_name.upper()
    if reg_upper not in SUB_REGISTER_MAP:
        return False

    parent, mask, shift = SUB_REGISTER_MAP[reg_upper]
    parent_val = ws["registers"].get(parent, "0x00000000")

    try:
        current = int(parent_val, 16)
        new_val = int(value, 16) & mask
        # Clear the bits we're writing to, then set them
        cleared = current & ~(mask << shift)
        merged = cleared | (new_val << shift)
        ws["registers"][parent] = f"0x{merged & 0xFFFFFFFF:08x}"
        return True
    except (ValueError, TypeError):
        return False


def _resolve_stack_reference(expr: str, ws: Dict[str, Any]) -> Optional[str]:
    """
    Resolve stack reference like [ESP+0x10] or ESP+0x10.

    Args:
        expr: Expression string
        ws: Worksheet dictionary

    Returns:
        Resolved value or None
    """
    m = re.match(r"\[?ESP([+-]0x[0-9a-fA-F]+)\]?", expr, re.IGNORECASE)
    if m:
        offset = m.group(1)
        return ws["stack"].get(offset)
    return None


def _resolve_deref_register(expr: str, ws: Dict[str, Any]) -> Optional[str]:
    """
    Resolve dereferenced register like [EAX] when it points to stack.

    Args:
        expr: Expression string
        ws: Worksheet dictionary

    Returns:
        Resolved value or None
    """
    m = re.match(r"\[([A-Z]{3}|EIP)\]", expr, re.IGNORECASE)
    if not m:
        return None

    reg_name = m.group(1).upper()
    if reg_name not in ws["registers"]:
        return None

    # Get the address stored in this register
    reg_val = ws["registers"][reg_name]
    if not reg_val or not reg_val.startswith("0x"):
        return None

    try:
        addr = int(reg_val, 16)
        # Check if this address is on the stack
        esp_str = ws["registers"].get("ESP", "0x00000000")
        if not esp_str or esp_str == "0x00000000":
            return None

        esp_val = int(esp_str, 16)
        offset = addr - esp_val

        # Format as stack offset
        if offset < 0:
            offset_str = f"-0x{abs(offset):02x}"
        else:
            offset_str = f"+0x{offset:02x}"

        # Get the value at that stack offset
        return ws["stack"].get(offset_str)
    except Exception:
        return None


def _resolve_arithmetic(expr: str, ws: Dict[str, Any]) -> Optional[str]:
    """
    Resolve arithmetic expression like name+0x100 or name-0x10.

    Args:
        expr: Expression string
        ws: Worksheet dictionary

    Returns:
        Resolved value or None
    """
    m = re.match(r"^([A-Za-z_]\w*)\s*([+-])\s*(0x[0-9a-fA-F]+)$", expr)
    if not m:
        return None

    name, op, offset_str = m.groups()
    base = resolve_value(name, ws)
    if not base or not base.startswith("0x"):
        return None

    try:
        base_val = int(base, 16)
        offset_val = int(offset_str, 16)
        result = base_val + offset_val if op == "+" else base_val - offset_val
        return f"0x{result:08x}"
    except Exception:
        return None


def resolve_value(expr: str, ws: Dict[str, Any]) -> Optional[str]:
    """
    Resolve an expression to a value.

    Supports:
    - Direct hex: 0x12345678
    - Named value: shellgen
    - Register: EAX
    - Stack offset: [ESP+0x10] or ESP+0x10
    - Dereferenced register: [ECX] (when ECX contains a stack address)
    - Arithmetic: shellgen+0x100

    Args:
        expr: Expression string to resolve
        ws: Worksheet dictionary

    Returns:
        Resolved hex value string (e.g., "0x12345678") or None if unresolvable
    """
    expr = expr.strip()
    if not expr:
        return None

    # Direct hex value
    if expr.startswith("0x"):
        return expr

    # Stack reference [ESP+offset]
    result = _resolve_stack_reference(expr, ws)
    if result is not None:
        return result

    # Dereferenced register: [EAX], [EBX], etc.
    result = _resolve_deref_register(expr, ws)
    if result is not None:
        return result

    # 32-bit register
    if expr.upper() in ws["registers"]:
        return ws["registers"][expr.upper()]

    # Sub-register (16-bit / 8-bit)
    if expr.upper() in SUB_REGISTER_MAP:
        return read_sub_register(expr, ws)

    # Named value
    if expr in ws["named"]:
        return ws["named"][expr]

    # Arithmetic: name+0x100 or name-0x10
    result = _resolve_arithmetic(expr, ws)
    if result is not None:
        return result

    return None


def _resolve_lea_token(token: str, ws: Dict[str, Any], all_regs: set) -> Optional[int]:
    """
    Resolve a single LEA expression token to an integer value.

    Handles: reg*scale, hex immediates, decimal immediates, registers.

    Args:
        token: Token string (without sign prefix)
        ws: Worksheet dictionary
        all_regs: Set of known register names

    Returns:
        Integer value or None if unresolvable
    """
    # reg*scale
    scale_match = re.match(r"^([A-Za-z]{2,3})\*(\d+)$", token)
    if scale_match:
        reg_val = resolve_value(scale_match.group(1), ws)
        if reg_val is None:
            return None
        return int(reg_val, 16) * int(scale_match.group(2))

    # Hex immediate
    if re.match(r"^0x[0-9a-fA-F]+$", token, re.IGNORECASE):
        return int(token, 16)

    # Decimal immediate
    if re.match(r"^\d+$", token):
        return int(token)

    # Register
    if token.upper() in all_regs:
        reg_val = resolve_value(token, ws)
        if reg_val is None:
            return None
        return int(reg_val, 16)

    return None


def resolve_lea_expression(expr: str, ws: Dict[str, Any]) -> Optional[str]:
    """
    Resolve a LEA bracket expression to a computed address.

    Supported forms:
    - [ecx]              — reg
    - [ecx+0x10]         — reg + offset
    - [ecx-0x10]         — reg - offset
    - [ecx+edx]          — reg + reg
    - [ecx+edx*4]        — reg + reg*scale
    - [ecx+edx*4+0x10]   — reg + reg*scale + offset
    - [ecx+edx+0x10]     — reg + reg + offset

    Args:
        expr: Bracket expression (with or without surrounding brackets)
        ws: Worksheet dictionary

    Returns:
        Hex value string or None if unparseable
    """
    expr = expr.strip()
    if expr.startswith("[") and expr.endswith("]"):
        expr = expr[1:-1].strip()

    if not expr:
        return None

    all_regs = set(ws["registers"].keys()) | set(SUB_REGISTER_MAP.keys())

    # Tokenize: split on +/- keeping operators as prefix
    tokens = re.split(r"(?=[+-])", expr)
    tokens = [t.strip() for t in tokens if t.strip()]

    total = 0
    for token in tokens:
        sign = 1
        if token.startswith("+"):
            token = token[1:].strip()
        elif token.startswith("-"):
            sign = -1
            token = token[1:].strip()

        if not token:
            continue

        val = _resolve_lea_token(token, ws, all_regs)
        if val is None:
            return None
        total += sign * val

    return f"0x{total & 0xFFFFFFFF:08x}"


def parse_target(target: str) -> Tuple[str, str]:
    """
    Parse a target location.

    Returns: (type, key) where type is "reg", "stack", "deref", or "named"

    Examples:
    - "EAX" -> ("reg", "EAX")
    - "[ESP+0x10]" or "ESP+0x10" -> ("stack", "+0x10")
    - "[ECX]" -> ("deref", "ECX")  (dereference ECX to get stack offset)
    - "shellgen" -> ("named", "shellgen")

    Args:
        target: Target string to parse

    Returns:
        Tuple of (target_type, target_key)
    """
    original = target.strip()
    target_upper = original.upper()

    # 32-bit register
    regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]
    if target_upper in regs:
        return ("reg", target_upper)

    # Sub-register (16-bit / 8-bit)
    if target_upper in SUB_REGISTER_MAP:
        return ("subreg", target_upper)

    # Dereferenced register: [EAX], [ECX], etc.
    m = re.match(r"\[([A-Z]{2,3}|EIP)\]", original, re.IGNORECASE)
    if m:
        reg_name = m.group(1).upper()
        if reg_name in regs:
            return ("deref", reg_name)

    # Stack offset (case-insensitive)
    m = re.match(r"\[?ESP([+-]0x[0-9a-fA-F]+)\]?", original, re.IGNORECASE)
    if m:
        return ("stack", m.group(1))

    # Named value (preserve original case)
    return ("named", original)
