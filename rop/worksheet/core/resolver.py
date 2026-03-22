"""
Value resolution and target parsing for worksheet operations.

This module handles resolving expressions (registers, stack offsets, named values,
arithmetic) and parsing target destinations for operations.
"""

import re
from typing import Any, Dict, Optional, Tuple


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

    # Register
    if expr.upper() in ws["registers"]:
        return ws["registers"][expr.upper()]

    # Named value
    if expr in ws["named"]:
        return ws["named"][expr]

    # Arithmetic: name+0x100 or name-0x10
    result = _resolve_arithmetic(expr, ws)
    if result is not None:
        return result

    return None


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

    # Register
    regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]
    if target_upper in regs:
        return ("reg", target_upper)

    # Dereferenced register: [EAX], [ECX], etc.
    m = re.match(r"\[([A-Z]{3}|EIP)\]", original, re.IGNORECASE)
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
