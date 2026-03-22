"""
Quick operations for setting and clearing values.

This module provides simple set/clear operations for registers,
stack values, and named values.
"""

from typing import Any, Dict, Optional, Tuple

from ..core.resolver import parse_target, resolve_value


def cmd_set(ws: Dict[str, Any], target: str, value: str) -> Tuple[
        bool, Optional[str]]:
    """
    Set a register, stack slot, or named value directly.

    Args:
        ws: Worksheet dictionary
        target: Target (register, stack offset, or named value)
        value: Value to set

    Returns:
        (success, error_message) tuple
    """
    target_type, target_key = parse_target(target)

    # Try to resolve the value (handles registers, stack refs, named values)
    resolved_value = resolve_value(value, ws)
    if resolved_value is not None:
        value = resolved_value
    # else: keep original value (for raw hex or named values that don't exist yet)

    if target_type == "reg":
        ws["registers"][target_key] = value
    elif target_type == "stack":
        ws["stack"][target_key] = value
    elif target_type == "named":
        ws["named"][target_key] = value

    return True, None


def cmd_clear(ws: Dict[str, Any], target: str) -> Tuple[bool, Optional[str]]:
    """
    Clear a register, stack slot, or named value.

    Args:
        ws: Worksheet dictionary
        target: Target to clear

    Returns:
        (success, error_message) tuple
    """
    target_type, target_key = parse_target(target)

    if target_type == "reg":
        ws["registers"][target_key] = ""
    elif target_type == "stack" and target_key in ws["stack"]:
        del ws["stack"][target_key]
    elif target_type == "named" and target_key in ws["named"]:
        del ws["named"][target_key]

    return True, None
