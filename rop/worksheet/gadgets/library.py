"""
Gadget library management.

This module handles adding, removing, and clearing gadgets from the library.
"""

from typing import Any, Dict, Optional, Tuple


def cmd_gadget_add(
        ws: Dict[str, Any], address: str, instructions: str
) -> Tuple[bool, Optional[str]]:
    """
    Add a gadget to the gadget library.

    Args:
        ws: Worksheet dictionary
        address: Gadget address (hex string)
        instructions: Instruction string (e.g., "pop eax ; ret")

    Returns:
        (success, error_message) tuple
    """
    # Normalize address to lowercase with 0x prefix
    if not address.startswith("0x"):
        address = "0x" + address
    address = address.lower()

    ws["gadgets"][address] = instructions
    return True, None


def cmd_gadget_del(ws: Dict[str, Any], address: str) -> Tuple[
        bool, Optional[str]]:
    """
    Remove a gadget from the library by address.

    Args:
        ws: Worksheet dictionary
        address: Gadget address to remove

    Returns:
        (success, error_message) tuple
    """
    # Normalize address to lowercase with 0x prefix
    if not address.startswith("0x"):
        address = "0x" + address
    address = address.lower()

    if address in ws["gadgets"]:
        del ws["gadgets"][address]
        return True, None
    else:
        return False, f"Gadget {address} not found in library"


def cmd_gadget_clear(ws: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Clear all gadgets from the library.

    Args:
        ws: Worksheet dictionary

    Returns:
        (success, error_message) tuple
    """
    ws["gadgets"] = {}
    return True, None
