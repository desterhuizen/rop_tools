"""
ROP chain building and management.

This module handles adding, removing, and clearing entries in the ROP chain.
"""

import re
from typing import Any, Dict, Optional, Tuple


def cmd_chain_add(ws: Dict[str, Any], value: str) -> Tuple[bool, Optional[str]]:
    """
    Add an entry to the ROP chain - can be address, gadget ID, or literal value.

    Args:
        ws: Worksheet dictionary
        value: Value to add (address, gadget ID like G1, or literal)

    Returns:
        (success, error_message) tuple
    """
    value = value.strip()

    # Check if it's a gadget ID (G1, G2, etc.)
    if re.match(r"^[Gg]\d+$", value):
        gadget_id = int(value[1:])  # Remove 'G' prefix and get number

        # Get sorted gadgets to match ID
        sorted_gadgets = sorted(
            ws["gadgets"].items(),
            key=lambda x: int(x[0], 16) if x[0].startswith("0x") else 0,
        )

        if 1 <= gadget_id <= len(sorted_gadgets):
            # Get the address for this gadget ID
            address = sorted_gadgets[gadget_id - 1][0]
            ws["chain"].append({"type": "address", "value": address})
            return True, None
        else:
            return (
                False,
                f"Gadget ID {value} not found (only {len(sorted_gadgets)} gadgets in library)",
            )

    # Check if it's a hex address
    elif value.startswith("0x") or re.match(r"^[0-9a-fA-F]+$", value):
        # Normalize to 0x format
        if not value.startswith("0x"):
            value = "0x" + value
        value = value.lower()
        ws["chain"].append({"type": "address", "value": value})
        return True, None

    # Otherwise it's a literal value (placeholder)
    else:
        ws["chain"].append({"type": "literal", "value": value})
        return True, None


def cmd_chain_del(ws: Dict[str, Any], index: str) -> Tuple[bool, Optional[str]]:
    """
    Remove a chain entry by index.

    Args:
        ws: Worksheet dictionary
        index: Index string (1-based)

    Returns:
        (success, error_message) tuple
    """
    try:
        idx = int(index) - 1
        if 0 <= idx < len(ws["chain"]):
            ws["chain"].pop(idx)
            return True, None
        else:
            return False, "Invalid index"
    except:
        return False, "Invalid index"


def cmd_chain_clear(ws: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Clear all entries from the chain.

    Args:
        ws: Worksheet dictionary

    Returns:
        (success, error_message) tuple
    """
    ws["chain"] = []
    return True, None
