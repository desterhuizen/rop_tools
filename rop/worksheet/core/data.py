"""
Worksheet data structure definition.

This module defines the core data structure for the ROP worksheet,
which tracks registers, stack, named values, gadgets, and ROP chains.
"""

from typing import Dict, List, Any


def blank_worksheet() -> Dict[str, Any]:
    """
    Create a blank ROP worksheet with default structure.

    Returns:
        Dictionary containing:
        - registers: 32-bit x86 registers (EAX-ESP, EIP)
        - stack: Stack values at ESP-relative offsets
        - named: Named values (symbolic names for addresses)
        - gadgets: Gadget library (address -> instruction string)
        - chain: ROP chain payload (list of entries)
        - notes: General notes string
        - auto_gadget: Auto-execute gadgets when EIP is set (bool)
        - execution_log: Rolling log of executed operations
        - log_manual: Log manual operations (bool)
    """
    return {
        "registers": {r: "0x00000000" for r in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]},
        "stack": {},       # offset -> value (e.g., "+0x00": "0xdeadbeef")
        "named": {},       # name -> value (e.g., "shellcode": "0x00501000")
        "gadgets": {},     # address -> instruction string (gadget library)
        "chain": [],       # list of addresses/values (ROP chain payload)
        "notes": "",
        "auto_gadget": True,  # Auto-execute gadgets when EIP is set
        "execution_log": [],  # Rolling log of executed operations
        "log_manual": True,   # Log manual operations (mov, add, etc.)
    }