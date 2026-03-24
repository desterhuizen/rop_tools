"""
Gadget auto-execution processor.

This module handles automatic processing of gadget instruction chains
when EIP is set (if auto-gadget mode is enabled).
"""

import re
from typing import Any, Dict, List, Optional, Tuple


def _validate_operands(operands: List[str], known_regs: List[str]) -> bool:
    """
    Validate that all operands are known registers or hex values.

    Args:
        operands: List of operand strings
        known_regs: List of known register names (includes sub-registers)

    Returns:
        True if all operands are valid, False otherwise
    """
    for op in operands:
        if not op:
            continue
        # Check if it's a known register (32-bit or sub-register)
        if op.upper() in known_regs:
            continue
        # Check if it's a hex value
        if re.match(r"^0x[0-9a-fA-F]+$", op, re.IGNORECASE):
            continue
        # Check if it's a stack reference like [esp+0x10]
        if re.match(r"\[?ESP[+-]0x[0-9a-fA-F]+\]?", op, re.IGNORECASE):
            continue
        # Check if it's a dereferenced register like [eax], [ecx], etc.
        if re.match(r"\[(" + "|".join(known_regs) + r")\]", op, re.IGNORECASE):
            continue
        # Check if it's a bracket expression (LEA-style): [reg+reg*scale+offset]
        if re.match(r"\[.+\]", op):
            continue
        # Unknown operand
        return False
    return True


def _build_dispatch_table():
    """Build opcode → (operand_count, handler) dispatch table."""
    from ..operations.asm_ops import (
        cmd_add,
        cmd_and,
        cmd_cdq,
        cmd_dec,
        cmd_inc,
        cmd_lea,
        cmd_lodsd,
        cmd_move,
        cmd_movsxd,
        cmd_movzx,
        cmd_neg,
        cmd_nop,
        cmd_not,
        cmd_or,
        cmd_rol,
        cmd_ror,
        cmd_shl,
        cmd_shr,
        cmd_stosd,
        cmd_sub,
        cmd_xchg,
        cmd_xor,
    )
    from ..operations.stack_ops import cmd_pop, cmd_push

    return {
        # Two-operand
        "mov": (2, cmd_move),
        "add": (2, cmd_add),
        "sub": (2, cmd_sub),
        "xor": (2, cmd_xor),
        "xchg": (2, cmd_xchg),
        "and": (2, cmd_and),
        "or": (2, cmd_or),
        "shl": (2, cmd_shl),
        "shr": (2, cmd_shr),
        "ror": (2, cmd_ror),
        "rol": (2, cmd_rol),
        "movzx": (2, cmd_movzx),
        "movsxd": (2, cmd_movsxd),
        "lea": (2, cmd_lea),
        # Single-operand
        "inc": (1, cmd_inc),
        "dec": (1, cmd_dec),
        "neg": (1, cmd_neg),
        "not": (1, cmd_not),
        "pop": (1, cmd_pop),
        "push": (1, cmd_push),
        # Zero-operand
        "cdq": (0, cmd_cdq),
        "lodsd": (0, cmd_lodsd),
        "stosd": (0, cmd_stosd),
        "nop": (0, cmd_nop),
    }


_dispatch_table = None


def _execute_instruction(
    ws: Dict[str, Any], opcode: str, operands: List[str]
) -> Tuple[bool, Optional[str]]:
    """
    Execute a single instruction.

    Args:
        ws: Worksheet dictionary
        opcode: Instruction opcode
        operands: List of operands

    Returns:
        (success, error_message) tuple
    """
    global _dispatch_table
    if _dispatch_table is None:
        _dispatch_table = _build_dispatch_table()

    entry = _dispatch_table.get(opcode)
    if not entry:
        return False, None

    expected_count = entry[0]
    # Normalize: [''] (from empty operand string) counts as 0 operands
    actual_count = len(operands) if operands != [""] else 0

    if actual_count == expected_count:
        if expected_count == 0:
            return entry[1](ws)
        return entry[1](ws, *operands)

    return False, None


def _parse_instruction(inst: str) -> Optional[Tuple[str, List[str]]]:
    """
    Parse instruction string into opcode and operands.

    Args:
        inst: Instruction string

    Returns:
        (opcode, operands) tuple or None if invalid
    """
    parts = inst.split(None, 1)
    if not parts:
        return None

    opcode = parts[0].lower()
    operands_str = parts[1] if len(parts) > 1 else ""
    operands = [op.strip() for op in operands_str.split(",")]

    return opcode, operands


def log_execution(ws: Dict[str, Any], exec_type: str, source: str, operation: str):
    """
    Add an operation to the execution log.

    Args:
        ws: Worksheet dictionary
        exec_type: "manual" or "auto"
        source: "User" for manual, address for auto (e.g., "0x1010adf1")
        operation: The operation string (e.g., "mov EAX, 0xdeadbeef")
    """
    log_entry = {"type": exec_type, "source": source, "operation": operation}

    # Add to log
    ws["execution_log"].append(log_entry)

    # Keep only last 10 entries
    if len(ws["execution_log"]) > 10:
        ws["execution_log"] = ws["execution_log"][-10:]


def find_gadget_by_address(ws: Dict[str, Any], addr: str) -> Optional[str]:
    """
    Find a gadget in the gadget library by its address.

    Args:
        ws: Worksheet dictionary
        addr: Address string (e.g., "0x1001234")

    Returns:
        Gadget instruction string or None if not found
    """
    return ws.get("gadgets", {}).get(addr.lower())


def process_gadget(
    ws: Dict[str, Any], gadget_str: str, gadget_addr: Optional[str] = None
) -> List[str]:
    """
    Automatically process a gadget instruction chain.

    Example: "add bl, al ; mov eax, 0x02FAF080 ; ret"

    - Splits instructions by semicolon
    - Only processes known 32-bit registers (EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP)
    - Ignores unsupported instructions (8-bit/16-bit registers, unknown ops)
    - Stops at 'ret'

    Args:
        ws: Worksheet dictionary
        gadget_str: Gadget instruction string
        gadget_addr: Optional address of the gadget

    Returns:
        List of successfully executed instruction strings
    """
    from ..core.resolver import ALL_REGISTERS

    known_regs = ALL_REGISTERS

    # Set flag to prevent cmd functions from logging (we'll log here instead)
    ws["_in_auto_gadget"] = True

    # Split by semicolon
    instructions = [inst.strip() for inst in gadget_str.split(";")]
    executed = []

    for inst in instructions:
        if not inst:
            continue

        # Stop at ret
        if inst.lower() in ["ret", "retn"]:
            break

        # Parse instruction
        parsed = _parse_instruction(inst)
        if not parsed:
            continue

        opcode, operands = parsed

        # Validate operands
        if not _validate_operands(operands, known_regs):
            continue

        # Execute instruction
        try:
            success, error_msg = _execute_instruction(ws, opcode, operands)

            if success:
                executed.append(inst)
                # Log the auto-executed instruction
                source = gadget_addr if gadget_addr else "Auto"
                log_execution(ws, "auto", source, inst)
            elif error_msg:
                # Log failed instruction with error message
                executed.append(f"[FAILED: {error_msg}] {inst}")
        except Exception as e:
            # Log exception
            executed.append(f"[ERROR: {e}] {inst}")

    # Clear the flag
    ws["_in_auto_gadget"] = False

    return executed
