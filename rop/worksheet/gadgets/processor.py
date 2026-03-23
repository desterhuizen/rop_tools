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
        known_regs: List of known register names

    Returns:
        True if all operands are valid, False otherwise
    """
    for op in operands:
        if not op:
            continue
        # Check if it's a known register
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
        # Unknown operand
        return False
    return True


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
    from ..operations.asm_ops import (
        cmd_add,
        cmd_dec,
        cmd_inc,
        cmd_move,
        cmd_neg,
        cmd_sub,
        cmd_xchg,
        cmd_xor,
    )
    from ..operations.stack_ops import cmd_pop, cmd_push

    if opcode == "mov" and len(operands) == 2:
        return cmd_move(ws, operands[0], operands[1])
    elif opcode == "add" and len(operands) == 2:
        return cmd_add(ws, operands[0], operands[1])
    elif opcode == "sub" and len(operands) == 2:
        return cmd_sub(ws, operands[0], operands[1])
    elif opcode == "xor" and len(operands) == 2:
        return cmd_xor(ws, operands[0], operands[1])
    elif opcode == "xchg" and len(operands) == 2:
        return cmd_xchg(ws, operands[0], operands[1])
    elif opcode == "inc" and len(operands) == 1:
        return cmd_inc(ws, operands[0])
    elif opcode == "dec" and len(operands) == 1:
        return cmd_dec(ws, operands[0])
    elif opcode == "neg" and len(operands) == 1:
        return cmd_neg(ws, operands[0])
    elif opcode == "pop" and len(operands) == 1:
        return cmd_pop(ws, operands[0])
    elif opcode == "push" and len(operands) == 1:
        return cmd_push(ws, operands[0])

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
    known_regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]

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
