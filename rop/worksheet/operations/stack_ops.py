"""
Stack manipulation operations for the ROP worksheet.

This module implements stack operations: push, pop, and direct stack manipulation.
"""

import re
from typing import Dict, Any, Tuple, Optional
from ..core.resolver import resolve_value, parse_target


def log_execution(ws: Dict[str, Any], exec_type: str, source: str, operation: str):
    """
    Add an operation to the execution log.

    Args:
        ws: Worksheet dictionary
        exec_type: "manual" or "auto"
        source: "User" for manual, address for auto
        operation: The operation string
    """
    log_entry = {
        "type": exec_type,
        "source": source,
        "operation": operation
    }

    ws["execution_log"].append(log_entry)

    # Keep only last 10 entries
    if len(ws["execution_log"]) > 10:
        ws["execution_log"] = ws["execution_log"][-10:]


def cmd_push(ws: Dict[str, Any], src: str) -> Tuple[bool, Optional[str]]:
    """
    Push to stack: push src (ESP -= 4, [ESP] = src).

    Args:
        ws: Worksheet dictionary
        src: Source expression

    Returns:
        (success, error_message) tuple
    """
    # Resolve source value
    value = resolve_value(src, ws)
    if value is None:
        return False, f"Cannot resolve source: {src}"

    # Get current ESP
    esp_val = ws["registers"].get("ESP", "0x00000000")

    try:
        # Decrement ESP by 4 FIRST
        current_esp = int(esp_val, 16)
        new_esp = (current_esp - 4) & 0xffffffff
        ws["registers"]["ESP"] = f"0x{new_esp:08x}"

        # Adjust all existing stack offsets by +4 (they're farther from new ESP)
        new_stack = {}
        for offset_str, val in ws["stack"].items():
            # Parse the offset
            offset_val = int(offset_str, 16)
            # Adjust by +4
            new_offset_val = offset_val + 4
            # Format as string
            if new_offset_val < 0:
                new_offset_str = f"-0x{abs(new_offset_val):02x}"
            else:
                new_offset_str = f"+0x{new_offset_val:02x}"
            new_stack[new_offset_str] = val

        # Store the pushed value at +0x00 (new top of stack)
        new_stack["+0x00"] = value
        ws["stack"] = new_stack

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"push {src}")

        return True, None
    except Exception as e:
        return False, f"Failed to push: {e}"


def cmd_pop(ws: Dict[str, Any], dst: str) -> Tuple[bool, Optional[str]]:
    """
    Pop from stack: pop dst (dst = [ESP], ESP += 4).

    Args:
        ws: Worksheet dictionary
        dst: Destination

    Returns:
        (success, error_message) tuple
    """
    # Import here to avoid circular dependency
    from ..gadgets.processor import find_gadget_by_address, process_gadget

    # Get value at ESP
    esp_val = ws["registers"].get("ESP", "")
    if not esp_val:
        return False, "ESP not set"

    # Pop gets value at ESP+0x00 (top of stack)
    stack_val = ws["stack"].get("+0x00", None)
    if stack_val is None:
        return False, f"No value at [ESP] (offset +0x00) to pop"

    # Move stack value to destination
    dst_type, dst_key = parse_target(dst)
    if dst_type == "reg":
        ws["registers"][dst_key] = stack_val
    elif dst_type == "stack":
        ws["stack"][dst_key] = stack_val

    # Increment ESP by 4 FIRST
    current_esp = int(esp_val, 16)
    new_esp = (current_esp + 4) & 0xffffffff
    ws["registers"]["ESP"] = f"0x{new_esp:08x}"

    # Adjust all stack offsets by -4 (they're all 4 bytes closer to ESP now)
    new_stack = {}
    for offset_str, value in ws["stack"].items():
        # Parse the offset
        offset_val = int(offset_str, 16)
        # Adjust by -4
        new_offset_val = offset_val - 4
        # Format as string
        if new_offset_val < 0:
            new_offset_str = f"-0x{abs(new_offset_val):02x}"
        else:
            new_offset_str = f"+0x{new_offset_val:02x}"
        new_stack[new_offset_str] = value

    ws["stack"] = new_stack

    # Remove the value that was at +0x00 (now at -0x04, which doesn't make sense)
    if "-0x04" in ws["stack"]:
        del ws["stack"]["-0x04"]

    # Log manual operation if enabled (skip if in auto-gadget mode)
    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", f"pop {dst}")

    # Auto-process gadget if popping into EIP (and auto-gadget is enabled)
    if dst_key == "EIP" and stack_val and ws.get("auto_gadget", True):
        gadget_str = find_gadget_by_address(ws, stack_val)
        if gadget_str:
            executed = process_gadget(ws, gadget_str, stack_val)
            if executed:
                return True, f"Executed gadget: {' ; '.join(executed)}"

    return True, None


def cmd_stack(ws: Dict[str, Any], offset_str: str, value: str) -> Tuple[bool, Optional[str]]:
    """
    Directly set stack value at offset without affecting ESP.

    Args:
        ws: Worksheet dictionary
        offset_str: Offset string (e.g., "+0x10", "ESP+0x10", or register name)
        value: Value to set

    Returns:
        (success, error_message) tuple
    """
    # Parse offset - can be like "+0x10", "ESP+0x10", "0x10", or a register containing a stack address
    offset_str = offset_str.strip()

    # Check if offset_str is a register name
    if offset_str.upper() in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"]:
        # Get the register's value
        reg_value = ws["registers"].get(offset_str.upper(), "0x00000000")
        if not reg_value or reg_value == "0x00000000":
            return False, f"{offset_str.upper()} does not contain a valid address"

        # Get current ESP value
        esp_str = ws["registers"].get("ESP", "0x00000000")
        if not esp_str or esp_str == "0x00000000":
            return False, "ESP not set"

        try:
            # Calculate offset from ESP
            reg_addr = int(reg_value, 16)
            esp_val = int(esp_str, 16)
            offset = reg_addr - esp_val

            # Format offset as string
            if offset < 0:
                offset_str = f"-0x{abs(offset):02x}"
            else:
                offset_str = f"+0x{offset:02x}"
        except ValueError:
            return False, f"Invalid address in {offset_str.upper()}"
    else:
        # Remove "ESP" prefix if present (case-insensitive)
        if offset_str.upper().startswith("ESP"):
            offset_str = offset_str[3:]

        # Ensure it starts with + or -
        if not offset_str.startswith('+') and not offset_str.startswith('-'):
            offset_str = '+' + offset_str

        # Validate offset format (case-insensitive for 0x)
        if not re.match(r'^[+-]0x[0-9a-fA-F]+$', offset_str, re.IGNORECASE):
            return False, f"Invalid offset format: {offset_str}"

    # Try to resolve the value (handles registers, stack refs, named values)
    resolved_value = resolve_value(value, ws)
    if resolved_value is not None:
        value = resolved_value
    # else: keep original value (for raw hex or named values that don't exist yet)

    # Store value at the offset
    ws["stack"][offset_str] = value
    return True, None