"""
ASM-like operations for the ROP worksheet.

This module implements Intel-syntax assembly operations:
mov, add, xor, xchg, inc, dec, neg
"""

from typing import Any, Dict, Optional, Tuple

from ..core.resolver import parse_target, resolve_value


def _handle_eip_auto_gadget(
    ws: Dict[str, Any], value: str
) -> Tuple[bool, Optional[str]]:
    """
    Process auto-gadget when setting EIP.

    Args:
        ws: Worksheet dictionary
        value: Value being set to EIP

    Returns:
        (gadget_executed, message) tuple
    """
    from ..gadgets.processor import find_gadget_by_address, process_gadget

    if not value or not ws.get("auto_gadget", True):
        return False, None

    gadget_str = find_gadget_by_address(ws, value)
    if not gadget_str:
        return False, None

    executed = process_gadget(ws, gadget_str, value)
    if executed:
        return True, f"Executed gadget: {' ; '.join(executed)}"

    return False, None


def _write_deref_to_stack(
    ws: Dict[str, Any], dst_key: str, value: str
) -> Tuple[bool, Optional[str]]:
    """
    Write value to stack at dereferenced register address.

    Args:
        ws: Worksheet dictionary
        dst_key: Register containing the address
        value: Value to write

    Returns:
        (success, error_message) tuple
    """
    reg_val = ws["registers"].get(dst_key, "0x00000000")
    if not reg_val or reg_val == "0x00000000":
        return False, f"{dst_key} does not contain a valid address"

    esp_str = ws["registers"].get("ESP", "0x00000000")
    if not esp_str or esp_str == "0x00000000":
        return False, "ESP not set"

    try:
        # Calculate offset from ESP
        addr = int(reg_val, 16)
        esp_val = int(esp_str, 16)
        offset = addr - esp_val

        # Format as stack offset
        if offset < 0:
            offset_str = f"-0x{abs(offset):02x}"
        else:
            offset_str = f"+0x{offset:02x}"

        # Write to stack at this offset
        ws["stack"][offset_str] = value
        return True, None
    except Exception:
        return False, f"Cannot dereference {dst_key}"


def _write_to_register(
    ws: Dict[str, Any], dst_key: str, value: str, dst: str, src: str
) -> Tuple[bool, Optional[str]]:
    """
    Write value to register and handle EIP auto-gadget processing.

    Args:
        ws: Worksheet dictionary
        dst_key: Register name
        value: Value to write
        dst: Original destination string (for logging)
        src: Original source string (for logging)

    Returns:
        (success, message) tuple - message is set if gadget executed
    """
    ws["registers"][dst_key] = value

    # Auto-process gadget if setting EIP
    if dst_key == "EIP":
        gadget_executed, gadget_msg = _handle_eip_auto_gadget(ws, value)
        if gadget_executed:
            # Log manual operation if enabled
            if ws.get("log_manual", True):
                log_execution(ws, "manual", "User", f"mov {dst}, {src}")
            return True, gadget_msg

    return True, None


def log_execution(ws: Dict[str, Any], exec_type: str, source: str, operation: str):
    """
    Add an operation to the execution log.

    Args:
        ws: Worksheet dictionary
        exec_type: "manual" or "auto"
        source: "User" for manual, address for auto
        operation: The operation string
    """
    log_entry = {"type": exec_type, "source": source, "operation": operation}

    ws["execution_log"].append(log_entry)

    # Keep only last 10 entries
    if len(ws["execution_log"]) > 10:
        ws["execution_log"] = ws["execution_log"][-10:]


def cmd_move(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Move value: mov dst, src (Intel syntax).

    Args:
        ws: Worksheet dictionary
        dst: Destination (register, stack, named value, or dereferenced register)
        src: Source expression

    Returns:
        (success, error_message) tuple
    """
    # Resolve source value
    value = resolve_value(src, ws)
    if value is None:
        return False, f"Cannot resolve source: {src}"

    # Parse destination
    dst_type, dst_key = parse_target(dst)

    # Handle different destination types
    if dst_type == "reg":
        success, msg = _write_to_register(ws, dst_key, value, dst, src)
        if msg:  # Gadget was executed
            return success, msg

    elif dst_type == "stack":
        ws["stack"][dst_key] = value

    elif dst_type == "deref":
        # Dereferenced register: [EAX], [ECX], etc.
        success, error_msg = _write_deref_to_stack(ws, dst_key, value)
        if not success:
            return False, error_msg

    elif dst_type == "named":
        ws["named"][dst_key] = value

    # Log manual operation if enabled (skip if in auto-gadget mode)
    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", f"mov {dst}, {src}")

    return True, None


def cmd_add(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Add: add dst, src (dst = dst + src).

    Args:
        ws: Worksheet dictionary
        dst: Destination
        src: Source expression

    Returns:
        (success, error_message) tuple
    """
    # Get current dst value
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    try:
        result = int(dst_val, 16) + int(src_val, 16)
        result_hex = f"0x{result & 0xffffffff:08x}"  # Keep 32-bit

        # Update destination
        dst_type, dst_key = parse_target(dst)
        if dst_type == "reg":
            ws["registers"][dst_key] = result_hex
        elif dst_type == "stack":
            ws["stack"][dst_key] = result_hex

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"add {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for add"


def cmd_xor(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    XOR: xor dst, src (dst = dst ^ src).

    Args:
        ws: Worksheet dictionary
        dst: Destination
        src: Source expression

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    try:
        result = int(dst_val, 16) ^ int(src_val, 16)
        result_hex = f"0x{result & 0xffffffff:08x}"

        dst_type, dst_key = parse_target(dst)
        if dst_type == "reg":
            ws["registers"][dst_key] = result_hex
        elif dst_type == "stack":
            ws["stack"][dst_key] = result_hex

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"xor {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for xor"


def cmd_xchg(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Exchange: xchg dst, src (swap values).

    Args:
        ws: Worksheet dictionary
        dst: First operand
        src: Second operand

    Returns:
        (success, error_message) tuple
    """
    # Get both values
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    # Parse both targets
    dst_type, dst_key = parse_target(dst)
    src_type, src_key = parse_target(src)

    # Swap the values
    if dst_type == "reg":
        ws["registers"][dst_key] = src_val
    elif dst_type == "stack":
        ws["stack"][dst_key] = src_val
    elif dst_type == "named":
        ws["named"][dst_key] = src_val

    if src_type == "reg":
        ws["registers"][src_key] = dst_val
    elif src_type == "stack":
        ws["stack"][src_key] = dst_val
    elif src_type == "named":
        ws["named"][src_key] = dst_val

    # Log manual operation if enabled (skip if in auto-gadget mode)
    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", f"xchg {dst}, {src}")

    return True, None


def cmd_inc(ws: Dict[str, Any], dst: str) -> Tuple[bool, Optional[str]]:
    """
    Increment: inc dst (dst = dst + 1).

    Args:
        ws: Worksheet dictionary
        dst: Destination

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)

    if dst_val is None:
        return False, "Cannot resolve operand"

    try:
        result = (int(dst_val, 16) + 1) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        if dst_type == "reg":
            ws["registers"][dst_key] = result_hex
        elif dst_type == "stack":
            ws["stack"][dst_key] = result_hex

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"inc {dst}")

        return True, None
    except Exception:
        return False, "Invalid operand for inc"


def cmd_dec(ws: Dict[str, Any], dst: str) -> Tuple[bool, Optional[str]]:
    """
    Decrement: dec dst (dst = dst - 1).

    Args:
        ws: Worksheet dictionary
        dst: Destination

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)

    if dst_val is None:
        return False, "Cannot resolve operand"

    try:
        result = (int(dst_val, 16) - 1) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        if dst_type == "reg":
            ws["registers"][dst_key] = result_hex
        elif dst_type == "stack":
            ws["stack"][dst_key] = result_hex

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"dec {dst}")

        return True, None
    except Exception:
        return False, "Invalid operand for dec"


def cmd_neg(ws: Dict[str, Any], dst: str) -> Tuple[bool, Optional[str]]:
    """
    Negate: neg dst (two's complement).

    Args:
        ws: Worksheet dictionary
        dst: Destination

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)

    if dst_val is None:
        return False, "Cannot resolve operand"

    try:
        # Two's complement negation
        result = (~int(dst_val, 16) + 1) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        if dst_type == "reg":
            ws["registers"][dst_key] = result_hex
        elif dst_type == "stack":
            ws["stack"][dst_key] = result_hex

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"neg {dst}")

        return True, None
    except Exception:
        return False, "Invalid operand for neg"
