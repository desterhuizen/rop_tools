"""
ASM-like operations for the ROP worksheet.

This module implements Intel-syntax assembly operations:
mov, add, sub, xor, xchg, inc, dec, neg, and, or, shl, shr, ror, rol, not
"""

from typing import Any, Dict, Optional, Tuple

from ..core.resolver import (
    parse_target,
    resolve_lea_expression,
    resolve_value,
    write_sub_register,
)


def _write_to_target(
    ws: Dict[str, Any], dst_type: str, dst_key: str, value: str
) -> Tuple[bool, Optional[str]]:
    """
    Write a value to a parsed target (reg, subreg, stack, deref, named).

    Args:
        ws: Worksheet dictionary
        dst_type: Target type from parse_target()
        dst_key: Target key from parse_target()
        value: Hex value to write

    Returns:
        (success, error_message) tuple
    """
    if dst_type == "reg":
        ws["registers"][dst_key] = value
        return True, None
    elif dst_type == "subreg":
        success = write_sub_register(dst_key, value, ws)
        if not success:
            return False, f"Cannot write to sub-register: {dst_key}"
        return True, None
    elif dst_type == "stack":
        ws["stack"][dst_key] = value
        return True, None
    elif dst_type == "deref":
        return _write_deref_to_stack(ws, dst_key, value)
    elif dst_type == "named":
        ws["named"][dst_key] = value
        return True, None
    return False, f"Unknown target type: {dst_type}"


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
    from ..gadgets.processor import (
        find_gadget_by_address,
        format_executed_list,
        process_gadget,
    )

    if not value or not ws.get("auto_gadget", True):
        return False, None

    gadget_str = find_gadget_by_address(ws, value)
    if not gadget_str:
        return False, None

    executed = process_gadget(ws, gadget_str, value)
    if executed:
        return True, f"Executed gadget: {format_executed_list(executed)}"

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

    # Special handling for EIP (auto-gadget processing)
    if dst_type == "reg" and dst_key == "EIP":
        success, msg = _write_to_register(ws, dst_key, value, dst, src)
        if msg:  # Gadget was executed
            return success, msg
    else:
        success, error_msg = _write_to_target(ws, dst_type, dst_key, value)
        if not success:
            return False, error_msg

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
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"add {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for add"


def cmd_sub(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Subtract: sub dst, src (dst = dst - src).

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
        result = int(dst_val, 16) - int(src_val, 16)
        result_hex = f"0x{result & 0xffffffff:08x}"  # Keep 32-bit

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"sub {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for sub"


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
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

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
    success, err = _write_to_target(ws, dst_type, dst_key, src_val)
    if not success:
        return False, err

    success, err = _write_to_target(ws, src_type, src_key, dst_val)
    if not success:
        return False, err

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
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

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
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

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
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        # Log manual operation if enabled (skip if in auto-gadget mode)
        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"neg {dst}")

        return True, None
    except Exception:
        return False, "Invalid operand for neg"


# ============================================================================
# Phase 2 — Two-Operand Instructions
# ============================================================================


def cmd_and(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Bitwise AND: and dst, src (dst = dst & src).

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
        result = int(dst_val, 16) & int(src_val, 16)
        result_hex = f"0x{result & 0xffffffff:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"and {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for and"


def cmd_or(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Bitwise OR: or dst, src (dst = dst | src).

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
        result = int(dst_val, 16) | int(src_val, 16)
        result_hex = f"0x{result & 0xffffffff:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"or {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for or"


def cmd_shl(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Shift left: shl dst, imm (dst = dst << imm).

    Args:
        ws: Worksheet dictionary
        dst: Destination
        src: Shift amount (immediate or register)

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    try:
        shift = int(src_val, 16) & 0x1F  # x86 masks shift to 5 bits
        result = (int(dst_val, 16) << shift) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"shl {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for shl"


def cmd_shr(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Logical shift right: shr dst, imm (dst = dst >> imm).

    Args:
        ws: Worksheet dictionary
        dst: Destination
        src: Shift amount (immediate or register)

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    try:
        shift = int(src_val, 16) & 0x1F
        result = (int(dst_val, 16) >> shift) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"shr {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for shr"


def cmd_ror(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Rotate right: ror dst, imm.

    Args:
        ws: Worksheet dictionary
        dst: Destination
        src: Rotation amount

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    try:
        val = int(dst_val, 16) & 0xFFFFFFFF
        rot = int(src_val, 16) & 0x1F
        result = ((val >> rot) | (val << (32 - rot))) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"ror {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for ror"


def cmd_rol(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Rotate left: rol dst, imm.

    Args:
        ws: Worksheet dictionary
        dst: Destination
        src: Rotation amount

    Returns:
        (success, error_message) tuple
    """
    dst_val = resolve_value(dst, ws)
    src_val = resolve_value(src, ws)

    if dst_val is None or src_val is None:
        return False, "Cannot resolve operands"

    try:
        val = int(dst_val, 16) & 0xFFFFFFFF
        rot = int(src_val, 16) & 0x1F
        result = ((val << rot) | (val >> (32 - rot))) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"rol {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for rol"


# ============================================================================
# Phase 3 — Single-Operand Instructions
# ============================================================================


def cmd_not(ws: Dict[str, Any], dst: str) -> Tuple[bool, Optional[str]]:
    """
    Bitwise NOT: not dst (dst = ~dst).

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
        result = ~int(dst_val, 16) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"not {dst}")

        return True, None
    except Exception:
        return False, "Invalid operand for not"


# ============================================================================
# Phase 4 — Zero-Operand Instructions
# ============================================================================


def cmd_cdq(ws: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    CDQ: sign-extend EAX into EDX:EAX.

    EDX = 0xFFFFFFFF if EAX bit 31 is set, else 0x00000000.
    Common trick: when EAX < 0x80000000, this zeros EDX.

    Args:
        ws: Worksheet dictionary

    Returns:
        (success, error_message) tuple
    """
    eax_val = ws["registers"].get("EAX", "0x00000000")
    try:
        eax = int(eax_val, 16)
        if eax & 0x80000000:
            ws["registers"]["EDX"] = "0xffffffff"
        else:
            ws["registers"]["EDX"] = "0x00000000"

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", "cdq")

        return True, None
    except Exception:
        return False, "Invalid state for cdq"


def cmd_lodsd(ws: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    LODSD: load dword from [ESI] into EAX, then ESI += 4.

    Args:
        ws: Worksheet dictionary

    Returns:
        (success, error_message) tuple
    """
    # Read value at [ESI] (resolve as dereferenced register)
    value = resolve_value("[ESI]", ws)
    if value is None:
        return False, "Cannot read [ESI] — ESI may not point to a valid stack address"

    ws["registers"]["EAX"] = value

    # Increment ESI by 4
    try:
        esi = int(ws["registers"].get("ESI", "0x00000000"), 16)
        ws["registers"]["ESI"] = f"0x{(esi + 4) & 0xFFFFFFFF:08x}"
    except (ValueError, TypeError):
        return False, "Invalid ESI value"

    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", "lodsd")

    return True, None


def cmd_stosd(ws: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    STOSD: store EAX to [EDI], then EDI += 4.

    Args:
        ws: Worksheet dictionary

    Returns:
        (success, error_message) tuple
    """
    eax_val = ws["registers"].get("EAX", "0x00000000")

    # Write EAX to [EDI] (dereference EDI to stack offset)
    edi_val = ws["registers"].get("EDI", "0x00000000")
    esp_str = ws["registers"].get("ESP", "0x00000000")

    if not edi_val or edi_val == "0x00000000":
        return False, "EDI does not contain a valid address"
    if not esp_str or esp_str == "0x00000000":
        return False, "ESP not set"

    try:
        addr = int(edi_val, 16)
        esp_val = int(esp_str, 16)
        offset = addr - esp_val

        if offset < 0:
            offset_str = f"-0x{abs(offset):02x}"
        else:
            offset_str = f"+0x{offset:02x}"

        ws["stack"][offset_str] = eax_val

        # Increment EDI by 4
        ws["registers"]["EDI"] = f"0x{(addr + 4) & 0xFFFFFFFF:08x}"
    except (ValueError, TypeError):
        return False, "Cannot dereference EDI"

    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", "stosd")

    return True, None


def cmd_nop(ws: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    NOP: no operation.

    Args:
        ws: Worksheet dictionary

    Returns:
        (success, error_message) tuple
    """
    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", "nop")

    return True, None


# ============================================================================
# Phase 5 — Data Movement
# ============================================================================


def cmd_movzx(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Move with zero-extend: movzx dst, src.

    The source is read (8-bit or 16-bit) and zero-extended into the
    destination (typically 32-bit).

    Args:
        ws: Worksheet dictionary
        dst: Destination register
        src: Source (sub-register or value)

    Returns:
        (success, error_message) tuple
    """
    src_val = resolve_value(src, ws)
    if src_val is None:
        return False, f"Cannot resolve source: {src}"

    try:
        # Zero-extend: just take the value as-is (already zero-extended
        # since we read sub-registers with masking)
        result = int(src_val, 16) & 0xFFFFFFFF
        result_hex = f"0x{result:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"movzx {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for movzx"


def cmd_movsxd(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Move with sign-extend: movsxd dst, src.

    Sign-extends the source value into the destination. For 8-bit sources,
    bit 7 is the sign bit; for 16-bit, bit 15.

    Args:
        ws: Worksheet dictionary
        dst: Destination register
        src: Source (sub-register or value)

    Returns:
        (success, error_message) tuple
    """
    from ..core.resolver import SUB_REGISTER_MAP

    src_val = resolve_value(src, ws)
    if src_val is None:
        return False, f"Cannot resolve source: {src}"

    try:
        val = int(src_val, 16)

        # Determine source width from register name and sign-extend
        src_upper = src.strip().upper()
        if src_upper in SUB_REGISTER_MAP:
            mask = SUB_REGISTER_MAP[src_upper][1]
            if mask == 0xFF and val & 0x80:  # 8-bit negative
                val = val | 0xFFFFFF00
            elif mask == 0xFFFF and val & 0x8000:  # 16-bit negative
                val = val | 0xFFFF0000

        result_hex = f"0x{val & 0xFFFFFFFF:08x}"

        dst_type, dst_key = parse_target(dst)
        success, err = _write_to_target(ws, dst_type, dst_key, result_hex)
        if not success:
            return False, err

        if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
            log_execution(ws, "manual", "User", f"movsxd {dst}, {src}")

        return True, None
    except Exception:
        return False, "Invalid operands for movsxd"


# ============================================================================
# Phase 6 — LEA
# ============================================================================


def cmd_lea(ws: Dict[str, Any], dst: str, src: str) -> Tuple[bool, Optional[str]]:
    """
    Load effective address: lea dst, [expression].

    Computes the address from the bracket expression without memory access.
    Supports: [reg], [reg+off], [reg+reg], [reg+reg*scale], [reg+reg*scale+off].

    Args:
        ws: Worksheet dictionary
        dst: Destination register
        src: Bracket expression (e.g., "[ecx+edx*4+0x10]")

    Returns:
        (success, error_message) tuple
    """
    result = resolve_lea_expression(src, ws)
    if result is None:
        return False, f"Cannot resolve LEA expression: {src}"

    dst_type, dst_key = parse_target(dst)
    success, err = _write_to_target(ws, dst_type, dst_key, result)
    if not success:
        return False, err

    if ws.get("log_manual", True) and not ws.get("_in_auto_gadget", False):
        log_execution(ws, "manual", "User", f"lea {dst}, {src}")

    return True, None
