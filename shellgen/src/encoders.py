"""
Bad Character Encoding Module

Handles encoding of immediate values to avoid bad characters in shellgen.
Supports both 32-bit (dword) and 64-bit (qword) encoding.
"""

import struct


def contains_bad_chars(value_bytes, bad_chars):
    """Check if any byte in value_bytes is in the bad_chars set."""
    return any(b in bad_chars for b in value_bytes)


def encode_dword(target, bad_chars):
    """
    Find a (clean_value, sub_value) pair such that:
        clean_value - sub_value == target
    and neither clean_value nor sub_value contain bad chars.

    Returns (clean_value, sub_value) or None if not found.

    Handles consecutive bad characters by trying multiple offset increments.
    """
    target = target & 0xFFFFFFFF
    target_bytes = struct.pack("<I", target)

    # If target is already clean, no encoding needed
    if not contains_bad_chars(target_bytes, bad_chars):
        return None  # Signal: no encoding needed

    # Strategy 1: Try small offsets with varying increments
    # This handles consecutive bad characters better
    increment_strategies = [1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
                           0x101, 0x1001, 0x10001, 0x100001]

    for increment in increment_strategies:
        for multiplier in range(1, 1000):
            offset = increment * multiplier
            if offset > 0x00FFFFFF:
                break

            clean = (target + offset) & 0xFFFFFFFF
            clean_bytes = struct.pack("<I", clean)
            offset_bytes = struct.pack("<I", offset)

            if (not contains_bad_chars(clean_bytes, bad_chars) and
                    not contains_bad_chars(offset_bytes, bad_chars)):
                return (clean, offset)

    # Strategy 2: Try addition pairs (val1 + val2 = target)
    add_result = encode_dword_split(target, bad_chars)
    if add_result:
        # Convert to subtraction format for consistency
        val1, val2 = add_result
        # Return special marker for add operation
        return ("ADD", val1, val2)

    raise ValueError(f"Cannot encode 0x{target:08x} avoiding bad chars: "
                     f"{{{', '.join(f'0x{b:02x}' for b in bad_chars)}}}")


def encode_dword_split(target, bad_chars):
    """
    Alternative: split into two values that ADD to the target.
        val1 + val2 == target
    Useful when sub encoding doesn't find a pair quickly.
    """
    target = target & 0xFFFFFFFF
    for val1 in range(0x01010101, 0x7F7F7F7F, 0x01010101):
        val2 = (target - val1) & 0xFFFFFFFF
        val1_bytes = struct.pack("<I", val1)
        val2_bytes = struct.pack("<I", val2)
        if (not contains_bad_chars(val1_bytes, bad_chars) and
                not contains_bad_chars(val2_bytes, bad_chars)):
            return (val1, val2)
    return None


def encode_qword(target, bad_chars):
    """
    Encode a 64-bit qword by finding a clean pair.
    For x64 shellgen.

    Handles consecutive bad characters by trying multiple offset increments.
    """
    target = target & 0xFFFFFFFFFFFFFFFF
    target_bytes = struct.pack("<Q", target)

    if not contains_bad_chars(target_bytes, bad_chars):
        return None

    # Strategy 1: Try varying increments to handle consecutive bad chars
    increment_strategies = [1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
                           0x101, 0x1001, 0x10001, 0x100001, 0x1000001,
                           0x10000001, 0x100000001]

    for increment in increment_strategies:
        for multiplier in range(1, 1000):
            offset = increment * multiplier
            if offset > 0x00FFFFFFFFFFFFFF:
                break

            clean = (target + offset) & 0xFFFFFFFFFFFFFFFF
            clean_bytes = struct.pack("<Q", clean)
            offset_bytes = struct.pack("<Q", offset)

            if (not contains_bad_chars(clean_bytes, bad_chars) and
                    not contains_bad_chars(offset_bytes, bad_chars)):
                return (clean, offset)

    # Strategy 2: Try 64-bit addition pairs
    # Split target into two 64-bit values that add up to it
    for val1 in range(0x0101010101010101, 0x0F0F0F0F0F0F0F0F, 0x0101010101010101):
        if val1 > target:
            break
        val2 = (target - val1) & 0xFFFFFFFFFFFFFFFF
        val1_bytes = struct.pack("<Q", val1)
        val2_bytes = struct.pack("<Q", val2)
        if (not contains_bad_chars(val1_bytes, bad_chars) and
                not contains_bad_chars(val2_bytes, bad_chars)):
            return ("ADD", val1, val2)

    raise ValueError(f"Cannot encode 0x{target:016x} avoiding bad chars")


def string_to_push_dwords(s):
    """
    Convert a string to a list of dwords (little-endian) for pushing onto
    the stack in reverse order. Includes null terminator padding.
    """
    # Pad to 4-byte alignment with nulls
    s_bytes = s.encode("ascii") + b"\x00"
    while len(s_bytes) % 4 != 0:
        s_bytes += b"\x00"

    dwords = []
    for i in range(0, len(s_bytes), 4):
        dword = struct.unpack("<I", s_bytes[i:i+4])[0]
        dwords.append(dword)

    return dwords


def ror13_hash(name):
    """Compute the ROR13 hash of a function name (used in API resolution)."""
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h
