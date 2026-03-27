"""Stack padding generation for vulnerability templates.

Generates C++ local variable declarations that sit between the vulnerable
buffer and saved EBP/EIP on the stack. These increase the offset the
attacker must calculate and make the stack layout more realistic.

Also generates optional landing-pad truncation code that limits how many
bytes of controlled data exist after the EIP overwrite, forcing short
jumps or first-stage stagers in tight scenarios.
"""

from target_builder.src.config import PaddingStyle, StackLayoutConfig


def generate_padding_vars(layout: StackLayoutConfig) -> str:
    """Generate C++ local variable declarations for stack padding.

    Variables are declared BEFORE the vulnerable buffer in the generated
    function. On MSVC /Od, first-declared locals are closer to saved EBP,
    so these sit between the buffer overflow and the return address.

    Args:
        layout: Stack layout configuration.

    Returns:
        C++ code block with local variable declarations, or empty string.
    """
    size = layout.pre_padding_size
    if size <= 0 or layout.padding_style == PaddingStyle.NONE:
        return ""

    style = layout.padding_style

    if style == PaddingStyle.ARRAY:
        return _array_padding(size)
    elif style == PaddingStyle.MIXED:
        return _mixed_padding(size)
    elif style == PaddingStyle.STRUCT:
        return _struct_padding(size)
    elif style == PaddingStyle.MULTI:
        return _multi_array_padding(size)

    return ""


def generate_landing_pad_truncation(
    layout: StackLayoutConfig,
    data_param: str,
    len_param: str,
    buffer_size: int,
    seh: bool = False,
) -> str:
    """Generate C++ code to truncate input, limiting post-overwrite space.

    When landing_pad_size is set, the server caps the received data so
    only a limited number of bytes can be placed after the critical
    overwrite target. This forces attackers to use short jumps or
    first-stage stagers.

    For BOF the max processed size is:
        buffer_size + pre_padding + 8 (saved EBP + EIP) + landing_pad

    For SEH the frame overhead is larger because MSVC __try/__except
    places nSEH (4) + handler (4) + scope/try-level (4) on the stack
    between the buffer and saved EBP/EIP:
        buffer_size + pre_padding + 20 (SEH + EBP + EIP) + landing_pad

    Args:
        layout: Stack layout configuration.
        data_param: Name of the data pointer parameter.
        len_param: Name of the length parameter.
        buffer_size: Size of the vulnerable buffer.
        seh: True for SEH overflow (larger frame overhead).

    Returns:
        C++ code block with truncation logic, or empty string.
    """
    if layout.landing_pad_size <= 0:
        return ""

    # BOF: saved EBP (4) + saved EIP (4) = 8
    # SEH: nSEH (4) + handler (4) + try-level (4) + saved EBP (4)
    #       + saved EIP (4) = 20
    frame_overhead = 20 if seh else 8
    max_size = (
        buffer_size + layout.pre_padding_size + frame_overhead + layout.landing_pad_size
    )

    return f"""\
    // Server-side payload cap — limits shellcode space after EIP
    int max_process_len = {max_size};
    if ({len_param} > max_process_len) {{
        {data_param}[max_process_len] = '\\0';
    }}
"""


def _array_padding(size: int) -> str:
    """Single initialized char array."""
    return f"""\
    // Session audit buffer (stack padding)
    char audit_trail[{size}];
    memset(audit_trail, 0, sizeof(audit_trail));
"""


def _mixed_padding(size: int) -> str:
    """Mix of different variable types that approximate the target size."""
    lines = [
        "    // Connection tracking variables (stack padding)",
    ]
    remaining = size

    # Lay down variables in a realistic-looking mix
    var_templates = [
        ("int session_id = 0x41414141;", 4),
        ("int msg_counter = 0;", 4),
        ("double timestamp = 0.0;", 8),
        ("char client_tag[16];", 16),
        ("int auth_flags = 0;", 4),
        ("char log_prefix[32];", 32),
        ("int retry_count = 3;", 4),
        ("double timeout_val = 30.0;", 8),
        ("char session_token[48];", 48),
        ("int checksum = 0xDEAD;", 4),
        ("char request_id[24];", 24),
        ("int priority_level = 1;", 4),
        ("char worker_name[36];", 36),
        ("int sequence_num = 0;", 4),
        ("double rate_limit = 100.0;", 8),
    ]

    used = []
    for decl, var_size in var_templates:
        if remaining <= 0:
            break
        if var_size <= remaining:
            used.append(f"    {decl}")
            remaining -= var_size

    # Fill any leftover with a small char array
    if remaining > 0:
        used.append(f"    char _pad[{remaining}];")

    lines.extend(used)

    # Initialize char arrays to avoid MSVC warnings
    lines.append("    memset(client_tag, 0, sizeof(client_tag));")
    # Only add memset for arrays we actually declared
    for decl, _ in var_templates:
        if "char " in decl and "[" in decl:
            var_name = decl.split("[")[0].replace("char ", "").strip()
            if var_name != "client_tag" and any(var_name in u for u in used):
                lines.append(f"    memset({var_name}, 0, sizeof({var_name}));")
    if remaining > 0:
        lines.append("    memset(_pad, 0, sizeof(_pad));")

    lines.append("")
    return "\n".join(lines) + "\n"


def _struct_padding(size: int) -> str:
    """A struct with named fields."""
    # Distribute size across struct fields
    # Reserve 8 bytes for two ints, rest goes to char arrays
    int_bytes = 8
    char_bytes = max(size - int_bytes, 4)
    name_size = char_bytes // 2
    data_size = char_bytes - name_size

    return f"""\
    // Request metadata record (stack padding)
    struct {{
        int request_type;
        char sender_name[{name_size}];
        char payload_hash[{data_size}];
        int status_code;
    }} req_meta;
    memset(&req_meta, 0, sizeof(req_meta));
"""


def _multi_array_padding(size: int) -> str:
    """Multiple smaller arrays with different names."""
    # Split into 3-5 arrays of varying sizes
    arrays = []
    names = [
        "cmd_history",
        "auth_nonce",
        "route_table",
        "sess_cache",
        "temp_digest",
    ]
    remaining = size
    num_arrays = min(5, max(2, size // 16))

    for i in range(num_arrays):
        if i == num_arrays - 1:
            arr_size = remaining
        else:
            # Use roughly equal chunks with some variation
            arr_size = max(4, remaining // (num_arrays - i))
            # Add some jitter: alternate between slightly larger and smaller
            if i % 2 == 0:
                arr_size = min(arr_size + 4, remaining)
            else:
                arr_size = max(4, arr_size - 4)
        if arr_size <= 0:
            break
        arrays.append((names[i % len(names)], arr_size))
        remaining -= arr_size

    lines = ["    // Protocol processing buffers (stack padding)"]
    for name, sz in arrays:
        lines.append(f"    char {name}[{sz}];")
    for name, _ in arrays:
        lines.append(f"    memset({name}, 0, sizeof({name}));")
    lines.append("")

    return "\n".join(lines) + "\n"
