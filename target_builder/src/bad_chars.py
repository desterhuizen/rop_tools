"""Bad character filter C++ code generation.

Generates the C++ function body that filters bad characters from received
input before the vulnerable copy. Three modes: drop, replace, terminate.
"""

from typing import List

from target_builder.src.config import BadCharAction


def generate_bad_char_filter(bad_chars: List[int], action: BadCharAction) -> str:
    """Generate C++ filter_bad_chars() function.

    Args:
        bad_chars: List of byte values to filter (0x00 is implicit).
        action: How to handle bad characters.

    Returns:
        Complete C++ function as a string.
    """
    if not bad_chars:
        return _generate_passthrough()

    hex_list = ", ".join(f"0x{b:02x}" for b in sorted(set(bad_chars)))
    count = len(set(bad_chars))

    if action == BadCharAction.DROP:
        return _generate_drop_filter(hex_list, count)
    elif action == BadCharAction.REPLACE:
        return _generate_replace_filter(hex_list, count)
    elif action == BadCharAction.TERMINATE:
        return _generate_terminate_filter(hex_list, count)
    else:
        return _generate_passthrough()


def _generate_passthrough() -> str:
    """No filtering — just return the input length unchanged."""
    return """\
// No bad character filtering
int filter_bad_chars(char* buf, int len) {
    return len;
}"""


def _generate_drop_filter(hex_list: str, count: int) -> str:
    """Silently remove bad bytes, shifting remaining data down."""
    return f"""\
// Bad character filter: drop mode
// Silently removes filtered bytes from the input
int filter_bad_chars(char* buf, int len) {{
    unsigned char bad_chars[] = {{ {hex_list} }};
    int bad_count = {count};
    int write_pos = 0;

    for (int i = 0; i < len; i++) {{
        int is_bad = 0;
        for (int j = 0; j < bad_count; j++) {{
            if ((unsigned char)buf[i] == bad_chars[j]) {{
                is_bad = 1;
                break;
            }}
        }}
        if (!is_bad) {{
            buf[write_pos++] = buf[i];
        }}
    }}
    buf[write_pos] = '\\0';
    return write_pos;
}}"""


def _generate_replace_filter(hex_list: str, count: int) -> str:
    """Replace bad bytes with 0x41 ('A')."""
    return f"""\
// Bad character filter: replace mode
// Substitutes filtered bytes with 0x41
int filter_bad_chars(char* buf, int len) {{
    unsigned char bad_chars[] = {{ {hex_list} }};
    int bad_count = {count};

    for (int i = 0; i < len; i++) {{
        for (int j = 0; j < bad_count; j++) {{
            if ((unsigned char)buf[i] == bad_chars[j]) {{
                buf[i] = 0x41;
                break;
            }}
        }}
    }}
    return len;
}}"""


def _generate_terminate_filter(hex_list: str, count: int) -> str:
    """Truncate input at first bad byte."""
    return f"""\
// Bad character filter: terminate mode
// Truncates input at the first filtered byte
int filter_bad_chars(char* buf, int len) {{
    unsigned char bad_chars[] = {{ {hex_list} }};
    int bad_count = {count};

    for (int i = 0; i < len; i++) {{
        for (int j = 0; j < bad_count; j++) {{
            if ((unsigned char)buf[i] == bad_chars[j]) {{
                buf[i] = '\\0';
                return i;
            }}
        }}
    }}
    return len;
}}"""
