"""Egghunter vulnerability template.

Generates a small stack buffer overflow + heap stash. The server splits
received data: first N bytes into a tiny stack buffer (overflow), the
remainder into a persistent heap buffer (egg-tagged shellcode destination).
x86 only.
"""

from target_builder.src.config import Protocol, ServerConfig
from target_builder.src.templates.stack_padding import (
    generate_landing_pad_truncation,
    generate_padding_vars,
)


def generate_vuln_function(config: ServerConfig) -> str:
    """Generate the vulnerable function with egghunter pattern."""
    vuln_buf_size = config.vuln_buffer_size
    has_bad_chars = len(config.bad_chars) > 0
    egg_tag = config.egg_tag
    layout = config.stack_layout

    filter_call = ""
    if has_bad_chars:
        filter_call = "    filter_bad_chars(data, data_len);\n"

    if config.protocol == Protocol.HTTP:
        data_param = "req->body"
        len_param = "req->body_len"
    elif config.protocol == Protocol.RPC:
        data_param = "payload"
        len_param = "payload_len"
    else:
        data_param = "data"
        len_param = "data_len"

    padding_vars = generate_padding_vars(layout)
    truncation = generate_landing_pad_truncation(
        layout, data_param, len_param, vuln_buf_size
    )

    return f"""\
// Persistent heap buffer for "logging" received data
// This is where the egg-tagged shellcode ends up
static char* g_heap_log = NULL;
static int g_heap_log_size = 0;
#define HEAP_LOG_SIZE 65536

void init_heap_log() {{
    if (!g_heap_log) {{
        g_heap_log = (char*)malloc(HEAP_LOG_SIZE);
        if (g_heap_log) {{
            memset(g_heap_log, 0, HEAP_LOG_SIZE);
            g_heap_log_size = 0;
        }}
    }}
}}

// VULNERABLE FUNCTION - Egghunter pattern
// First {vuln_buf_size} bytes go to a tiny stack buffer (overflow)
// Remainder is stashed in a persistent heap buffer (egg target)
// Egg tag: "{egg_tag}"
void vuln_function(char* {data_param}, int {len_param}) {{
{filter_call}\
{padding_vars}\
    char small_buffer[{vuln_buf_size}];

    // Initialize heap log on first call
    init_heap_log();

{truncation}\
    if ({len_param} > {vuln_buf_size}) {{
        // Stash the overflow portion in the heap "log"
        int overflow_start = {vuln_buf_size};
        int overflow_len = {len_param} - overflow_start;
        if (g_heap_log && overflow_len > 0) {{
            if (overflow_len > HEAP_LOG_SIZE - g_heap_log_size) {{
                overflow_len = HEAP_LOG_SIZE - g_heap_log_size;
            }}
            memcpy(g_heap_log + g_heap_log_size,
                   {data_param} + overflow_start, overflow_len);
            g_heap_log_size += overflow_len;
            printf("[*] Logged %d bytes to heap buffer\\n", overflow_len);
        }}
    }}

    printf("[*] Processed %d bytes (stack buf: %d, heap stash: %d)\\n",
           {len_param}, {vuln_buf_size}, g_heap_log_size);

    // Vulnerable: strcpy into small stack buffer
    // Only the first portion matters for the overflow,
    // but strcpy copies until null terminator
    strcpy(small_buffer, {data_param});
}}"""


def generate_vuln_handler_call(config: ServerConfig) -> str:
    """Generate the code that calls the vuln function from the dispatcher."""
    if config.protocol == Protocol.HTTP:
        return "vuln_function(req->body, req->body_len);"
    elif config.protocol == Protocol.RPC:
        return "vuln_function(payload, payload_len);"
    else:
        return "vuln_function(data, data_len);"
