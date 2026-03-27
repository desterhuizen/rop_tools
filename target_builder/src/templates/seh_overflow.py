"""SEH overflow vulnerability template.

Generates a buffer overflow inside __try/__except that overwrites the
SEH chain. x86 only (no classic SEH exploitation on x64).
"""

from target_builder.src.config import Protocol, ServerConfig
from target_builder.src.templates.stack_padding import (
    generate_landing_pad_truncation,
    generate_padding_vars,
)


def generate_vuln_function(config: ServerConfig) -> str:
    """Generate the vulnerable function with SEH overflow."""
    buf_size = config.buffer_size
    has_bad_chars = len(config.bad_chars) > 0
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
        layout, data_param, len_param, buf_size, seh=True
    )

    return f"""\
// VULNERABLE FUNCTION - SEH-based buffer overflow
// Overflow inside __try/__except overwrites SEH chain
void vuln_function(char* {data_param}, int {len_param}) {{
{filter_call}\
    __try {{
{padding_vars}\
        char buffer[{buf_size}];

        printf("[*] Received %d bytes into %d-byte buffer\\n", {len_param}, {buf_size});

{truncation}\
        // Vulnerable: strcpy inside __try block overflows past SEH record
        strcpy(buffer, {data_param});

        // Stack integrity check — if the overflow reached past the buffer,
        // the bytes beyond it are attacker-controlled. Interpreting them as
        // a pointer and dereferencing triggers an access violation, which
        // hands control to the (now corrupted) SEH handler chain.
        volatile int *p = *(volatile int **)(buffer + sizeof(buffer));
        int check = *p;
        (void)check;
    }}
    __except (EXCEPTION_EXECUTE_HANDLER) {{
        printf("[!] Exception caught in handler\\n");
    }}
}}"""


def generate_vuln_handler_call(config: ServerConfig) -> str:
    """Generate the code that calls the vuln function from the dispatcher."""
    if config.protocol == Protocol.HTTP:
        return "vuln_function(req->body, req->body_len);"
    elif config.protocol == Protocol.RPC:
        return "vuln_function(payload, payload_len);"
    else:
        return "vuln_function(data, data_len);"
