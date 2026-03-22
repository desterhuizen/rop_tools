"""Buffer overflow vulnerability template.

Generates a classic stack buffer overflow: strcpy into an undersized
stack-allocated char buffer. Works on x86 and x64.
"""

from target_builder.src.config import Protocol, ServerConfig


def generate_vuln_function(config: ServerConfig) -> str:
    """Generate the vulnerable function with strcpy into a stack buffer."""
    buf_size = config.buffer_size
    has_bad_chars = len(config.bad_chars) > 0

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

    return f"""\
// VULNERABLE FUNCTION - Classic stack buffer overflow
// Buffer is {buf_size} bytes, recv allows up to {RECV_BUF_SIZE} bytes
void vuln_function(char* {data_param}, int {len_param}) {{
{filter_call}\
    char buffer[{buf_size}];

    // Vulnerable: strcpy does not check bounds
    strcpy(buffer, {data_param});

    printf("[*] Received %d bytes into %d-byte buffer\\n", {len_param}, {buf_size});
}}"""


def generate_vuln_handler_call(config: ServerConfig) -> str:
    """Generate the code that calls the vuln function from the dispatcher."""
    if config.protocol == Protocol.HTTP:
        return "vuln_function(req->body, req->body_len);"
    elif config.protocol == Protocol.RPC:
        return "vuln_function(payload, payload_len);"
    else:
        return "vuln_function(data, data_len);"


RECV_BUF_SIZE = 8192
