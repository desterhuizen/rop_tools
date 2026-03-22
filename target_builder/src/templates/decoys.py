"""Decoy command templates.

Generates non-exploitable commands that look suspicious but are safe.
Forces the attacker to properly analyze which command is truly vulnerable.
"""

from typing import List, Tuple

from target_builder.src.config import DecoyType, Protocol, ServerConfig


def generate_decoy_functions(
    config: ServerConfig,
    decoy_specs: List[Tuple[str, DecoyType]],
) -> str:
    """Generate C++ functions for each decoy command.

    Args:
        config: Server configuration.
        decoy_specs: List of (command_name, decoy_type) tuples.

    Returns:
        C++ code with all decoy functions.
    """
    functions = []
    for name, decoy_type in decoy_specs:
        func_name = f"handle_{name.lower()}"
        if decoy_type == DecoyType.NEAR_MISS_BUFFER:
            functions.append(_near_miss_buffer(func_name, name))
        elif decoy_type == DecoyType.SAFE_FORMAT:
            functions.append(_safe_format(func_name, name))
        elif decoy_type == DecoyType.BOUNDED_COPY:
            functions.append(_bounded_copy(func_name, name))
        elif decoy_type == DecoyType.HEAP_BUFFER:
            functions.append(_heap_buffer(func_name, name))

    return "\n\n".join(functions)


def generate_decoy_dispatcher_branches(
    config: ServerConfig,
    decoy_specs: List[Tuple[str, DecoyType]],
) -> str:
    """Generate dispatcher branches for decoy commands.

    Returns C++ if-else branches appropriate for the protocol.
    """
    if config.protocol == Protocol.TCP:
        return _tcp_branches(decoy_specs)
    elif config.protocol == Protocol.HTTP:
        return _http_branches(decoy_specs)
    elif config.protocol == Protocol.RPC:
        return _rpc_branches(decoy_specs)
    return ""


def _near_miss_buffer(func_name: str, cmd_name: str) -> str:
    """strncpy with correct bounds — looks vulnerable but isn't."""
    return f"""\
// Decoy: {cmd_name} - looks like overflow but uses strncpy with bounds
void {func_name}(char* data, int data_len) {{
    char buffer[512];
    // Safe: strncpy with sizeof(buffer) limit
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("[*] {cmd_name}: processed %d bytes (safe copy)\\n", data_len);
}}"""


def _safe_format(func_name: str, cmd_name: str) -> str:
    """printf with proper format specifier — looks like fmtstr but isn't."""
    return f"""\
// Decoy: {cmd_name} - looks like format string but uses %s
void {func_name}(char* data, int data_len) {{
    char output[1024];
    // Safe: printf with explicit format specifier
    _snprintf(output, sizeof(output), "[%s] %s", "{cmd_name}", data);
    printf("%s\\n", output);
}}"""


def _bounded_copy(func_name: str, cmd_name: str) -> str:
    """memcpy with min(len, sizeof) — copies to stack but safely."""
    return f"""\
// Decoy: {cmd_name} - copies to stack buffer but with bounds check
void {func_name}(char* data, int data_len) {{
    char buffer[256];
    // Safe: bounded memcpy with minimum of input and buffer size
    int copy_len = data_len < (int)sizeof(buffer) - 1
                   ? data_len : (int)sizeof(buffer) - 1;
    memcpy(buffer, data, copy_len);
    buffer[copy_len] = '\\0';
    printf("[*] {cmd_name}: copied %d of %d bytes (bounded)\\n",
           copy_len, data_len);
}}"""


def _heap_buffer(func_name: str, cmd_name: str) -> str:
    """strcpy into malloc'd buffer — overflows heap, not stack."""
    return f"""\
// Decoy: {cmd_name} - heap overflow, not directly exploitable for EIP
void {func_name}(char* data, int data_len) {{
    // Allocates on the heap — overflow here won't overwrite return address
    char* heap_buf = (char*)malloc(256);
    if (heap_buf) {{
        strcpy(heap_buf, data);  // Overflow goes to heap, not stack
        printf("[*] {cmd_name}: stored %d bytes on heap\\n", data_len);
        free(heap_buf);
    }}
}}"""


def _tcp_branches(decoy_specs: List[Tuple[str, DecoyType]]) -> str:
    """Generate TCP dispatcher branches for decoys."""
    branches = []
    for name, _ in decoy_specs:
        func_name = f"handle_{name.lower()}"
        branches.append(f"""\

    // Decoy command: {name}
    if (_stricmp(cmd, "{name}") == 0) {{
        if (data && data_len > 0) {{
            {func_name}(data, data_len);
            const char* msg = "{name}: OK\\n";
            send(client, msg, (int)strlen(msg), 0);
        }} else {{
            const char* msg = "{name}: missing argument\\n";
            send(client, msg, (int)strlen(msg), 0);
        }}
        return;
    }}""")
    return "\n".join(branches)


def _http_branches(decoy_specs: List[Tuple[str, DecoyType]]) -> str:
    """Generate HTTP dispatcher branches for decoys."""
    branches = []
    for i, (name, _) in enumerate(decoy_specs):
        func_name = f"handle_{name.lower()}"
        path = f"/{name.lower()}"
        branches.append(f"""\

    // Decoy endpoint: POST {path}
    if (_stricmp(req->method, "POST") == 0 &&
        _stricmp(req->path, "{path}") == 0) {{
        if (req->body_len > 0) {{
            {func_name}(req->body, req->body_len);
            send_http_response(client, 200, "OK",
                             "text/plain", "Processed\\n");
        }} else {{
            send_http_response(client, 400, "Bad Request",
                             "text/plain", "Missing body\\n");
        }}
        return;
    }}""")
    return "\n".join(branches)


def _rpc_branches(decoy_specs: List[Tuple[str, DecoyType]]) -> str:
    """Generate RPC dispatcher branches for decoys."""
    branches = []
    # Assign opcodes starting from 10 for decoys
    for i, (name, _) in enumerate(decoy_specs):
        func_name = f"handle_{name.lower()}"
        opcode = 10 + i
        branches.append(f"""\

    // Decoy opcode {opcode}: {name}
    if (opcode == {opcode}) {{
        if (payload_len > 0) {{
            {func_name}(payload, payload_len);
            send_rpc_response(client, {opcode}, "OK", 2);
        }} else {{
            send_rpc_response(client, {opcode}, "ERR:NO_DATA", 11);
        }}
        return;
    }}""")
    return "\n".join(branches)
