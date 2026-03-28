"""Binary RPC protocol template.

Generates a length-prefixed binary protocol handler:
  4-byte LE message length + 2-byte LE opcode + payload
"""

from target_builder.src.config import ServerConfig


def generate_protocol_definitions(config: ServerConfig) -> str:
    """Generate RPC type definitions and macros (must precede dispatcher)."""
    try:
        vuln_opcode = int(config.command)
    except ValueError:
        vuln_opcode = 1

    return f"""\
// RPC message header
#pragma pack(push, 1)
typedef struct {{
    unsigned int msg_len;     // Total message length (including header)
    unsigned short opcode;    // Operation code
}} rpc_header_t;
#pragma pack(pop)

#define RPC_HEADER_SIZE sizeof(rpc_header_t)
#define VULN_OPCODE {vuln_opcode}
#define PING_OPCODE 0
#define INFO_OPCODE 255"""


def generate_connection_handler(config: ServerConfig) -> str:
    """Generate the RPC connection handler function."""
    return """\
// Read exactly n bytes from socket
int recv_exact(SOCKET s, char* buf, int n) {
    int total = 0;
    while (total < n) {
        int received = recv(s, buf + total, n - total, 0);
        if (received <= 0) return -1;
        total += received;
    }
    return total;
}

// Send RPC response: header + payload
void send_rpc_response(SOCKET client, unsigned short opcode,
                       const char* payload, int payload_len) {
    rpc_header_t resp_hdr;
    resp_hdr.msg_len = (unsigned int)(RPC_HEADER_SIZE + payload_len);
    resp_hdr.opcode = opcode;
    send(client, (char*)&resp_hdr, RPC_HEADER_SIZE, 0);
    if (payload && payload_len > 0) {
        send(client, payload, payload_len, 0);
    }
}

DWORD WINAPI handle_connection(LPVOID lpParam) {
    SOCKET client = (SOCKET)lpParam;
    rpc_header_t hdr;
    char payload_buf[RECV_BUF_SIZE];

    // Send banner as ping response on connect
    send_rpc_response(client, PING_OPCODE, BANNER, (int)strlen(BANNER));

    while (1) {
        // Read message header
        if (recv_exact(client, (char*)&hdr, RPC_HEADER_SIZE) < 0) {
            break;
        }

        // Validate message length
        int payload_len = hdr.msg_len - RPC_HEADER_SIZE;
        if (payload_len < 0 || payload_len >= RECV_BUF_SIZE) {
            break;
        }

        // Read payload
        memset(payload_buf, 0, sizeof(payload_buf));
        if (payload_len > 0) {
            if (recv_exact(client, payload_buf, payload_len) < 0) {
                break;
            }
            payload_buf[payload_len] = '\\0';
        }

        // Dispatch by opcode
        dispatch_rpc(client, hdr.opcode, payload_buf, payload_len);
    }

    printf("[*] RPC client disconnected\\n");
    closesocket(client);
    return 0;
}"""


def generate_command_dispatcher(
    config: ServerConfig,
    vuln_handler_call: str,
    safe_handler_calls: str,
    decoy_handler_calls: str,
    info_leak_call: str,
    fmtstr_leak_call: str = "",
) -> str:
    """Generate the RPC opcode dispatcher."""
    try:
        vuln_opcode = int(config.command)
    except ValueError:
        vuln_opcode = 1

    parts = []
    parts.append(f"""\
void dispatch_rpc(SOCKET client, unsigned short opcode,
                  char* payload, int payload_len) {{
    // Vulnerable opcode: {vuln_opcode}
    if (opcode == VULN_OPCODE) {{
        if (payload_len > 0) {{
{_indent(vuln_handler_call, 12)}
            send_rpc_response(client, VULN_OPCODE, "OK", 2);
        }} else {{
            send_rpc_response(client, VULN_OPCODE, "ERR:NO_DATA", 11);
        }}
        return;
    }}""")

    # Ping opcode
    parts.append("""\

    // Opcode 0: Ping
    if (opcode == PING_OPCODE) {
        send_rpc_response(client, PING_OPCODE, "PONG", 4);
        return;
    }""")

    # Info leak (ASLR)
    if info_leak_call:
        parts.append(info_leak_call)

    # Format string leak
    if fmtstr_leak_call:
        parts.append(fmtstr_leak_call)

    # Safe opcodes
    parts.append(safe_handler_calls)

    # Decoy opcodes
    if decoy_handler_calls:
        parts.append(decoy_handler_calls)

    parts.append("""\

    // Unknown opcode
    send_rpc_response(client, opcode, "ERR:UNKNOWN_OP", 14);
}""")

    return "\n".join(parts)


def generate_safe_commands(config: ServerConfig) -> str:
    """Generate handler branches for safe RPC opcodes."""
    return """\

    // Opcode 2: Echo
    if (opcode == 2) {
        send_rpc_response(client, 2, payload, payload_len);
        return;
    }

    // Opcode 3: Server stats
    if (opcode == 3) {
        char stats[128];
        int stats_len = _snprintf(stats, sizeof(stats),
                                  "UPTIME:%d", GetTickCount() / 1000);
        send_rpc_response(client, 3, stats, stats_len);
        return;
    }"""


def generate_info_leak(config: ServerConfig) -> str:
    """Generate opcode 255 response that leaks an address."""
    if not config.aslr:
        return ""

    name = config.leak_func_name
    return f"""\

    // Opcode 255: Server info - inadvertently leaks internal address
    if (opcode == INFO_OPCODE) {{
        #pragma pack(push, 1)
        struct {{
            unsigned int uptime;
            unsigned int version;
            void* internal_handle;  // Leaked pointer
        }} info_resp;
        #pragma pack(pop)

        info_resp.uptime = GetTickCount() / 1000;
        info_resp.version = 0x00010000;
        info_resp.internal_handle = (void*){name};
        send_rpc_response(client, INFO_OPCODE,
                         (char*)&info_resp, sizeof(info_resp));
        return;
    }}"""


def generate_fmtstr_leak(config: ServerConfig) -> str:
    """Generate opcode 254 handler that passes payload to printf (format string leak)."""
    if not config.fmtstr_leak:
        return ""

    return """\

    // Opcode 254: Echo - passes payload directly to printf (format string leak)
    if (opcode == 254) {
        if (payload_len > 0) {
            char echo_buf[512];
            memset(echo_buf, 0, sizeof(echo_buf));
            _snprintf(echo_buf, sizeof(echo_buf) - 1, payload);
            send_rpc_response(client, 254, echo_buf,
                             (int)strlen(echo_buf));
        } else {
            send_rpc_response(client, 254, "ERR:NO_DATA", 11);
        }
        return;
    }"""


def _indent(text: str, spaces: int) -> str:
    """Indent each line of text by the given number of spaces."""
    prefix = " " * spaces
    lines = text.split("\n")
    return "\n".join(prefix + line if line.strip() else line for line in lines)
