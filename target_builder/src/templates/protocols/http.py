"""HTTP protocol template.

Generates a minimal HTTP/1.1 server using Winsock. Vulnerability is
triggered via a specific HTTP method + path (e.g. POST /vulnerable).
"""

from target_builder.src.config import ServerConfig


def generate_protocol_definitions(config: ServerConfig) -> str:
    """Generate HTTP type definitions (must precede dispatcher)."""
    return """\
// HTTP request structure
typedef struct {
    char method[16];
    char path[256];
    char headers[4096];
    char body[RECV_BUF_SIZE];
    int body_len;
    int content_length;
} http_request_t;"""


def generate_connection_handler(config: ServerConfig) -> str:
    """Generate the HTTP connection handler function."""
    banner_escaped = config.banner.replace("\\", "\\\\").replace('"', '\\"')

    return f"""\
// HTTP request parser — extracts method, path, headers, body
int parse_http_request(char* raw, int raw_len, http_request_t* req) {{
    memset(req, 0, sizeof(http_request_t));

    // Find end of request line
    char* line_end = strstr(raw, "\\r\\n");
    if (!line_end) return -1;

    // Parse method
    char* sp1 = strchr(raw, ' ');
    if (!sp1 || sp1 > line_end) return -1;
    int method_len = (int)(sp1 - raw);
    if (method_len >= (int)sizeof(req->method)) method_len = sizeof(req->method) - 1;
    strncpy(req->method, raw, method_len);

    // Parse path
    char* path_start = sp1 + 1;
    char* sp2 = strchr(path_start, ' ');
    if (!sp2 || sp2 > line_end) return -1;
    int path_len = (int)(sp2 - path_start);
    if (path_len >= (int)sizeof(req->path)) path_len = sizeof(req->path) - 1;
    strncpy(req->path, path_start, path_len);

    // Find headers and body separator
    char* header_start = line_end + 2;
    char* body_sep = strstr(header_start, "\\r\\n\\r\\n");
    if (body_sep) {{
        int hdr_len = (int)(body_sep - header_start);
        if (hdr_len >= (int)sizeof(req->headers)) hdr_len = sizeof(req->headers) - 1;
        strncpy(req->headers, header_start, hdr_len);

        // Check for Content-Length
        char* cl = strstr(req->headers, "Content-Length:");
        if (!cl) cl = strstr(req->headers, "content-length:");
        if (cl) {{
            req->content_length = atoi(cl + 15);
        }}

        // Copy body
        char* body_start = body_sep + 4;
        req->body_len = raw_len - (int)(body_start - raw);
        if (req->body_len > 0) {{
            if (req->body_len >= (int)sizeof(req->body))
                req->body_len = sizeof(req->body) - 1;
            memcpy(req->body, body_start, req->body_len);
            req->body[req->body_len] = '\\0';
        }}
    }}

    return 0;
}}

void send_http_response(SOCKET client, int status, const char* status_text,
                        const char* content_type, const char* body) {{
    char response[RECV_BUF_SIZE];
    int body_len = body ? (int)strlen(body) : 0;
    _snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\\r\\n"
             "Server: {banner_escaped}\\r\\n"
             "Content-Type: %s\\r\\n"
             "Content-Length: %d\\r\\n"
             "Connection: close\\r\\n"
             "\\r\\n"
             "%s",
             status, status_text, content_type, body_len,
             body ? body : "");
    send(client, response, (int)strlen(response), 0);
}}

DWORD WINAPI handle_connection(LPVOID lpParam) {{
    SOCKET client = (SOCKET)lpParam;
    char recv_buf[RECV_BUF_SIZE];
    int bytes_received;

    memset(recv_buf, 0, sizeof(recv_buf));
    bytes_received = recv(client, recv_buf, sizeof(recv_buf) - 1, 0);

    if (bytes_received > 0) {{
        recv_buf[bytes_received] = '\\0';

        http_request_t req;
        if (parse_http_request(recv_buf, bytes_received, &req) == 0) {{
            dispatch_http(client, &req);
        }} else {{
            send_http_response(client, 400, "Bad Request",
                             "text/plain", "Malformed HTTP request\\n");
        }}
    }}

    closesocket(client);
    return 0;
}}"""


def generate_command_dispatcher(
    config: ServerConfig,
    vuln_handler_call: str,
    safe_handler_calls: str,
    decoy_handler_calls: str,
    info_leak_call: str,
    fmtstr_leak_call: str = "",
    data_staging_call: str = "",
) -> str:
    """Generate the HTTP request dispatcher."""
    vuln_path = config.command
    if not vuln_path.startswith("/"):
        vuln_path = "/" + vuln_path

    parts = []
    parts.append(f"""\
void dispatch_http(SOCKET client, http_request_t* req) {{
    // Vulnerable endpoint: POST {vuln_path}
    if (_stricmp(req->method, "POST") == 0 &&
        _stricmp(req->path, "{vuln_path}") == 0) {{
        if (req->body_len > 0) {{
{_indent(vuln_handler_call, 12)}
            send_http_response(client, 200, "OK",
                             "text/plain", "Processed\\n");
        }} else {{
            send_http_response(client, 400, "Bad Request",
                             "text/plain", "Missing body\\n");
        }}
        return;
    }}""")

    # Index page
    parts.append("""\

    // GET / - Index page
    if (_stricmp(req->method, "GET") == 0 &&
        (_stricmp(req->path, "/") == 0 || _stricmp(req->path, "/index") == 0)) {
        send_http_response(client, 200, "OK", "text/plain",
                         "Server is running. Use POST to submit data.\\n");
        return;
    }""")

    # Info leak (ASLR)
    if info_leak_call:
        parts.append(info_leak_call)

    # Format string leak
    if fmtstr_leak_call:
        parts.append(fmtstr_leak_call)

    # Safe endpoints
    parts.append(safe_handler_calls)

    # Data staging
    if data_staging_call:
        parts.append(data_staging_call)

    # Decoy endpoints
    if decoy_handler_calls:
        parts.append(decoy_handler_calls)

    parts.append("""\

    // 404 Not Found
    send_http_response(client, 404, "Not Found",
                     "text/plain", "Not Found\\n");
}""")

    return "\n".join(parts)


def generate_safe_commands(config: ServerConfig) -> str:
    """Generate handler branches for safe HTTP endpoints."""
    branches = []

    branches.append("""\

    // GET /status
    if (_stricmp(req->method, "GET") == 0 &&
        _stricmp(req->path, "/status") == 0) {
        char status_buf[256];
        _snprintf(status_buf, sizeof(status_buf),
                 "{\\"status\\":\\"running\\",\\"uptime\\":%d}\\n",
                 GetTickCount() / 1000);
        send_http_response(client, 200, "OK",
                         "application/json", status_buf);
        return;
    }""")

    endpoints = "Endpoints: GET /, GET /status, GET /help, POST /vulnerable"
    if config.aslr:
        endpoints += ", GET /info"
    if config.fmtstr_leak:
        endpoints += ", POST /echo"
    if config.data_staging:
        endpoints += f", POST /{config.data_staging_cmd.lower()}"

    branches.append(f"""\

    // GET /help
    if (_stricmp(req->method, "GET") == 0 &&
        _stricmp(req->path, "/help") == 0) {{
        send_http_response(client, 200, "OK", "text/plain",
                         "{endpoints}\\n");
        return;
    }}""")

    return "\n".join(branches)


def generate_info_leak(config: ServerConfig) -> str:
    """Generate GET /info endpoint that leaks an address."""
    if not config.aslr:
        return ""

    name = config.leak_func_name
    return f"""\

    // GET /info - inadvertently leaks internal address
    if (_stricmp(req->method, "GET") == 0 &&
        _stricmp(req->path, "/info") == 0) {{
        char info_buf[512];
        _snprintf(info_buf, sizeof(info_buf),
                 "{{\\\\"server\\\\":\\\\"running\\\\","
                 "\\\\"version\\\\":\\\\"1.0\\\\","
                 "\\\\"debug_handle\\\\":\\\\"0x%p\\\\","
                 "\\\\"uptime\\\\":%d}}\\n",
                 {name}, GetTickCount() / 1000);
        send_http_response(client, 200, "OK",
                         "application/json", info_buf);
        return;
    }}"""


def generate_fmtstr_leak(config: ServerConfig) -> str:
    """Generate POST /echo endpoint that passes body to printf (format string leak)."""
    if not config.fmtstr_leak:
        return ""

    return """\

    // POST /echo - passes body directly to printf (format string leak)
    if (_stricmp(req->method, "POST") == 0 &&
        _stricmp(req->path, "/echo") == 0) {
        if (req->body_len > 0) {
            char echo_buf[512];
            memset(echo_buf, 0, sizeof(echo_buf));
            _sprintf_p(echo_buf, sizeof(echo_buf) - 1, req->body);
            send_http_response(client, 200, "OK",
                             "text/plain", echo_buf);
        } else {
            send_http_response(client, 400, "Bad Request",
                             "text/plain", "Missing body\\n");
        }
        return;
    }"""


def generate_data_staging(config: ServerConfig) -> str:
    """Generate POST /store endpoint that stores data on the heap."""
    if not config.data_staging:
        return ""

    path = "/" + config.data_staging_cmd.lower()
    cmd = config.data_staging_cmd
    return f"""\

    // POST {path} - stores data in persistent heap buffer
    if (_stricmp(req->method, "POST") == 0 &&
        _stricmp(req->path, "{path}") == 0) {{
        if (req->body_len > 0) {{
            handle_data_staging(req->body, req->body_len);
            send_http_response(client, 200, "OK",
                             "text/plain", "{cmd}: data stored\\n");
        }} else {{
            send_http_response(client, 400, "Bad Request",
                             "text/plain", "Missing body\\n");
        }}
        return;
    }}"""


def _indent(text: str, spaces: int) -> str:
    """Indent each line of text by the given number of spaces."""
    prefix = " " * spaces
    lines = text.split("\n")
    return "\n".join(prefix + line if line.strip() else line for line in lines)
