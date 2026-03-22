"""TCP protocol template.

Generates raw TCP text-based command dispatcher:
  COMMAND <data>\n
"""

from target_builder.src.config import ServerConfig


def generate_connection_handler(config: ServerConfig) -> str:
    """Generate the TCP connection handler function."""
    return """\
DWORD WINAPI handle_connection(LPVOID lpParam) {
    SOCKET client = (SOCKET)lpParam;
    char recv_buf[RECV_BUF_SIZE];
    int bytes_received;

    // Send banner
    send(client, BANNER, (int)strlen(BANNER), 0);

    while (1) {
        memset(recv_buf, 0, sizeof(recv_buf));
        bytes_received = recv(client, recv_buf, sizeof(recv_buf) - 1, 0);

        if (bytes_received <= 0) {
            break;
        }

        recv_buf[bytes_received] = '\\0';

        // Strip trailing newline/carriage return
        while (bytes_received > 0 &&
               (recv_buf[bytes_received - 1] == '\\n' ||
                recv_buf[bytes_received - 1] == '\\r')) {
            recv_buf[--bytes_received] = '\\0';
        }

        if (bytes_received == 0) continue;

        // Dispatch command
        dispatch_command(client, recv_buf, bytes_received);
    }

    printf("[*] Client disconnected\\n");
    closesocket(client);
    return 0;
}"""


def generate_command_dispatcher(
    config: ServerConfig,
    vuln_handler_call: str,
    safe_handler_calls: str,
    decoy_handler_calls: str,
    info_leak_call: str,
) -> str:
    """Generate the TCP command dispatcher.

    Args:
        config: Server configuration.
        vuln_handler_call: C++ code for the vulnerable command branch.
        safe_handler_calls: C++ code for safe command branches.
        decoy_handler_calls: C++ code for decoy command branches.
        info_leak_call: C++ code for ASLR info leak command (or empty).
    """
    cmd_name = config.command

    parts = []
    parts.append(f"""\
void dispatch_command(SOCKET client, char* buf, int len) {{
    // Parse command verb and data
    char* space = strchr(buf, ' ');
    char* cmd = buf;
    char* data = NULL;
    int data_len = 0;

    if (space) {{
        *space = '\\0';
        data = space + 1;
        data_len = len - (int)(data - buf);
    }}

    // Vulnerable command: {cmd_name}
    if (_stricmp(cmd, "{cmd_name}") == 0) {{
        if (data && data_len > 0) {{
{_indent(vuln_handler_call, 12)}
        }} else {{
            const char* msg = "{cmd_name}: missing argument\\n";
            send(client, msg, (int)strlen(msg), 0);
        }}
        return;
    }}""")

    # Safe commands
    parts.append(safe_handler_calls)

    # Info leak (ASLR)
    if info_leak_call:
        parts.append(info_leak_call)

    # Decoy commands
    if decoy_handler_calls:
        parts.append(decoy_handler_calls)

    parts.append("""\

    // Unknown command
    const char* msg = "Unknown command. Type HELP for available commands.\\n";
    send(client, msg, (int)strlen(msg), 0);
}""")

    return "\n".join(parts)


def generate_safe_commands(config: ServerConfig) -> str:
    """Generate handler branches for safe (non-vulnerable) commands."""
    branches = []

    for cmd in config.additional_commands:
        cmd_upper = cmd.upper()
        if cmd_upper == "HELP":
            branches.append(_generate_help_branch(config))
        elif cmd_upper == "STATS":
            branches.append(_generate_stats_branch())
        elif cmd_upper == "EXIT":
            branches.append(_generate_exit_branch())
        else:
            branches.append(_generate_generic_safe_branch(cmd_upper))

    return "\n".join(branches)


def generate_info_leak(config: ServerConfig) -> str:
    """Generate DEBUG command that leaks an address (for ASLR bypass)."""
    if not config.aslr:
        return ""

    return """\

    // DEBUG command - inadvertently leaks internal address
    if (_stricmp(cmd, "DEBUG") == 0) {
        char debug_buf[512];
        int local_var = 42;
        _snprintf(debug_buf, sizeof(debug_buf),
                 "DEBUG INFO:\\n"
                 "  Server uptime: %d seconds\\n"
                 "  Connections: %d\\n"
                 "  Internal handle: 0x%p\\n"
                 "  Status: OK\\n",
                 GetTickCount() / 1000, 1, &local_var);
        send(client, debug_buf, (int)strlen(debug_buf), 0);
        return;
    }"""


def _generate_help_branch(config: ServerConfig) -> str:
    """Generate HELP command response listing all commands."""
    all_cmds = [config.command] + config.additional_commands
    cmd_list = "\\n".join(f"  {c}" for c in all_cmds)
    if config.aslr:
        cmd_list += "\\n  DEBUG"

    return f"""\

    // HELP command
    if (_stricmp(cmd, "HELP") == 0) {{
        const char* help_msg =
            "Available commands:\\n"
            "{cmd_list}\\n";
        send(client, help_msg, (int)strlen(help_msg), 0);
        return;
    }}"""


def _generate_stats_branch() -> str:
    """Generate STATS command response."""
    return """\

    // STATS command
    if (_stricmp(cmd, "STATS") == 0) {
        char stats_buf[256];
        _snprintf(stats_buf, sizeof(stats_buf),
                 "Server Statistics:\\n"
                 "  Uptime: %d seconds\\n"
                 "  Status: Running\\n",
                 GetTickCount() / 1000);
        send(client, stats_buf, (int)strlen(stats_buf), 0);
        return;
    }"""


def _generate_exit_branch() -> str:
    """Generate EXIT command."""
    return """\

    // EXIT command
    if (_stricmp(cmd, "EXIT") == 0) {
        const char* msg = "Goodbye.\\n";
        send(client, msg, (int)strlen(msg), 0);
        closesocket(client);
        return;
    }"""


def _generate_generic_safe_branch(cmd_name: str) -> str:
    """Generate a generic safe command branch."""
    return f"""\

    // {cmd_name} command
    if (_stricmp(cmd, "{cmd_name}") == 0) {{
        const char* msg = "{cmd_name}: OK\\n";
        send(client, msg, (int)strlen(msg), 0);
        return;
    }}"""


def _indent(text: str, spaces: int) -> str:
    """Indent each line of text by the given number of spaces."""
    prefix = " " * spaces
    lines = text.split("\n")
    return "\n".join(prefix + line if line.strip() else line for line in lines)
