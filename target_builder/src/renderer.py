"""Renderer — assembles complete C++ source from template fragments.

Orchestrates all template modules to produce a complete, compilable
C++ server source file from a ServerConfig.
"""

from typing import List, Tuple

from target_builder.src.bad_chars import generate_bad_char_filter
from target_builder.src.config import (
    DECOY_COMMAND_POOL,
    DecoyType,
    Protocol,
    ServerConfig,
    VulnType,
)
from target_builder.src.templates import base, buffer_overflow
from target_builder.src.templates import data_staging as data_staging_templates
from target_builder.src.templates import decoys as decoy_templates
from target_builder.src.templates import egghunter, format_string, rop_dll, seh_overflow
from target_builder.src.templates.protocols import http as http_proto
from target_builder.src.templates.protocols import rpc as rpc_proto
from target_builder.src.templates.protocols import tcp as tcp_proto


def render(config: ServerConfig) -> str:
    """Render a complete C++ server source from configuration.

    Args:
        config: Fully validated ServerConfig.

    Returns:
        Complete C++ source code as a string.
    """
    sections = []

    # 1. Compile instructions header
    sections.append(base.generate_compile_instructions(config))
    sections.append("")

    # 2. Includes and pragma
    sections.append(base.generate_includes(config))
    sections.append(base.generate_pragma_comment(config))
    sections.append("")

    # 3. Defines and globals
    sections.append(base.generate_globals(config))

    # 3b. Protocol-specific type definitions and macros
    proto_module = _get_protocol_module(config)
    proto_defs = proto_module.generate_protocol_definitions(config)
    if proto_defs:
        sections.append(proto_defs)
        sections.append("")

    # 4. Forward declarations
    sections.append(_generate_forward_declarations(config))
    sections.append("")

    # 4b. Info leak function (leaked pointer target for ASLR bypass)
    info_leak_func = base.generate_info_leak_function(config)
    if info_leak_func:
        sections.append(info_leak_func)

    # 5. Bad character filter
    if config.bad_chars:
        sections.append(
            generate_bad_char_filter(config.bad_chars, config.bad_char_action)
        )
        sections.append("")

    # 6. DEP bypass API usage
    dep_code = base.generate_dep_api_usage(config)
    if dep_code:
        sections.append(dep_code)

    # 6b. Embedded ROP gadgets
    if config.embedded_gadgets.enabled:
        sections.append(
            rop_dll.generate_embedded_gadgets(
                config.embedded_gadgets.gadget_density,
                config.embedded_gadgets.seed,
            )
        )
        sections.append("")

    # 6c. Data staging function
    staging_func = data_staging_templates.generate_data_staging_function(config)
    if staging_func:
        sections.append(staging_func)

    # 7. Decoy functions
    decoy_specs = _resolve_decoy_specs(config)
    if decoy_specs:
        sections.append(decoy_templates.generate_decoy_functions(config, decoy_specs))
        sections.append("")

    # 7b. Format string macros (needed by fmtstr vuln and fmtstr-leak)
    if config.vuln_type == VulnType.FMTSTR or config.fmtstr_leak:
        sections.append(_fmtstr_macros())

    # 8. Vulnerable function
    vuln_func = _get_vuln_function(config)
    sections.append(vuln_func)
    sections.append("")

    # 9. Protocol-specific handler and dispatcher
    # Connection handler first (defines helper functions used by dispatcher)
    sections.append(proto_module.generate_connection_handler(config))
    sections.append("")

    # Build dispatcher components
    vuln_call = _get_vuln_handler_call(config)
    safe_calls = proto_module.generate_safe_commands(config)
    info_leak = proto_module.generate_info_leak(config)
    fmtstr_leak = proto_module.generate_fmtstr_leak(config)
    data_staging = proto_module.generate_data_staging(config)
    decoy_calls = ""
    if decoy_specs:
        decoy_calls = decoy_templates.generate_decoy_dispatcher_branches(
            config, decoy_specs
        )

    # Command dispatcher
    dispatcher = proto_module.generate_command_dispatcher(
        config,
        vuln_call,
        safe_calls,
        decoy_calls,
        info_leak,
        fmtstr_leak,
        data_staging,
    )
    sections.append(dispatcher)
    sections.append("")

    # 10. Winsock init
    sections.append(base.generate_winsock_init())

    # 11. Main function
    sections.append(base.generate_main_function(config))
    sections.append("")

    return "\n".join(sections)


def _generate_forward_declarations(config: ServerConfig) -> str:
    """Generate forward declarations for functions."""
    decls = [
        "// Forward declarations",
        "DWORD WINAPI handle_connection(LPVOID lpParam);",
        "int init_winsock();",
    ]

    if config.aslr:
        decls.append(f"int {config.leak_func_name}(void);")

    if config.data_staging:
        decls.append("void handle_data_staging(char* data, int data_len);")

    if config.bad_chars:
        decls.append("int filter_bad_chars(char* buf, int len);")

    if config.protocol == Protocol.TCP:
        decls.append("void dispatch_command(SOCKET client, char* buf, int len);")
    elif config.protocol == Protocol.HTTP:
        decls.append("void dispatch_http(SOCKET client, http_request_t* req);")
        decls.append(
            "void send_http_response(SOCKET client, int status, "
            "const char* status_text, const char* content_type, "
            "const char* body);"
        )
    elif config.protocol == Protocol.RPC:
        decls.append(
            "void dispatch_rpc(SOCKET client, unsigned short opcode, "
            "char* payload, int payload_len);"
        )
        decls.append("int recv_exact(SOCKET s, char* buf, int n);")
        decls.append(
            "void send_rpc_response(SOCKET client, unsigned short opcode, "
            "const char* payload, int payload_len);"
        )

    return "\n".join(decls)


def _get_protocol_module(config: ServerConfig):
    """Return the protocol template module for the config."""
    if config.protocol == Protocol.TCP:
        return tcp_proto
    elif config.protocol == Protocol.HTTP:
        return http_proto
    elif config.protocol == Protocol.RPC:
        return rpc_proto
    raise ValueError(f"Unknown protocol: {config.protocol}")


def _fmtstr_macros() -> str:
    """Return portable format-string macro definitions."""
    return """\
// Portable format-string wrappers:
// MSVC _printf_p/_sprintf_p support positional params (%3$p).
// MinGW printf/snprintf support them natively (glibc-compatible).
#ifdef _MSC_VER
#define VULN_PRINTF _printf_p
#define VULN_SNPRINTF _sprintf_p
#else
#define VULN_PRINTF printf
#define VULN_SNPRINTF snprintf
#endif
"""


def _get_vuln_function(config: ServerConfig) -> str:
    """Return the vulnerability function C++ code."""
    if config.vuln_type == VulnType.BOF:
        return buffer_overflow.generate_vuln_function(config)
    elif config.vuln_type == VulnType.SEH:
        return seh_overflow.generate_vuln_function(config)
    elif config.vuln_type == VulnType.EGGHUNTER:
        return egghunter.generate_vuln_function(config)
    elif config.vuln_type == VulnType.FMTSTR:
        return format_string.generate_vuln_function(config)
    raise ValueError(f"Unknown vuln type: {config.vuln_type}")


def _get_vuln_handler_call(config: ServerConfig) -> str:
    """Return the dispatcher call to the vulnerability function."""
    if config.vuln_type == VulnType.BOF:
        return buffer_overflow.generate_vuln_handler_call(config)
    elif config.vuln_type == VulnType.SEH:
        return seh_overflow.generate_vuln_handler_call(config)
    elif config.vuln_type == VulnType.EGGHUNTER:
        return egghunter.generate_vuln_handler_call(config)
    elif config.vuln_type == VulnType.FMTSTR:
        return format_string.generate_vuln_handler_call(config)
    raise ValueError(f"Unknown vuln type: {config.vuln_type}")


def _resolve_decoy_specs(
    config: ServerConfig,
) -> List[Tuple[str, DecoyType]]:
    """Build decoy command specs from config.

    If decoy_names/decoy_types are already set (e.g. from randomization),
    use those. Otherwise, pick from pools.
    """
    if config.decoy_count == 0:
        return []

    decoy_types_list = list(DecoyType)
    available_names = [
        n
        for n in DECOY_COMMAND_POOL
        if n not in config.additional_commands and n != config.command.upper()
    ]

    specs = []
    for i in range(config.decoy_count):
        if i < len(config.decoy_names):
            name = config.decoy_names[i]
        elif i < len(available_names):
            name = available_names[i]
        else:
            name = f"DECOY{i}"

        if i < len(config.decoy_types):
            dtype = config.decoy_types[i]
        else:
            dtype = decoy_types_list[i % len(decoy_types_list)]

        specs.append((name, dtype))

    return specs
