"""Format string vulnerability template.

Generates printf(user_data) without a format specifier. Works on x86/x64.
"""

from target_builder.src.config import Protocol, ServerConfig


def generate_vuln_function(config: ServerConfig) -> str:
    """Generate the vulnerable function with format string bug."""
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
// VULNERABLE FUNCTION - Format string vulnerability
// User input passed directly to printf without format specifier
void vuln_function(SOCKET client, char* {data_param}, int {len_param}) {{
{filter_call}\
    char response[4096];
    int resp_len;

    // Some local variables on the stack for the attacker to leak
    int secret_value = 0xDEADBEEF;
    char internal_key[] = "S3cretK3y!";
    void* stack_addr = &secret_value;

    (void)internal_key;
    (void)stack_addr;

    // VULNERABLE: printf with user-controlled format string
    // Attacker can use %x/%p to read stack, %n to write
    printf("[*] Processing: ");
    printf({data_param});
    printf("\\n");

    // Also send the formatted output back to the attacker
    // This lets them see the leaked data over the network
    resp_len = _snprintf(response, sizeof(response) - 1, "Result: ");
    resp_len += _snprintf(response + resp_len, sizeof(response) - resp_len - 1,
                          {data_param});
    response[resp_len] = '\\0';
    strcat(response, "\\n");

    send(client, response, (int)strlen(response), 0);
}}"""


def generate_vuln_handler_call(config: ServerConfig) -> str:
    """Generate the code that calls the vuln function from the dispatcher.

    Note: fmtstr vuln_function takes an extra SOCKET parameter to send
    the formatted output back to the attacker.
    """
    if config.protocol == Protocol.HTTP:
        return "vuln_function(client, req->body, req->body_len);"
    elif config.protocol == Protocol.RPC:
        return "vuln_function(client, payload, payload_len);"
    else:
        return "vuln_function(client, data, data_len);"
