"""Tests for vulnerability and protocol templates.

Verifies each template produces valid C++ fragments with expected patterns.
"""

import unittest

from target_builder.src.config import (
    DecoyType,
    PaddingStyle,
    Protocol,
    ServerConfig,
    StackLayoutConfig,
    VulnType,
)
from target_builder.src.templates import (
    buffer_overflow,
    decoys,
    egghunter,
    format_string,
    seh_overflow,
)
from target_builder.src.templates.protocols import http as http_proto
from target_builder.src.templates.protocols import rpc as rpc_proto
from target_builder.src.templates.protocols import tcp as tcp_proto


class TestBufferOverflow(unittest.TestCase):
    """Test buffer overflow template."""

    def test_contains_strcpy(self):
        config = ServerConfig(vuln_type=VulnType.BOF, buffer_size=512)
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("strcpy", result)
        self.assertIn("buffer[512]", result)

    def test_handler_call_tcp(self):
        config = ServerConfig(protocol=Protocol.TCP)
        call = buffer_overflow.generate_vuln_handler_call(config)
        self.assertIn("vuln_function(data, data_len)", call)

    def test_handler_call_http(self):
        config = ServerConfig(protocol=Protocol.HTTP)
        call = buffer_overflow.generate_vuln_handler_call(config)
        self.assertIn("req->body", call)

    def test_handler_call_rpc(self):
        config = ServerConfig(protocol=Protocol.RPC)
        call = buffer_overflow.generate_vuln_handler_call(config)
        self.assertIn("payload", call)

    def test_bad_char_filter_included(self):
        config = ServerConfig(vuln_type=VulnType.BOF, bad_chars=[0x0A])
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("filter_bad_chars", result)

    def test_no_filter_without_bad_chars(self):
        config = ServerConfig(vuln_type=VulnType.BOF, bad_chars=[])
        result = buffer_overflow.generate_vuln_function(config)
        self.assertNotIn("filter_bad_chars", result)


class TestSEHOverflow(unittest.TestCase):
    """Test SEH overflow template."""

    def test_contains_try_except(self):
        config = ServerConfig(vuln_type=VulnType.SEH)
        result = seh_overflow.generate_vuln_function(config)
        self.assertIn("__try", result)
        self.assertIn("__except", result)
        self.assertIn("strcpy", result)

    def test_buffer_size(self):
        config = ServerConfig(vuln_type=VulnType.SEH, buffer_size=300)
        result = seh_overflow.generate_vuln_function(config)
        self.assertIn("buffer[300]", result)


class TestEgghunter(unittest.TestCase):
    """Test egghunter template."""

    def test_contains_heap_stash(self):
        config = ServerConfig(
            vuln_type=VulnType.EGGHUNTER,
            vuln_buffer_size=128,
            buffer_size=2048,
        )
        result = egghunter.generate_vuln_function(config)
        self.assertIn("small_buffer[128]", result)
        self.assertIn("g_heap_log", result)
        self.assertIn("malloc", result)
        self.assertIn("memcpy", result)
        self.assertIn("strcpy", result)

    def test_egg_tag_in_comment(self):
        config = ServerConfig(
            vuln_type=VulnType.EGGHUNTER,
            egg_tag="test",
        )
        result = egghunter.generate_vuln_function(config)
        self.assertIn("test", result)


class TestFormatString(unittest.TestCase):
    """Test format string template."""

    def test_contains_printf_vuln(self):
        config = ServerConfig(vuln_type=VulnType.FMTSTR)
        result = format_string.generate_vuln_function(config)
        # Should have _printf_p(data) — positional param support
        self.assertIn("VULN_PRINTF(data)", result)
        # Should have secret values for leaking
        self.assertIn("0xDEADBEEF", result)

    def test_handler_call_includes_socket(self):
        config = ServerConfig(vuln_type=VulnType.FMTSTR, protocol=Protocol.TCP)
        call = format_string.generate_vuln_handler_call(config)
        self.assertIn("client", call)


class TestDecoys(unittest.TestCase):
    """Test decoy command generation."""

    def test_near_miss_buffer(self):
        config = ServerConfig()
        result = decoys.generate_decoy_functions(
            config, [("PROCESS", DecoyType.NEAR_MISS_BUFFER)]
        )
        self.assertIn("strncpy", result)
        self.assertIn("sizeof(buffer)", result)

    def test_safe_format(self):
        config = ServerConfig()
        result = decoys.generate_decoy_functions(
            config, [("QUERY", DecoyType.SAFE_FORMAT)]
        )
        self.assertIn("%s", result)
        self.assertIn("_snprintf", result)

    def test_bounded_copy(self):
        config = ServerConfig()
        result = decoys.generate_decoy_functions(
            config, [("UPDATE", DecoyType.BOUNDED_COPY)]
        )
        self.assertIn("memcpy", result)
        self.assertIn("copy_len", result)

    def test_heap_buffer(self):
        config = ServerConfig()
        result = decoys.generate_decoy_functions(
            config, [("VALIDATE", DecoyType.HEAP_BUFFER)]
        )
        self.assertIn("malloc", result)
        self.assertIn("free", result)

    def test_multiple_decoys(self):
        config = ServerConfig()
        specs = [
            ("CMD1", DecoyType.NEAR_MISS_BUFFER),
            ("CMD2", DecoyType.SAFE_FORMAT),
        ]
        result = decoys.generate_decoy_functions(config, specs)
        self.assertIn("handle_cmd1", result)
        self.assertIn("handle_cmd2", result)


class TestStackPadding(unittest.TestCase):
    """Test stack padding generation in vulnerability templates."""

    def test_bof_with_array_padding(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=512,
            stack_layout=StackLayoutConfig(
                pre_padding_size=64,
                padding_style=PaddingStyle.ARRAY,
            ),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("audit_trail[64]", result)
        self.assertIn("memset(audit_trail", result)
        self.assertIn("strcpy", result)

    def test_bof_with_mixed_padding(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=256,
            stack_layout=StackLayoutConfig(
                pre_padding_size=48,
                padding_style=PaddingStyle.MIXED,
            ),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("session_id", result)
        self.assertIn("strcpy", result)

    def test_bof_with_struct_padding(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=256,
            stack_layout=StackLayoutConfig(
                pre_padding_size=64,
                padding_style=PaddingStyle.STRUCT,
            ),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("req_meta", result)
        self.assertIn("request_type", result)

    def test_bof_with_multi_padding(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=256,
            stack_layout=StackLayoutConfig(
                pre_padding_size=96,
                padding_style=PaddingStyle.MULTI,
            ),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("cmd_history", result)
        self.assertIn("auth_nonce", result)

    def test_bof_no_padding_when_none(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=256,
            stack_layout=StackLayoutConfig(
                pre_padding_size=0,
                padding_style=PaddingStyle.NONE,
            ),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertNotIn("audit_trail", result)
        self.assertNotIn("req_meta", result)

    def test_bof_landing_pad_truncation(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=256,
            stack_layout=StackLayoutConfig(
                landing_pad_size=16,
            ),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertIn("max_process_len", result)
        # 256 + 0 (padding) + 8 (frame) + 16 (landing) = 280
        self.assertIn("280", result)

    def test_seh_with_padding(self):
        config = ServerConfig(
            vuln_type=VulnType.SEH,
            buffer_size=300,
            stack_layout=StackLayoutConfig(
                pre_padding_size=32,
                padding_style=PaddingStyle.ARRAY,
            ),
        )
        result = seh_overflow.generate_vuln_function(config)
        self.assertIn("audit_trail[32]", result)
        self.assertIn("__try", result)
        self.assertIn("strcpy", result)

    def test_egghunter_with_padding(self):
        config = ServerConfig(
            vuln_type=VulnType.EGGHUNTER,
            buffer_size=2048,
            vuln_buffer_size=128,
            stack_layout=StackLayoutConfig(
                pre_padding_size=48,
                padding_style=PaddingStyle.ARRAY,
            ),
        )
        result = egghunter.generate_vuln_function(config)
        self.assertIn("audit_trail[48]", result)
        self.assertIn("small_buffer[128]", result)
        self.assertIn("g_heap_log", result)

    def test_no_truncation_when_landing_pad_zero(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=256,
            stack_layout=StackLayoutConfig(landing_pad_size=0),
        )
        result = buffer_overflow.generate_vuln_function(config)
        self.assertNotIn("max_process_len", result)


class TestTCPProtocol(unittest.TestCase):
    """Test TCP protocol template."""

    def test_connection_handler(self):
        config = ServerConfig(protocol=Protocol.TCP)
        result = tcp_proto.generate_connection_handler(config)
        self.assertIn("handle_connection", result)
        self.assertIn("recv", result)
        self.assertIn("dispatch_command", result)

    def test_info_leak_with_aslr(self):
        config = ServerConfig(protocol=Protocol.TCP, aslr=True)
        result = tcp_proto.generate_info_leak(config)
        self.assertIn("DEBUG", result)
        self.assertIn("0x%p", result)

    def test_no_info_leak_without_aslr(self):
        config = ServerConfig(protocol=Protocol.TCP, aslr=False)
        result = tcp_proto.generate_info_leak(config)
        self.assertEqual(result, "")


class TestHTTPProtocol(unittest.TestCase):
    """Test HTTP protocol template."""

    def test_connection_handler(self):
        config = ServerConfig(protocol=Protocol.HTTP)
        result = http_proto.generate_connection_handler(config)
        self.assertIn("http_request_t", result)
        self.assertIn("parse_http_request", result)
        self.assertIn("dispatch_http", result)

    def test_info_leak_with_aslr(self):
        config = ServerConfig(protocol=Protocol.HTTP, aslr=True)
        result = http_proto.generate_info_leak(config)
        self.assertIn("/info", result)
        self.assertIn("debug_handle", result)


class TestRPCProtocol(unittest.TestCase):
    """Test RPC protocol template."""

    def test_connection_handler(self):
        config = ServerConfig(protocol=Protocol.RPC)
        result = rpc_proto.generate_connection_handler(config)
        self.assertIn("rpc_header_t", result)
        self.assertIn("recv_exact", result)
        self.assertIn("dispatch_rpc", result)

    def test_info_leak_with_aslr(self):
        config = ServerConfig(protocol=Protocol.RPC, aslr=True)
        result = rpc_proto.generate_info_leak(config)
        self.assertIn("INFO_OPCODE", result)
        self.assertIn("internal_handle", result)

    def test_custom_opcode(self):
        config = ServerConfig(protocol=Protocol.RPC, command="5")
        result = rpc_proto.generate_protocol_definitions(config)
        self.assertIn("VULN_OPCODE 5", result)


class TestFmtstrLeakTCP(unittest.TestCase):
    """Test format string leak for TCP protocol."""

    def test_fmtstr_leak_enabled(self):
        config = ServerConfig(protocol=Protocol.TCP, fmtstr_leak=True)
        result = tcp_proto.generate_fmtstr_leak(config)
        self.assertIn("ECHO", result)
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

    def test_fmtstr_leak_disabled(self):
        config = ServerConfig(protocol=Protocol.TCP, fmtstr_leak=False)
        result = tcp_proto.generate_fmtstr_leak(config)
        self.assertEqual(result, "")

    def test_help_includes_echo(self):
        config = ServerConfig(protocol=Protocol.TCP, fmtstr_leak=True)
        result = tcp_proto.generate_safe_commands(config)
        # HELP branch is generated by safe_commands
        self.assertIn("ECHO", result)


class TestFmtstrLeakHTTP(unittest.TestCase):
    """Test format string leak for HTTP protocol."""

    def test_fmtstr_leak_enabled(self):
        config = ServerConfig(protocol=Protocol.HTTP, fmtstr_leak=True)
        result = http_proto.generate_fmtstr_leak(config)
        self.assertIn("/echo", result)
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

    def test_fmtstr_leak_disabled(self):
        config = ServerConfig(protocol=Protocol.HTTP, fmtstr_leak=False)
        result = http_proto.generate_fmtstr_leak(config)
        self.assertEqual(result, "")

    def test_help_includes_echo(self):
        config = ServerConfig(protocol=Protocol.HTTP, fmtstr_leak=True)
        result = http_proto.generate_safe_commands(config)
        self.assertIn("/echo", result)


class TestFmtstrLeakRPC(unittest.TestCase):
    """Test format string leak for RPC protocol."""

    def test_fmtstr_leak_enabled(self):
        config = ServerConfig(protocol=Protocol.RPC, fmtstr_leak=True)
        result = rpc_proto.generate_fmtstr_leak(config)
        self.assertIn("254", result)
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

    def test_fmtstr_leak_disabled(self):
        config = ServerConfig(protocol=Protocol.RPC, fmtstr_leak=False)
        result = rpc_proto.generate_fmtstr_leak(config)
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
