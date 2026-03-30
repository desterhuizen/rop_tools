"""Tests for renderer.py — template assembly into complete C++ source."""

import unittest

from target_builder.src.config import (
    Architecture,
    BadCharAction,
    DecoyType,
    DepBypassApi,
    Protocol,
    ServerConfig,
    VulnType,
)
from target_builder.src.renderer import render


class TestRendererBasic(unittest.TestCase):
    """Test basic rendering for each vuln type."""

    def test_bof_tcp_renders(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            banner="Test Server",
        )
        result = render(config)
        self.assertIn("#include <winsock2.h>", result)
        self.assertIn("strcpy", result)
        self.assertIn("handle_connection", result)
        self.assertIn("main(", result)
        self.assertIn("WSAStartup", result)

    def test_seh_renders(self):
        config = ServerConfig(
            vuln_type=VulnType.SEH,
            banner="Test",
        )
        result = render(config)
        self.assertIn("__try", result)
        self.assertIn("__except", result)

    def test_egghunter_renders(self):
        config = ServerConfig(
            vuln_type=VulnType.EGGHUNTER,
            buffer_size=2048,
            vuln_buffer_size=128,
            banner="Test",
        )
        result = render(config)
        self.assertIn("g_heap_log", result)
        self.assertIn("small_buffer", result)

    def test_fmtstr_renders(self):
        config = ServerConfig(
            vuln_type=VulnType.FMTSTR,
            banner="Test",
        )
        result = render(config)
        self.assertIn("VULN_PRINTF(data)", result)


class TestRendererProtocols(unittest.TestCase):
    """Test rendering with different protocols."""

    def test_http_protocol(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.HTTP,
            banner="Test",
        )
        result = render(config)
        self.assertIn("http_request_t", result)
        self.assertIn("parse_http_request", result)
        self.assertIn("dispatch_http", result)

    def test_rpc_protocol(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.RPC,
            banner="Test",
        )
        result = render(config)
        self.assertIn("rpc_header_t", result)
        self.assertIn("recv_exact", result)
        self.assertIn("dispatch_rpc", result)


class TestRendererMitigations(unittest.TestCase):
    """Test mitigation-related code generation."""

    def test_dep_compile_flags(self):
        config = ServerConfig(vuln_type=VulnType.BOF, dep=True, banner="Test")
        result = render(config)
        self.assertIn("/NXCOMPAT", result)
        # Should not have /NXCOMPAT:NO
        self.assertNotIn("/NXCOMPAT:NO", result)

    def test_no_dep_compile_flags(self):
        config = ServerConfig(vuln_type=VulnType.BOF, dep=False, banner="Test")
        result = render(config)
        self.assertIn("/NXCOMPAT:NO", result)

    def test_dep_api_virtualprotect(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            dep=True,
            dep_api=DepBypassApi.VIRTUALPROTECT,
            banner="Test",
        )
        result = render(config)
        self.assertIn("VirtualProtect", result)
        self.assertIn("init_config_buffer", result)

    def test_dep_api_virtualalloc(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            dep=True,
            dep_api=DepBypassApi.VIRTUALALLOC,
            banner="Test",
        )
        result = render(config)
        self.assertIn("VirtualAlloc", result)

    def test_aslr_info_leak_tcp(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            aslr=True,
            banner="Test",
        )
        result = render(config)
        self.assertIn("DEBUG", result)
        self.assertIn("/DYNAMICBASE", result)

    def test_aslr_info_leak_http(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.HTTP,
            aslr=True,
            banner="Test",
        )
        result = render(config)
        self.assertIn("/info", result)
        self.assertIn("debug_handle", result)

    def test_stack_canary_flag(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            stack_canary=True,
            banner="Test",
        )
        result = render(config)
        # Should have /GS, not /GS-
        self.assertIn("/GS", result)
        self.assertNotIn("/GS-", result)

    def test_safeseh_flag(self):
        config = ServerConfig(
            vuln_type=VulnType.SEH,
            safe_seh=True,
            banner="Test",
        )
        result = render(config)
        self.assertIn("/SAFESEH", result)
        # Make sure it's not /SAFESEH:NO
        lines = result.split("\n")
        compile_lines = [line for line in lines if "/SAFESEH" in line]
        has_safeseh_yes = any(
            "/SAFESEH" in line and "/SAFESEH:NO" not in line for line in compile_lines
        )
        self.assertTrue(has_safeseh_yes)


class TestRendererBadChars(unittest.TestCase):
    """Test bad character filter integration."""

    def test_bad_chars_included(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            bad_chars=[0x0A, 0x0D],
            bad_char_action=BadCharAction.DROP,
            banner="Test",
        )
        result = render(config)
        self.assertIn("filter_bad_chars", result)
        self.assertIn("0x0a", result)
        self.assertIn("0x0d", result)

    def test_no_bad_chars_no_filter(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            bad_chars=[],
            banner="Test",
        )
        result = render(config)
        # Forward declaration should not include filter
        self.assertNotIn("int filter_bad_chars", result)


class TestRendererDecoys(unittest.TestCase):
    """Test decoy command integration."""

    def test_decoys_included(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            decoy_count=2,
            decoy_names=["PROCESS", "QUERY"],
            decoy_types=[
                DecoyType.NEAR_MISS_BUFFER,
                DecoyType.SAFE_FORMAT,
            ],
            banner="Test",
        )
        result = render(config)
        self.assertIn("handle_process", result)
        self.assertIn("handle_query", result)
        self.assertIn("strncpy", result)


class TestRendererFmtstrLeak(unittest.TestCase):
    """Test format string leak in full render pipeline."""

    def test_fmtstr_leak_tcp(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            fmtstr_leak=True,
            banner="Test",
        )
        result = render(config)
        self.assertIn("ECHO", result)
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

    def test_fmtstr_leak_http(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.HTTP,
            fmtstr_leak=True,
            banner="Test",
        )
        result = render(config)
        self.assertIn("/echo", result)
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

    def test_fmtstr_leak_rpc(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.RPC,
            fmtstr_leak=True,
            banner="Test",
        )
        result = render(config)
        self.assertIn("254", result)
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

    def test_fmtstr_leak_coexists_with_aslr_leak(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            aslr=True,
            fmtstr_leak=True,
            banner="Test",
        )
        result = render(config)
        # Both should be present
        self.assertIn("ECHO", result)
        self.assertIn("DEBUG", result)

    def test_no_fmtstr_leak_when_disabled(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            fmtstr_leak=False,
            banner="Test",
        )
        result = render(config)
        self.assertNotIn("VULN_SNPRINTF(echo_buf", result)


class TestRendererArchitecture(unittest.TestCase):
    """Test architecture-specific output."""

    def test_x86_compile_instructions(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            arch=Architecture.X86,
            banner="Test",
        )
        result = render(config)
        self.assertIn("x86", result)
        self.assertIn("x86 Native Tools", result)

    def test_x64_compile_instructions(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            arch=Architecture.X64,
            banner="Test",
        )
        result = render(config)
        self.assertIn("x64", result)
        self.assertIn("x64 Native Tools", result)


if __name__ == "__main__":
    unittest.main()
