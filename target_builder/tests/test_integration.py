"""Integration tests for target_builder.

Tests full CLI invocations, output generation, and validation logic.
"""

import os
import tempfile
import unittest

from target_builder.src.cli import parse_args, run
from target_builder.src.config import (
    Architecture,
    GadgetDensity,
    PaddingStyle,
    Protocol,
    RopDllConfig,
    ServerConfig,
    StackLayoutConfig,
    VulnType,
)
from target_builder.src.renderer import render
from target_builder.src.templates.rop_dll import generate_rop_dll


class TestCLIParsing(unittest.TestCase):
    """Test CLI argument parsing."""

    def test_minimal_args(self):
        config = parse_args(["--vuln", "bof"])
        self.assertEqual(config.vuln_type, VulnType.BOF)
        self.assertEqual(config.port, 9999)
        self.assertEqual(config.arch, Architecture.X86)

    def test_full_args(self):
        config = parse_args(
            [
                "--vuln",
                "seh",
                "--port",
                "4444",
                "--arch",
                "x86",
                "--buffer-size",
                "512",
                "--protocol",
                "http",
                "--dep",
                "--aslr",
                "--stack-canary",
                "--safeSEH",
            ]
        )
        self.assertEqual(config.vuln_type, VulnType.SEH)
        self.assertEqual(config.port, 4444)
        self.assertEqual(config.buffer_size, 512)
        self.assertEqual(config.protocol, Protocol.HTTP)
        self.assertTrue(config.dep)
        self.assertTrue(config.aslr)
        self.assertTrue(config.stack_canary)
        self.assertTrue(config.safe_seh)

    def test_bad_chars_parsing(self):
        config = parse_args(
            [
                "--vuln",
                "bof",
                "--bad-chars",
                "0a,0d,00,25",
            ]
        )
        self.assertIn(0x0A, config.bad_chars)
        self.assertIn(0x0D, config.bad_chars)
        self.assertIn(0x00, config.bad_chars)
        self.assertIn(0x25, config.bad_chars)

    def test_arch_vuln_compat_rejected(self):
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(["--vuln", "seh", "--arch", "x64"])

    def test_egghunter_x64_rejected(self):
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(["--vuln", "egghunter", "--arch", "x64"])


class TestRandomization(unittest.TestCase):
    """Test randomized challenge generation."""

    def test_random_seed_deterministic(self):
        config1 = parse_args(["--random", "--random-seed", "12345"])
        config2 = parse_args(["--random", "--random-seed", "12345"])
        self.assertEqual(config1.vuln_type, config2.vuln_type)
        self.assertEqual(config1.arch, config2.arch)
        self.assertEqual(config1.protocol, config2.protocol)
        self.assertEqual(config1.buffer_size, config2.buffer_size)
        self.assertEqual(config1.bad_chars, config2.bad_chars)

    def test_random_produces_valid_config(self):
        config = parse_args(["--random", "--random-seed", "42"])
        # Should not raise
        config.validate()

    def test_difficulty_easy(self):
        config = parse_args(
            [
                "--random",
                "--random-seed",
                "100",
                "--difficulty",
                "easy",
            ]
        )
        # Easy should have no mitigations
        self.assertFalse(config.dep)
        self.assertFalse(config.aslr)
        self.assertFalse(config.stack_canary)
        self.assertEqual(config.decoy_count, 0)

    def test_difficulty_hard(self):
        config = parse_args(
            [
                "--random",
                "--random-seed",
                "100",
                "--difficulty",
                "hard",
            ]
        )
        # Hard should have mitigations
        self.assertTrue(config.dep)
        self.assertTrue(config.aslr)
        self.assertTrue(config.stack_canary)


class TestStackLayoutCLI(unittest.TestCase):
    """Test stack layout CLI arguments."""

    def test_pre_padding_arg(self):
        config = parse_args(
            ["--vuln", "bof", "--pre-padding", "64", "--padding-style", "array"]
        )
        self.assertEqual(config.stack_layout.pre_padding_size, 64)
        self.assertEqual(config.stack_layout.padding_style, PaddingStyle.ARRAY)

    def test_landing_pad_arg(self):
        config = parse_args(["--vuln", "bof", "--landing-pad", "16"])
        self.assertEqual(config.stack_layout.landing_pad_size, 16)

    def test_default_stack_layout(self):
        config = parse_args(["--vuln", "bof"])
        self.assertEqual(config.stack_layout.pre_padding_size, 0)
        self.assertEqual(config.stack_layout.landing_pad_size, 0)
        self.assertEqual(config.stack_layout.padding_style, PaddingStyle.NONE)

    def test_random_hard_has_stack_layout(self):
        config = parse_args(
            ["--random", "--random-seed", "100", "--difficulty", "hard"]
        )
        # Hard difficulty should produce some padding
        layout = config.stack_layout
        self.assertGreaterEqual(layout.pre_padding_size, 64)
        self.assertLessEqual(layout.pre_padding_size, 256)
        self.assertGreaterEqual(layout.landing_pad_size, 8)
        self.assertLessEqual(layout.landing_pad_size, 32)

    def test_random_easy_no_padding(self):
        config = parse_args(
            ["--random", "--random-seed", "100", "--difficulty", "easy"]
        )
        self.assertEqual(config.stack_layout.pre_padding_size, 0)
        self.assertEqual(config.stack_layout.landing_pad_size, 0)

    def test_stack_layout_in_rendered_output(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            banner="Test",
            stack_layout=StackLayoutConfig(
                pre_padding_size=64,
                landing_pad_size=32,
                padding_style=PaddingStyle.ARRAY,
            ),
        )
        result = render(config)
        self.assertIn("audit_trail[64]", result)
        self.assertIn("max_process_len", result)


class TestFullRender(unittest.TestCase):
    """Test full rendering pipeline."""

    def test_bof_tcp_full_render(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            banner="Test Server",
        )
        result = render(config)
        # Must have all major sections
        self.assertIn("#include <winsock2.h>", result)
        self.assertIn("int main(", result)
        self.assertIn("handle_connection", result)
        self.assertIn("strcpy", result)
        self.assertIn("WSAStartup", result)

    def test_all_vuln_protocol_combos(self):
        """Every valid vuln+protocol combination should render."""
        combos = [
            (VulnType.BOF, Protocol.TCP),
            (VulnType.BOF, Protocol.HTTP),
            (VulnType.BOF, Protocol.RPC),
            (VulnType.SEH, Protocol.TCP),
            (VulnType.SEH, Protocol.HTTP),
            (VulnType.SEH, Protocol.RPC),
            (VulnType.EGGHUNTER, Protocol.TCP),
            (VulnType.EGGHUNTER, Protocol.HTTP),
            (VulnType.EGGHUNTER, Protocol.RPC),
            (VulnType.FMTSTR, Protocol.TCP),
            (VulnType.FMTSTR, Protocol.HTTP),
            (VulnType.FMTSTR, Protocol.RPC),
        ]
        for vuln, proto in combos:
            with self.subTest(vuln=vuln.value, proto=proto.value):
                config = ServerConfig(
                    vuln_type=vuln,
                    protocol=proto,
                    buffer_size=2048,
                    vuln_buffer_size=128,
                    banner="Test",
                )
                result = render(config)
                self.assertIn("main(", result)
                self.assertIn("handle_connection", result)
                self.assertTrue(len(result) > 500)


class TestRopDll(unittest.TestCase):
    """Test ROP DLL generation."""

    def test_minimal_density(self):
        config = RopDllConfig(enabled=True, gadget_density=GadgetDensity.MINIMAL)
        result = generate_rop_dll(config)
        self.assertIn("HelperInit", result)
        self.assertIn("pop eax", result)
        self.assertIn("jmp esp", result)
        # Should not have standard gadgets
        self.assertNotIn("ProcessData", result)

    def test_standard_density(self):
        config = RopDllConfig(enabled=True, gadget_density=GadgetDensity.STANDARD)
        result = generate_rop_dll(config)
        self.assertIn("ProcessData", result)
        self.assertIn("xchg eax, esp", result)
        # Should not have full gadgets
        self.assertNotIn("AnalyzeStream", result)

    def test_full_density(self):
        config = RopDllConfig(enabled=True, gadget_density=GadgetDensity.FULL)
        result = generate_rop_dll(config)
        self.assertIn("AnalyzeStream", result)
        self.assertIn("CompressPayload", result)
        self.assertIn("DecryptBlock", result)

    def test_dll_has_dllmain(self):
        config = RopDllConfig(enabled=True)
        result = generate_rop_dll(config)
        self.assertIn("DllMain", result)
        self.assertIn("RopHelperInit", result)

    def test_custom_base_address(self):
        config = RopDllConfig(enabled=True, base_address=0x62500000)
        result = generate_rop_dll(config)
        self.assertIn("0x62500000", result)


class TestCLIRun(unittest.TestCase):
    """Test the run() function with file output."""

    def test_run_writes_output_file(self):
        with tempfile.NamedTemporaryFile(suffix=".cpp", delete=False) as f:
            tmp_path = f.name

        try:
            exit_code = run(
                [
                    "--vuln",
                    "bof",
                    "--output",
                    tmp_path,
                ]
            )
            self.assertEqual(exit_code, 0)
            with open(tmp_path) as f:
                content = f.read()
            self.assertIn("#include <winsock2.h>", content)
            self.assertIn("strcpy", content)
        finally:
            os.unlink(tmp_path)

    def test_run_with_build_script(self):
        with tempfile.NamedTemporaryFile(suffix=".cpp", delete=False) as f:
            tmp_cpp = f.name

        tmp_bat = tmp_cpp.rsplit(".", 1)[0] + ".bat"

        try:
            exit_code = run(
                [
                    "--vuln",
                    "bof",
                    "--output",
                    tmp_cpp,
                    "--build-script",
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(tmp_bat))
            with open(tmp_bat) as f:
                content = f.read()
            self.assertIn("cl.exe", content)
        finally:
            if os.path.exists(tmp_cpp):
                os.unlink(tmp_cpp)
            if os.path.exists(tmp_bat):
                os.unlink(tmp_bat)


class TestBaseAddress(unittest.TestCase):
    """Test base address CLI and rendering."""

    def test_base_address_hex_parsed(self):
        config = parse_args(["--vuln", "bof", "--base-address", "0x11110000"])
        self.assertEqual(config.base_address, 0x11110000)

    def test_base_address_auto(self):
        config = parse_args(
            [
                "--vuln",
                "bof",
                "--base-address",
                "auto",
                "--bad-chars",
                "00,0a,0d",
            ]
        )
        self.assertIsNotNone(config.base_address)
        # Upper bytes should not contain bad chars
        upper = (config.base_address >> 16) & 0xFF
        self.assertNotIn(upper, [0x00, 0x0A, 0x0D])

    def test_base_address_in_build_script(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            base_address=0x11110000,
            banner="Test",
        )
        from target_builder.src.build_script import generate as gen_build

        bat = gen_build(config)
        self.assertIn("/BASE:0x11110000", bat)

    def test_base_address_in_compile_instructions(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            base_address=0x11110000,
            banner="Test",
        )
        result = render(config)
        self.assertIn("/BASE:0x11110000", result)

    def test_default_base_address(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            banner="Test",
        )
        result = render(config)
        self.assertIn("/BASE:0x11110000", result)

    def test_random_with_bad_chars_gets_safe_base(self):
        config = parse_args(
            [
                "--random",
                "--random-seed",
                "42",
                "--bad-chars",
                "00,0a,0d",
            ]
        )
        self.assertIsNotNone(config.base_address)
        upper_b2 = (config.base_address >> 16) & 0xFF
        upper_b3 = (config.base_address >> 24) & 0xFF
        for byte in [upper_b2, upper_b3]:
            self.assertNotIn(byte, [0x00, 0x0A, 0x0D])


class TestFmtstrLeakIntegration(unittest.TestCase):
    """Integration tests for --fmtstr-leak flag."""

    def test_cli_fmtstr_leak_flag(self):
        config = parse_args(["--vuln", "bof", "--fmtstr-leak"])
        self.assertTrue(config.fmtstr_leak)

    def test_cli_fmtstr_leak_default_off(self):
        config = parse_args(["--vuln", "bof"])
        self.assertFalse(config.fmtstr_leak)

    def test_fmtstr_leak_in_rendered_output(self):
        config = parse_args(["--vuln", "bof", "--fmtstr-leak"])
        from target_builder.src.renderer import render

        result = render(config)
        self.assertIn("ECHO", result)
        self.assertIn("_snprintf(echo_buf", result)

    def test_random_hard_may_enable_fmtstr_leak(self):
        """Hard difficulty with ASLR can randomly enable fmtstr_leak."""
        # Use a seed that produces aslr=True for hard difficulty
        config = parse_args(
            ["--random", "--random-seed", "100", "--difficulty", "hard"]
        )
        # Hard always has aslr, so fmtstr_leak is possible
        self.assertTrue(config.aslr)
        # fmtstr_leak is random (50%) — just check the field exists
        self.assertIsInstance(config.fmtstr_leak, bool)

    def test_random_easy_no_fmtstr_leak(self):
        """Easy difficulty should never enable fmtstr_leak."""
        config = parse_args(["--random", "--random-seed", "42", "--difficulty", "easy"])
        self.assertFalse(config.fmtstr_leak)


if __name__ == "__main__":
    unittest.main()
