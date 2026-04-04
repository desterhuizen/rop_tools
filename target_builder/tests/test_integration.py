"""Integration tests for target_builder.

Tests full CLI invocations, output generation, and validation logic.
"""

import os
import tempfile
import unittest

from target_builder.src.cli import parse_args, run
from target_builder.src.config import (
    Architecture,
    BadCharAction,
    Compiler,
    DepBypassApi,
    GadgetDensity,
    HintVerbosity,
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
                "--rop-dll",
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
        self.assertTrue(config.rop_dll.enabled)

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

    def test_dll_includes_virtualprotect_when_dep_api_set(self):
        config = RopDllConfig(enabled=True, dep_api=DepBypassApi.VIRTUALPROTECT)
        result = generate_rop_dll(config)
        self.assertIn("VirtualProtect", result)
        self.assertIn("rop_init_helper_data", result)

    def test_dll_includes_virtualalloc_when_dep_api_set(self):
        config = RopDllConfig(enabled=True, dep_api=DepBypassApi.VIRTUALALLOC)
        result = generate_rop_dll(config)
        self.assertIn("VirtualAlloc", result)
        self.assertIn("rop_init_scratch", result)

    def test_dll_includes_writeprocessmemory_when_dep_api_set(self):
        config = RopDllConfig(enabled=True, dep_api=DepBypassApi.WRITEPROCESSMEMORY)
        result = generate_rop_dll(config)
        self.assertIn("WriteProcessMemory", result)
        self.assertIn("rop_patch_callback", result)

    def test_dll_includes_heapcreate_when_dep_api_set(self):
        config = RopDllConfig(enabled=True, dep_api=DepBypassApi.HEAPCREATE)
        result = generate_rop_dll(config)
        self.assertIn("HeapCreate", result)
        self.assertIn("rop_init_heap", result)

    def test_dll_includes_setprocessdeppolicy_when_dep_api_set(self):
        config = RopDllConfig(enabled=True, dep_api=DepBypassApi.SETPROCESSDEPPOLICY)
        result = generate_rop_dll(config)
        self.assertIn("SetProcessDEPPolicy", result)
        self.assertIn("rop_check_dep", result)

    def test_dll_includes_ntallocate_when_dep_api_set(self):
        config = RopDllConfig(enabled=True, dep_api=DepBypassApi.NTALLOCATE)
        result = generate_rop_dll(config)
        self.assertIn("NtAllocateVirtualMemory", result)
        self.assertIn("rop_init_nt_alloc", result)

    def test_dll_no_dep_api_no_extra_imports(self):
        config = RopDllConfig(enabled=True, dep_api=None)
        result = generate_rop_dll(config)
        for api in [
            "VirtualProtect",
            "VirtualAlloc",
            "WriteProcessMemory",
            "HeapCreate",
            "SetProcessDEPPolicy",
            "NtAllocateVirtualMemory",
        ]:
            self.assertNotIn(api, result)

    def test_dll_dep_api_matches_server(self):
        """DLL and server should use the same DEP API."""
        for api in DepBypassApi:
            server_config = ServerConfig(
                dep=True,
                dep_api=api,
                rop_dll=RopDllConfig(enabled=True, dep_api=api),
            )
            server = render(server_config)
            dll = generate_rop_dll(server_config.rop_dll)

            api_names = {
                "virtualprotect": "VirtualProtect",
                "virtualalloc": "VirtualAlloc",
                "writeprocessmemory": "WriteProcessMemory",
                "heapcreate": "HeapCreate",
                "setprocessdeppolicy": "SetProcessDEPPolicy",
                "ntallocate": "NtAllocateVirtualMemory",
            }
            target = api_names[api.value]
            self.assertIn(target, server, f"Server missing {target}")
            self.assertIn(target, dll, f"DLL missing {target}")


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
        self.assertIn("VULN_SNPRINTF(echo_buf", result)

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


class TestConstrainedRandomization(unittest.TestCase):
    """Test --random with explicit overrides/constraints."""

    def test_explicit_arch_x86_respected(self):
        """--random --arch x86 should always produce x86."""
        for seed in [1, 42, 100, 999, 12345]:
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--arch", "x86"]
            )
            self.assertEqual(config.arch, Architecture.X86)

    def test_explicit_arch_x64_respected(self):
        config = parse_args(["--random", "--random-seed", "42", "--arch", "x64"])
        self.assertEqual(config.arch, Architecture.X64)

    def test_explicit_protocol_tcp_respected(self):
        """--random --protocol tcp should always produce tcp."""
        for seed in [1, 42, 100, 999]:
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--protocol", "tcp"]
            )
            self.assertEqual(config.protocol, Protocol.TCP)

    def test_explicit_protocol_http_respected(self):
        config = parse_args(["--random", "--random-seed", "42", "--protocol", "http"])
        self.assertEqual(config.protocol, Protocol.HTTP)

    def test_vuln_comma_list(self):
        """--vuln bof,seh should only produce bof or seh."""
        results = set()
        for seed in range(50):
            config = parse_args(
                [
                    "--random",
                    "--random-seed",
                    str(seed),
                    "--vuln",
                    "bof,seh",
                    "--arch",
                    "x86",
                ]
            )
            results.add(config.vuln_type)
        self.assertTrue(results.issubset({VulnType.BOF, VulnType.SEH}))
        self.assertEqual(len(results), 2, "Expected both bof and seh across seeds")

    def test_protocol_comma_list(self):
        """--protocol tcp,http should only produce tcp or http."""
        results = set()
        for seed in range(50):
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--protocol", "tcp,http"]
            )
            results.add(config.protocol)
        self.assertTrue(results.issubset({Protocol.TCP, Protocol.HTTP}))
        self.assertEqual(len(results), 2)

    def test_bad_char_action_comma_list(self):
        """--bad-char-action drop,replace should pick from those two."""
        results = set()
        for seed in range(50):
            config = parse_args(
                [
                    "--random",
                    "--random-seed",
                    str(seed),
                    "--bad-char-action",
                    "drop,replace",
                ]
            )
            results.add(config.bad_char_action)
        self.assertTrue(results.issubset({BadCharAction.DROP, BadCharAction.REPLACE}))

    def test_padding_style_comma_list(self):
        """--padding-style mixed,struct should pick from those two."""
        results = set()
        for seed in range(50):
            config = parse_args(
                [
                    "--random",
                    "--random-seed",
                    str(seed),
                    "--padding-style",
                    "mixed,struct",
                ]
            )
            results.add(config.stack_layout.padding_style)
        self.assertTrue(results.issubset({PaddingStyle.MIXED, PaddingStyle.STRUCT}))

    def test_vuln_comma_arch_filtering(self):
        """--vuln bof,seh --arch x64 should filter out seh, pick bof."""
        config = parse_args(
            ["--random", "--random-seed", "42", "--vuln", "bof,seh", "--arch", "x64"]
        )
        self.assertEqual(config.vuln_type, VulnType.BOF)

    def test_vuln_comma_arch_filtering_empty_error(self):
        """--vuln seh,egghunter --arch x64 should error."""
        with self.assertRaises(ValueError):
            parse_args(
                [
                    "--random",
                    "--random-seed",
                    "42",
                    "--vuln",
                    "seh,egghunter",
                    "--arch",
                    "x64",
                ]
            )

    def test_single_vuln_pin(self):
        """--vuln bof should always produce bof."""
        for seed in [1, 42, 100]:
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--vuln", "bof"]
            )
            self.assertEqual(config.vuln_type, VulnType.BOF)

    def test_bad_char_action_single_respected(self):
        """Single --bad-char-action should be pinned."""
        config = parse_args(
            ["--random", "--random-seed", "42", "--bad-char-action", "terminate"]
        )
        self.assertEqual(config.bad_char_action, BadCharAction.TERMINATE)

    def test_dep_api_respected(self):
        """--dep-api should be pinned during randomization."""
        config = parse_args(
            ["--random", "--random-seed", "42", "--dep", "--dep-api", "virtualalloc"]
        )
        self.assertEqual(config.dep_api, DepBypassApi.VIRTUALALLOC)

    def test_padding_style_none_explicit(self):
        """--padding-style none should be respected, not randomized."""
        for seed in range(20):
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--padding-style", "none"]
            )
            self.assertEqual(config.stack_layout.padding_style, PaddingStyle.NONE)

    def test_invalid_vuln_value_rejected(self):
        """Invalid --vuln value should be rejected."""
        with self.assertRaises(SystemExit):
            parse_args(["--vuln", "garbage"])

    def test_invalid_protocol_value_rejected(self):
        """Invalid --protocol value should be rejected."""
        with self.assertRaises(SystemExit):
            parse_args(["--vuln", "bof", "--protocol", "garbage"])

    def test_comma_list_without_random_rejected(self):
        """Comma-lists without --random should error."""
        with self.assertRaises(SystemExit):
            parse_args(["--vuln", "bof,seh"])


class TestExcludeProtection(unittest.TestCase):
    """Test --exclude-protection flag."""

    def test_exclude_dep(self):
        for seed in range(20):
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--exclude-protection", "dep"]
            )
            self.assertFalse(config.dep)

    def test_exclude_aslr(self):
        for seed in range(20):
            config = parse_args(
                ["--random", "--random-seed", str(seed), "--exclude-protection", "aslr"]
            )
            self.assertFalse(config.aslr)

    def test_exclude_canary(self):
        for seed in range(20):
            config = parse_args(
                [
                    "--random",
                    "--random-seed",
                    str(seed),
                    "--exclude-protection",
                    "canary",
                ]
            )
            self.assertFalse(config.stack_canary)

    def test_exclude_safeseh(self):
        for seed in range(20):
            config = parse_args(
                [
                    "--random",
                    "--random-seed",
                    str(seed),
                    "--vuln",
                    "seh",
                    "--arch",
                    "x86",
                    "--exclude-protection",
                    "safeseh",
                ]
            )
            self.assertFalse(config.safe_seh)

    def test_exclude_fmtstr_leak(self):
        for seed in range(20):
            config = parse_args(
                [
                    "--random",
                    "--random-seed",
                    str(seed),
                    "--difficulty",
                    "hard",
                    "--base-address",
                    "auto",
                    "--exclude-protection",
                    "fmtstr-leak",
                ]
            )
            self.assertFalse(config.fmtstr_leak)

    def test_exclude_multiple(self):
        config = parse_args(
            [
                "--random",
                "--random-seed",
                "42",
                "--exclude-protection",
                "dep,aslr,canary",
            ]
        )
        self.assertFalse(config.dep)
        self.assertFalse(config.aslr)
        self.assertFalse(config.stack_canary)

    def test_exclude_overrides_difficulty(self):
        """--exclude-protection dep --difficulty hard should disable DEP."""
        config = parse_args(
            [
                "--random",
                "--random-seed",
                "42",
                "--difficulty",
                "hard",
                "--exclude-protection",
                "dep",
            ]
        )
        self.assertFalse(config.dep)

    def test_contradiction_exclude_and_enable_dep(self):
        """--exclude-protection dep --dep should error."""
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(
                [
                    "--random",
                    "--random-seed",
                    "42",
                    "--exclude-protection",
                    "dep",
                    "--dep",
                ]
            )

    def test_contradiction_exclude_and_enable_aslr(self):
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(
                [
                    "--random",
                    "--random-seed",
                    "42",
                    "--exclude-protection",
                    "aslr",
                    "--aslr",
                ]
            )

    def test_invalid_protection_name(self):
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(
                ["--random", "--random-seed", "42", "--exclude-protection", "invalid"]
            )

    def test_exclude_not_valid_without_random(self):
        with self.assertRaises(SystemExit):
            parse_args(["--vuln", "bof", "--exclude-protection", "dep"])


class TestBackwardCompatibility(unittest.TestCase):
    """Ensure existing CLI invocations still work after None defaults."""

    def test_non_random_defaults_preserved(self):
        config = parse_args(["--vuln", "bof"])
        self.assertEqual(config.arch, Architecture.X86)
        self.assertEqual(config.protocol, Protocol.TCP)
        self.assertEqual(config.bad_char_action, BadCharAction.DROP)
        self.assertEqual(config.stack_layout.padding_style, PaddingStyle.NONE)
        self.assertEqual(config.dep_api, DepBypassApi.VIRTUALPROTECT)

    def test_non_random_explicit_values_work(self):
        config = parse_args(
            [
                "--vuln",
                "bof",
                "--arch",
                "x64",
                "--protocol",
                "http",
                "--bad-char-action",
                "terminate",
                "--padding-style",
                "mixed",
                "--dep",
                "--dep-api",
                "virtualalloc",
            ]
        )
        self.assertEqual(config.arch, Architecture.X64)
        self.assertEqual(config.protocol, Protocol.HTTP)
        self.assertEqual(config.bad_char_action, BadCharAction.TERMINATE)
        self.assertEqual(config.stack_layout.padding_style, PaddingStyle.MIXED)
        self.assertEqual(config.dep_api, DepBypassApi.VIRTUALALLOC)


class TestCompilerFlag(unittest.TestCase):
    """Test --compiler flag parsing and validation."""

    def test_compiler_default_msvc(self):
        config = parse_args(["--vuln", "bof"])
        self.assertEqual(config.compiler, Compiler.MSVC)

    def test_compiler_mingw(self):
        config = parse_args(["--vuln", "bof", "--compiler", "mingw"])
        self.assertEqual(config.compiler, Compiler.MINGW)

    def test_mingw_rejects_rop_dll(self):
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(["--vuln", "bof", "--compiler", "mingw", "--rop-dll"])

    def test_mingw_rejects_embedded_gadgets(self):
        with self.assertRaises((ValueError, SystemExit)):
            parse_args(["--vuln", "bof", "--compiler", "mingw", "--embedded-gadgets"])

    def test_mingw_build_script(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("#!/bin/bash", result)
        self.assertIn("i686-w64-mingw32-g++", result)
        self.assertIn("-lws2_32", result)

    def test_mingw_x64_compiler_name(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            arch=Architecture.X64,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("x86_64-w64-mingw32-g++", result)

    def test_mingw_dep_flags(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            dep=True,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("-Wl,--nxcompat", result)
        self.assertNotIn("-Wl,--disable-nxcompat", result)

    def test_mingw_aslr_flags(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            aslr=True,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("-Wl,--dynamicbase", result)

    def test_mingw_base_address(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            base_address=0x22220000,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("-Wl,--image-base,0x22220000", result)

    def test_mingw_seh_exceptions_flag(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.SEH,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("-fseh-exceptions", result)

    def test_mingw_wine_comment(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("wine", result)

    def test_mingw_no_stack_protector(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            stack_canary=False,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("-fno-stack-protector", result)

    def test_mingw_stack_protector(self):
        from target_builder.src.build_script import generate

        config = ServerConfig(
            vuln_type=VulnType.BOF,
            stack_canary=True,
            compiler=Compiler.MINGW,
        )
        result = generate(config)
        self.assertIn("-fstack-protector", result)


class TestExploitHintsFlag(unittest.TestCase):
    """Test --exploit-hints flag parsing."""

    def test_default_is_full(self):
        config = parse_args(["--vuln", "bof", "--exploit", "crash"])
        self.assertEqual(config.exploit.hint_verbosity, HintVerbosity.FULL)

    def test_minimal(self):
        config = parse_args(
            ["--vuln", "bof", "--exploit", "crash", "--exploit-hints", "minimal"]
        )
        self.assertEqual(config.exploit.hint_verbosity, HintVerbosity.MINIMAL)

    def test_none(self):
        config = parse_args(
            ["--vuln", "bof", "--exploit", "crash", "--exploit-hints", "none"]
        )
        self.assertEqual(config.exploit.hint_verbosity, HintVerbosity.NONE)


class TestGenerateCompletion(unittest.TestCase):
    """Test --generate-completion integration."""

    def test_bash_exits_cleanly(self):
        result = run(["--generate-completion", "bash"])
        self.assertEqual(result, 0)

    def test_zsh_exits_cleanly(self):
        result = run(["--generate-completion", "zsh"])
        self.assertEqual(result, 0)

    def test_no_vuln_required(self):
        """Completion should work without --vuln."""
        result = run(["--generate-completion", "bash"])
        self.assertEqual(result, 0)


class TestPragmaComment(unittest.TestCase):
    """Test pragma comment guard for different compilers."""

    def test_msvc_pragma(self):
        from target_builder.src.templates.base import generate_pragma_comment

        config = ServerConfig(compiler=Compiler.MSVC)
        result = generate_pragma_comment(config)
        self.assertIn('#pragma comment(lib, "ws2_32.lib")', result)
        self.assertNotIn("#ifdef", result)

    def test_mingw_pragma_guarded(self):
        from target_builder.src.templates.base import generate_pragma_comment

        config = ServerConfig(compiler=Compiler.MINGW)
        result = generate_pragma_comment(config)
        self.assertIn("#ifdef _MSC_VER", result)
        self.assertIn("#endif", result)
        self.assertIn('#pragma comment(lib, "ws2_32.lib")', result)


class TestEgghunterStagingWarning(unittest.TestCase):
    """Tests for egghunter + tight landing pad warning."""

    def test_egghunter_tight_landing_pad_warns(self):
        """Egghunter with tight landing pad and no staging should warn."""
        import io
        import sys

        stderr = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr
        try:
            parse_args(
                [
                    "--vuln",
                    "egghunter",
                    "--landing-pad",
                    "32",
                ]
            )
        finally:
            sys.stderr = old_stderr
        self.assertIn("--data-staging", stderr.getvalue())

    def test_egghunter_tight_landing_pad_no_warn_with_staging(self):
        """No warning when --data-staging is provided."""
        import io
        import sys

        stderr = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr
        try:
            parse_args(
                [
                    "--vuln",
                    "egghunter",
                    "--landing-pad",
                    "32",
                    "--data-staging",
                ]
            )
        finally:
            sys.stderr = old_stderr
        self.assertNotIn("--data-staging", stderr.getvalue())

    def test_egghunter_no_landing_pad_no_warn(self):
        """No warning when landing pad is unlimited (0)."""
        import io
        import sys

        stderr = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr
        try:
            parse_args(["--vuln", "egghunter"])
        finally:
            sys.stderr = old_stderr
        self.assertNotIn("--data-staging", stderr.getvalue())

    def test_egghunter_large_landing_pad_no_warn(self):
        """No warning when landing pad is large enough."""
        import io
        import sys

        stderr = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr
        try:
            parse_args(
                [
                    "--vuln",
                    "egghunter",
                    "--landing-pad",
                    "256",
                ]
            )
        finally:
            sys.stderr = old_stderr
        self.assertNotIn("--data-staging", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
