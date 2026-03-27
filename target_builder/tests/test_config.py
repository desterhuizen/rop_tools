"""Tests for config.py — enums, dataclass defaults, validation."""

import unittest

from target_builder.src.config import (
    BANNER_POOL,
    DECOY_COMMAND_POOL,
    DIFFICULTY_PRESETS,
    VULN_ARCH_COMPAT,
    Architecture,
    BadCharAction,
    DecoyType,
    DepBypassApi,
    Difficulty,
    ExploitLevel,
    GadgetDensity,
    PaddingStyle,
    Protocol,
    RopDllConfig,
    ServerConfig,
    StackLayoutConfig,
    VulnType,
    address_base_bytes,
    address_conflicts_with_bad_chars,
    find_safe_base_address,
)


class TestEnums(unittest.TestCase):
    """Test that all enums have expected values."""

    def test_vuln_type_values(self):
        self.assertEqual(VulnType.BOF.value, "bof")
        self.assertEqual(VulnType.SEH.value, "seh")
        self.assertEqual(VulnType.EGGHUNTER.value, "egghunter")
        self.assertEqual(VulnType.FMTSTR.value, "fmtstr")

    def test_architecture_values(self):
        self.assertEqual(Architecture.X86.value, "x86")
        self.assertEqual(Architecture.X64.value, "x64")

    def test_protocol_values(self):
        self.assertEqual(Protocol.TCP.value, "tcp")
        self.assertEqual(Protocol.HTTP.value, "http")
        self.assertEqual(Protocol.RPC.value, "rpc")

    def test_bad_char_action_values(self):
        self.assertEqual(BadCharAction.DROP.value, "drop")
        self.assertEqual(BadCharAction.REPLACE.value, "replace")
        self.assertEqual(BadCharAction.TERMINATE.value, "terminate")

    def test_dep_bypass_api_values(self):
        self.assertEqual(len(DepBypassApi), 6)
        self.assertIn("virtualprotect", [a.value for a in DepBypassApi])

    def test_exploit_level_values(self):
        self.assertEqual(ExploitLevel.CONNECT.value, "connect")
        self.assertEqual(ExploitLevel.INTERACT.value, "interact")
        self.assertEqual(ExploitLevel.CRASH.value, "crash")

    def test_gadget_density_values(self):
        self.assertEqual(len(GadgetDensity), 3)

    def test_decoy_type_values(self):
        self.assertEqual(len(DecoyType), 4)

    def test_padding_style_values(self):
        self.assertEqual(PaddingStyle.NONE.value, "none")
        self.assertEqual(PaddingStyle.ARRAY.value, "array")
        self.assertEqual(PaddingStyle.MIXED.value, "mixed")
        self.assertEqual(PaddingStyle.STRUCT.value, "struct")
        self.assertEqual(PaddingStyle.MULTI.value, "multi")
        self.assertEqual(len(PaddingStyle), 5)


class TestServerConfigDefaults(unittest.TestCase):
    """Test ServerConfig defaults and __post_init__."""

    def test_default_values(self):
        config = ServerConfig()
        self.assertEqual(config.vuln_type, VulnType.BOF)
        self.assertEqual(config.port, 9999)
        self.assertEqual(config.arch, Architecture.X86)
        self.assertEqual(config.buffer_size, 2048)
        self.assertEqual(config.protocol, Protocol.TCP)
        self.assertFalse(config.dep)
        self.assertFalse(config.aslr)
        self.assertFalse(config.stack_canary)
        self.assertFalse(config.safe_seh)

    def test_default_command_tcp(self):
        config = ServerConfig(protocol=Protocol.TCP)
        self.assertEqual(config.command, "TRAD")

    def test_default_command_http(self):
        config = ServerConfig(protocol=Protocol.HTTP)
        self.assertEqual(config.command, "/vulnerable")

    def test_default_command_rpc(self):
        config = ServerConfig(protocol=Protocol.RPC)
        self.assertEqual(config.command, "1")

    def test_custom_command_preserved(self):
        config = ServerConfig(command="CUSTOM")
        self.assertEqual(config.command, "CUSTOM")


class TestServerConfigValidation(unittest.TestCase):
    """Test ServerConfig.validate()."""

    def test_valid_bof_x86(self):
        config = ServerConfig(vuln_type=VulnType.BOF, arch=Architecture.X86)
        config.validate()  # Should not raise

    def test_valid_bof_x64(self):
        config = ServerConfig(vuln_type=VulnType.BOF, arch=Architecture.X64)
        config.validate()

    def test_valid_fmtstr_x64(self):
        config = ServerConfig(vuln_type=VulnType.FMTSTR, arch=Architecture.X64)
        config.validate()

    def test_seh_x64_rejected(self):
        config = ServerConfig(vuln_type=VulnType.SEH, arch=Architecture.X64)
        with self.assertRaises(ValueError) as ctx:
            config.validate()
        self.assertIn("seh", str(ctx.exception))
        self.assertIn("x64", str(ctx.exception))

    def test_egghunter_x64_rejected(self):
        config = ServerConfig(vuln_type=VulnType.EGGHUNTER, arch=Architecture.X64)
        with self.assertRaises(ValueError) as ctx:
            config.validate()
        self.assertIn("egghunter", str(ctx.exception))

    def test_safeseh_requires_seh_vuln(self):
        config = ServerConfig(vuln_type=VulnType.BOF, safe_seh=True)
        with self.assertRaises(ValueError):
            config.validate()

    def test_safeseh_with_seh_valid(self):
        config = ServerConfig(vuln_type=VulnType.SEH, safe_seh=True)
        config.validate()

    def test_buffer_size_minimum(self):
        config = ServerConfig(buffer_size=8)
        with self.assertRaises(ValueError):
            config.validate()

    def test_egghunter_vuln_buffer_too_large(self):
        config = ServerConfig(
            vuln_type=VulnType.EGGHUNTER,
            buffer_size=256,
            vuln_buffer_size=256,
        )
        with self.assertRaises(ValueError):
            config.validate()

    def test_egg_tag_length(self):
        config = ServerConfig(
            vuln_type=VulnType.EGGHUNTER,
            egg_tag="ab",
        )
        with self.assertRaises(ValueError):
            config.validate()

    def test_port_range(self):
        config = ServerConfig(port=0)
        with self.assertRaises(ValueError):
            config.validate()

        config = ServerConfig(port=70000)
        with self.assertRaises(ValueError):
            config.validate()


class TestVulnArchCompat(unittest.TestCase):
    """Test architecture compatibility constants."""

    def test_bof_both_archs(self):
        self.assertIn(Architecture.X86, VULN_ARCH_COMPAT[VulnType.BOF])
        self.assertIn(Architecture.X64, VULN_ARCH_COMPAT[VulnType.BOF])

    def test_seh_x86_only(self):
        self.assertIn(Architecture.X86, VULN_ARCH_COMPAT[VulnType.SEH])
        self.assertNotIn(Architecture.X64, VULN_ARCH_COMPAT[VulnType.SEH])

    def test_egghunter_x86_only(self):
        self.assertNotIn(Architecture.X64, VULN_ARCH_COMPAT[VulnType.EGGHUNTER])

    def test_fmtstr_both_archs(self):
        self.assertIn(Architecture.X86, VULN_ARCH_COMPAT[VulnType.FMTSTR])
        self.assertIn(Architecture.X64, VULN_ARCH_COMPAT[VulnType.FMTSTR])


class TestConstants(unittest.TestCase):
    """Test constant pools."""

    def test_banner_pool_not_empty(self):
        self.assertTrue(len(BANNER_POOL) >= 5)

    def test_decoy_pool_not_empty(self):
        self.assertTrue(len(DECOY_COMMAND_POOL) >= 10)

    def test_difficulty_presets_complete(self):
        for diff in Difficulty:
            self.assertIn(diff, DIFFICULTY_PRESETS)
            preset = DIFFICULTY_PRESETS[diff]
            self.assertIn("buffer_size_range", preset)
            self.assertIn("bad_char_count_range", preset)
            self.assertIn("mitigations", preset)
            self.assertIn("pre_padding_range", preset)
            self.assertIn("landing_pad_range", preset)
            self.assertIn("padding_styles", preset)


class TestRopDllConfig(unittest.TestCase):
    """Test RopDllConfig defaults."""

    def test_defaults(self):
        cfg = RopDllConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.gadget_density, GadgetDensity.STANDARD)
        self.assertTrue(cfg.no_aslr)
        self.assertEqual(cfg.base_address, 0x10000000)


class TestBaseAddressUtils(unittest.TestCase):
    """Test base address utility functions."""

    def test_address_base_bytes_x86(self):
        # 0xAABB0000 -> upper bytes are 0xBB, 0xAA
        self.assertEqual(address_base_bytes(0xAABB0000, Architecture.X86), (0xBB, 0xAA))

    def test_address_base_bytes_x86_typical(self):
        # 0x11110000 -> upper bytes are 0x11, 0x11
        self.assertEqual(address_base_bytes(0x11110000, Architecture.X86), (0x11, 0x11))

    def test_address_base_bytes_x64_sub4gb(self):
        # x64 with sub-4GB address should return same as x86
        self.assertEqual(address_base_bytes(0x11110000, Architecture.X64), (0x11, 0x11))

    def test_address_conflicts_no_conflict(self):
        self.assertFalse(
            address_conflicts_with_bad_chars(
                0x11110000, [0x00, 0x0A, 0x0D], Architecture.X86
            )
        )

    def test_address_conflicts_with_null(self):
        # 0x00110000 has 0x11 and 0x00 as upper bytes
        # 0x00 is in bad chars -> conflict
        self.assertTrue(
            address_conflicts_with_bad_chars(0x00110000, [0x00], Architecture.X86)
        )

    def test_address_conflicts_empty_bad_chars(self):
        self.assertFalse(
            address_conflicts_with_bad_chars(0x00400000, [], Architecture.X86)
        )

    def test_find_safe_base_avoids_null(self):
        addr = find_safe_base_address([0x00], Architecture.X86)
        upper_bytes = address_base_bytes(addr, Architecture.X86)
        self.assertNotIn(0x00, upper_bytes)

    def test_find_safe_base_avoids_multiple(self):
        bad = [0x00, 0x0A, 0x0D, 0x11]
        addr = find_safe_base_address(bad, Architecture.X86)
        upper_bytes = address_base_bytes(addr, Architecture.X86)
        for b in bad:
            self.assertNotIn(b, upper_bytes)

    def test_find_safe_base_alignment(self):
        addr = find_safe_base_address([0x00], Architecture.X86)
        self.assertEqual(addr % 0x10000, 0)

    def test_find_safe_base_x64(self):
        addr = find_safe_base_address([0x00, 0x0A], Architecture.X64)
        upper_bytes = address_base_bytes(addr, Architecture.X64)
        self.assertNotIn(0x00, upper_bytes)
        self.assertNotIn(0x0A, upper_bytes)

    def test_find_safe_base_skips_conflicting_preferred(self):
        # 0x11 is in bad chars, so 0x11110000 should be skipped
        bad = [0x00, 0x11]
        addr = find_safe_base_address(bad, Architecture.X86)
        self.assertNotEqual(addr, 0x11110000)
        upper_bytes = address_base_bytes(addr, Architecture.X86)
        self.assertNotIn(0x11, upper_bytes)


class TestBaseAddressValidation(unittest.TestCase):
    """Test ServerConfig validation of base_address."""

    def test_valid_base_address(self):
        config = ServerConfig(base_address=0x11110000)
        config.validate()  # Should not raise

    def test_misaligned_base_rejected(self):
        config = ServerConfig(base_address=0x11110001)
        with self.assertRaises(ValueError):
            config.validate()

    def test_out_of_range_base_rejected(self):
        config = ServerConfig(base_address=0x80000000, arch=Architecture.X86)
        with self.assertRaises(ValueError):
            config.validate()

    def test_base_conflicting_with_bad_chars_rejected(self):
        config = ServerConfig(
            base_address=0x110A0000,
            bad_chars=[0x0A],
        )
        with self.assertRaises(ValueError):
            config.validate()

    def test_rop_dll_base_conflicting_rejected(self):
        config = ServerConfig(
            bad_chars=[0x10],
            rop_dll=RopDllConfig(
                enabled=True,
                base_address=0x10100000,
            ),
        )
        with self.assertRaises(ValueError):
            config.validate()

    def test_default_base_address(self):
        config = ServerConfig()
        self.assertEqual(config.base_address, 0x11110000)
        config.validate()  # Should not raise


class TestStackLayoutConfig(unittest.TestCase):
    """Test StackLayoutConfig defaults and validation."""

    def test_defaults(self):
        layout = StackLayoutConfig()
        self.assertEqual(layout.pre_padding_size, 0)
        self.assertEqual(layout.landing_pad_size, 0)
        self.assertEqual(layout.padding_style, PaddingStyle.NONE)

    def test_server_config_default_stack_layout(self):
        config = ServerConfig()
        self.assertEqual(config.stack_layout.pre_padding_size, 0)
        self.assertEqual(config.stack_layout.landing_pad_size, 0)
        self.assertEqual(config.stack_layout.padding_style, PaddingStyle.NONE)
        config.validate()  # Should not raise

    def test_valid_stack_layout(self):
        config = ServerConfig(
            stack_layout=StackLayoutConfig(
                pre_padding_size=64,
                landing_pad_size=16,
                padding_style=PaddingStyle.MIXED,
            )
        )
        config.validate()  # Should not raise

    def test_negative_pre_padding_rejected(self):
        config = ServerConfig(stack_layout=StackLayoutConfig(pre_padding_size=-1))
        with self.assertRaises(ValueError):
            config.validate()

    def test_negative_landing_pad_rejected(self):
        config = ServerConfig(stack_layout=StackLayoutConfig(landing_pad_size=-1))
        with self.assertRaises(ValueError):
            config.validate()


if __name__ == "__main__":
    unittest.main()
