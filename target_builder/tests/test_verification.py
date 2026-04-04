"""Tests for the verification checks feature.

Covers template generation, config validation, renderer integration,
exploit skeleton integration, and CLI randomization.
"""

import unittest

from target_builder.src.config import (
    DIFFICULTY_PRESETS,
    Difficulty,
    ExploitConfig,
    ExploitLevel,
    Protocol,
    ServerConfig,
    VulnType,
)
from target_builder.src.exploit_skeleton import generate as generate_exploit
from target_builder.src.renderer import render
from target_builder.src.templates.verification import (
    TIER_1_CHECKS,
    TIER_2_CHECKS,
    TIER_3_CHECKS,
    format_solution_comment,
    format_solution_python,
    generate_verification_function,
)


class TestVerificationTemplate(unittest.TestCase):
    """Test the verification template generator."""

    def test_level_zero_returns_empty(self):
        code, sol = generate_verification_function(0, 42)
        self.assertEqual(code, "")
        self.assertEqual(sol, [])

    def test_negative_level_returns_empty(self):
        code, sol = generate_verification_function(-1, 42)
        self.assertEqual(code, "")
        self.assertEqual(sol, [])

    def test_level_one_produces_one_check(self):
        code, sol = generate_verification_function(1, 42)
        self.assertIn("verify_input", code)
        self.assertIn("return 0;", code)
        self.assertIn("return 1;", code)
        self.assertGreater(len(sol), 0)

    def test_level_three_basic_tier_only(self):
        """Levels 1-3 should only produce tier 1 (basic) checks."""
        code, sol = generate_verification_function(3, 42)
        # Should not contain tier 2/3 check type labels
        for check in TIER_2_CHECKS + TIER_3_CHECKS:
            label = check.replace("_", " ")
            self.assertNotIn(f": {label}", code)

    def test_level_five_includes_intermediate(self):
        """Level 5 should include tier 2 (intermediate) checks."""
        code, sol = generate_verification_function(5, 42)
        # Should have at least one tier 2 check (checks 4-5 are tier 2)
        has_tier2 = any(check in code for check in TIER_2_CHECKS)
        self.assertTrue(has_tier2, "Level 5 should include tier 2 checks")

    def test_level_eight_includes_advanced(self):
        """Level 8 should include tier 3 (advanced) checks."""
        code, sol = generate_verification_function(8, 42)
        # Should have at least one tier 3 check (checks 7-8 are tier 3)
        has_tier3 = any(check in code for check in TIER_3_CHECKS)
        self.assertTrue(has_tier3, "Level 8 should include tier 3 checks")

    def test_deterministic_with_same_seed(self):
        code1, sol1 = generate_verification_function(5, 123)
        code2, sol2 = generate_verification_function(5, 123)
        self.assertEqual(code1, code2)
        self.assertEqual(sol1, sol2)

    def test_different_seed_different_output(self):
        code1, _ = generate_verification_function(5, 100)
        code2, _ = generate_verification_function(5, 200)
        self.assertNotEqual(code1, code2)

    def test_solution_offsets_unique(self):
        """Each offset in the solution should appear at most once."""
        _, sol = generate_verification_function(8, 42)
        offsets = [o for o, _ in sol]
        self.assertEqual(len(offsets), len(set(offsets)))

    def test_solution_values_nonzero(self):
        """Solution byte values should never be 0x00 (null terminator)."""
        _, sol = generate_verification_function(10, 42)
        for _, value in sol:
            self.assertNotEqual(value, 0x00, "Solution should not contain null bytes")

    def test_solution_sorted_by_offset(self):
        _, sol = generate_verification_function(7, 42)
        offsets = [o for o, _ in sol]
        self.assertEqual(offsets, sorted(offsets))

    def test_min_length_check_present(self):
        code, _ = generate_verification_function(3, 42)
        self.assertIn("data_len <", code)

    def test_max_level_ten(self):
        """Level 10 should produce output without errors."""
        code, sol = generate_verification_function(10, 42)
        self.assertIn("verify_input", code)
        self.assertGreater(len(sol), 0)

    def test_all_check_types_reachable(self):
        """With enough seeds, all 12 check types should be generated."""
        # Check types as they appear in C++ comments (space-separated)
        all_labels = {
            c.replace("_", " ") for c in TIER_1_CHECKS + TIER_2_CHECKS + TIER_3_CHECKS
        }
        found = set()
        for seed in range(500):
            code, _ = generate_verification_function(10, seed)
            code_lower = code.lower()
            for label in all_labels:
                if label in code_lower:
                    found.add(label)
        self.assertEqual(
            found, all_labels, f"Missing check types: {all_labels - found}"
        )


class TestVerificationFormatters(unittest.TestCase):
    """Test solution formatting helpers."""

    def test_format_comment_empty(self):
        result = format_solution_comment([])
        self.assertEqual(result, "")

    def test_format_comment_nonempty(self):
        sol = [(0, 0x41), (4, 0xBE)]
        result = format_solution_comment(sol)
        self.assertIn("0x41", result)
        self.assertIn("'A'", result)
        self.assertIn("0xBE", result)
        self.assertIn("Verification", result)

    def test_format_python_empty(self):
        result = format_solution_python([])
        self.assertEqual(result, "")

    def test_format_python_nonempty(self):
        sol = [(0, 0x41), (4, 0xBE)]
        result = format_solution_python(sol)
        self.assertIn("verify_header = bytearray(", result)
        self.assertIn("verify_header[0] = 0x41", result)
        self.assertIn("verify_header[4] = 0xBE", result)


class TestVerificationConfig(unittest.TestCase):
    """Test config validation for verification fields."""

    def test_default_verification_zero(self):
        config = ServerConfig()
        self.assertEqual(config.verification_level, 0)
        self.assertIsNone(config.verification_seed)

    def test_valid_verification_level(self):
        config = ServerConfig(verification_level=5, verification_seed=42)
        config.validate()  # should not raise

    def test_negative_verification_raises(self):
        config = ServerConfig(verification_level=-1)
        with self.assertRaises(ValueError):
            config.validate()

    def test_excessive_verification_raises(self):
        config = ServerConfig(verification_level=11)
        with self.assertRaises(ValueError):
            config.validate()

    def test_difficulty_presets_have_verification_range(self):
        for diff in Difficulty:
            preset = DIFFICULTY_PRESETS[diff]
            self.assertIn(
                "verification_range",
                preset,
                f"Missing verification_range in {diff.value}",
            )
            lo, hi = preset["verification_range"]
            self.assertGreaterEqual(hi, lo)


class TestVerificationRenderer(unittest.TestCase):
    """Test renderer integration with verification checks."""

    def _render(self, level=3, seed=42, protocol=Protocol.TCP, vuln=VulnType.BOF):
        config = ServerConfig(
            vuln_type=vuln,
            protocol=protocol,
            buffer_size=512,
            verification_level=level,
            verification_seed=seed,
        )
        return render(config)

    def test_verify_function_in_output(self):
        cpp = self._render(level=3)
        self.assertIn("int verify_input(char* data, int data_len)", cpp)

    def test_no_verify_when_disabled(self):
        config = ServerConfig(vuln_type=VulnType.BOF, buffer_size=512)
        cpp = render(config)
        self.assertNotIn("verify_input", cpp)

    def test_forward_declaration(self):
        cpp = self._render(level=3)
        # Forward declaration should appear before the function body
        decl_pos = cpp.find("int verify_input(char* data, int data_len);")
        body_pos = cpp.find("int verify_input(char* data, int data_len) {")
        self.assertGreater(decl_pos, -1)
        self.assertGreater(body_pos, -1)
        self.assertLess(decl_pos, body_pos)

    def test_verification_gate_tcp(self):
        cpp = self._render(level=3, protocol=Protocol.TCP)
        self.assertIn("verify_input(data, data_len)", cpp)
        self.assertIn("Access denied", cpp)

    def test_verification_gate_http(self):
        cpp = self._render(level=3, protocol=Protocol.HTTP)
        self.assertIn("verify_input(req->body, req->body_len)", cpp)
        self.assertIn("Access denied", cpp)

    def test_verification_gate_rpc(self):
        cpp = self._render(level=3, protocol=Protocol.RPC)
        self.assertIn("verify_input(payload, payload_len)", cpp)
        self.assertIn("Access denied", cpp)

    def test_vuln_function_still_present(self):
        """Verification should not replace the vuln function."""
        cpp = self._render(level=5)
        self.assertIn("vuln_function", cpp)
        self.assertIn("strcpy", cpp)

    def test_no_verify_seed_no_function(self):
        """If seed is None, no verify function should be emitted."""
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            buffer_size=512,
            verification_level=3,
            verification_seed=None,
        )
        cpp = render(config)
        # Forward decl is based on level, but function body needs seed
        self.assertNotIn("int verify_input(char* data, int data_len) {", cpp)


class TestVerificationExploit(unittest.TestCase):
    """Test exploit skeleton integration with verification."""

    def _config(self, protocol=Protocol.TCP, vuln=VulnType.BOF, level=3, seed=42):
        return ServerConfig(
            vuln_type=vuln,
            protocol=protocol,
            buffer_size=512,
            verification_level=level,
            verification_seed=seed,
            exploit=ExploitConfig(
                enabled=True,
                level=ExploitLevel.CRASH,
            ),
        )

    def test_tcp_crash_includes_header(self):
        exploit = generate_exploit(self._config(Protocol.TCP))
        self.assertIn("verify_header", exploit)
        self.assertIn("bytearray", exploit)

    def test_http_crash_includes_header(self):
        exploit = generate_exploit(self._config(Protocol.HTTP))
        self.assertIn("verify_header", exploit)

    def test_rpc_crash_includes_header(self):
        exploit = generate_exploit(self._config(Protocol.RPC))
        self.assertIn("verify_header", exploit)

    def test_no_header_when_disabled(self):
        config = ServerConfig(
            vuln_type=VulnType.BOF,
            protocol=Protocol.TCP,
            buffer_size=512,
            exploit=ExploitConfig(
                enabled=True,
                level=ExploitLevel.CRASH,
            ),
        )
        exploit = generate_exploit(config)
        self.assertNotIn("verify_header", exploit)

    def test_fmtstr_crash_includes_header(self):
        config = self._config(Protocol.TCP, VulnType.FMTSTR)
        exploit = generate_exploit(config)
        self.assertIn("verify_header", exploit)

    def test_payload_prepends_header(self):
        """The overflow payload should start with verify_header bytes."""
        exploit = generate_exploit(self._config(Protocol.TCP))
        self.assertIn("bytes(verify_header)", exploit)


class TestVerificationCLI(unittest.TestCase):
    """Test CLI argument parsing for --verification."""

    def test_parse_verification_flag(self):
        from target_builder.src.cli import parse_args

        config = parse_args(
            [
                "--vuln",
                "bof",
                "--verification",
                "5",
            ]
        )
        self.assertEqual(config.verification_level, 5)
        self.assertIsNotNone(config.verification_seed)

    def test_default_verification_zero(self):
        from target_builder.src.cli import parse_args

        config = parse_args(["--vuln", "bof"])
        self.assertEqual(config.verification_level, 0)

    def test_random_with_verification(self):
        from target_builder.src.cli import parse_args

        config = parse_args(
            [
                "--random",
                "--random-seed",
                "42",
                "--verification",
                "4",
            ]
        )
        self.assertEqual(config.verification_level, 4)
        self.assertIsNotNone(config.verification_seed)

    def test_exclude_verification(self):
        from target_builder.src.cli import parse_args

        config = parse_args(
            [
                "--random",
                "--random-seed",
                "100",
                "--exclude-protection",
                "verification",
                "--difficulty",
                "hard",
            ]
        )
        self.assertEqual(config.verification_level, 0)


if __name__ == "__main__":
    unittest.main()
