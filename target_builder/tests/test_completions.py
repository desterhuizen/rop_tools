"""Tests for completions.py — shell completion script generation."""

import unittest

from target_builder.src.cli import build_parser
from target_builder.src.completions import generate_completion


class TestBashCompletion(unittest.TestCase):
    """Test bash completion script generation."""

    def setUp(self):
        self.parser = build_parser()
        self.result = generate_completion("bash", self.parser)

    def test_contains_function_definition(self):
        self.assertIn("_target_builder_complete()", self.result)

    def test_contains_complete_command(self):
        self.assertIn(
            "complete -F _target_builder_complete target_builder", self.result
        )

    def test_contains_cli_script_completion(self):
        self.assertIn(
            "complete -F _target_builder_complete target_builder_cli.py", self.result
        )

    def test_vuln_flag_present(self):
        """--vuln has no choices= (removed for comma-list), but flag is present."""
        self.assertIn("--vuln", self.result)

    def test_arch_choices(self):
        self.assertIn("x86 x64", self.result)

    def test_protocol_flag_present(self):
        """--protocol has no choices= (removed for comma-list), but flag is present."""
        self.assertIn("--protocol", self.result)

    def test_compiler_choices(self):
        self.assertIn("msvc mingw", self.result)

    def test_exploit_hints_choices(self):
        self.assertIn("full minimal none", self.result)

    def test_difficulty_choices(self):
        self.assertIn("easy medium hard", self.result)

    def test_all_major_flags_present(self):
        for flag in [
            "--vuln",
            "--port",
            "--arch",
            "--protocol",
            "--dep",
            "--aslr",
            "--output",
            "--exploit",
            "--compiler",
            "--exploit-hints",
            "--generate-completion",
        ]:
            self.assertIn(flag, self.result, f"{flag} missing from bash completion")

    def test_boolean_flags_no_choices(self):
        """Boolean flags like --dep should appear in opts but not in case."""
        # --dep should be in the opts string but not have a case entry
        lines = self.result.split("\n")
        case_lines = [ln for ln in lines if ln.strip().startswith("--dep)")]
        self.assertEqual(len(case_lines), 0, "--dep should not have case entry")


class TestZshCompletion(unittest.TestCase):
    """Test zsh completion script generation."""

    def setUp(self):
        self.parser = build_parser()
        self.result = generate_completion("zsh", self.parser)

    def test_contains_compdef(self):
        self.assertIn("#compdef target_builder", self.result)

    def test_contains_function(self):
        self.assertIn("_target_builder()", self.result)

    def test_contains_arguments(self):
        self.assertIn("_arguments", self.result)

    def test_vuln_flag_present(self):
        self.assertIn("--vuln", self.result)

    def test_arch_choices(self):
        self.assertIn("(x86 x64)", self.result)

    def test_compiler_choices(self):
        self.assertIn("(msvc mingw)", self.result)

    def test_exploit_hints_choices(self):
        self.assertIn("(full minimal none)", self.result)

    def test_boolean_flag_no_value(self):
        """Boolean flags should not have :value: spec."""
        # Find the --dep line
        for line in self.result.split("\n"):
            if "'--dep[" in line:
                self.assertNotIn(":value:", line)
                break

    def test_output_has_files(self):
        """--output should have _files completion."""
        for line in self.result.split("\n"):
            if "'--output[" in line:
                self.assertIn("_files", line)
                break

    def test_all_major_flags_present(self):
        for flag in [
            "--vuln",
            "--arch",
            "--protocol",
            "--compiler",
            "--exploit-hints",
        ]:
            self.assertIn(flag, self.result, f"{flag} missing from zsh completion")


class TestCompletionErrors(unittest.TestCase):
    """Test error handling in completion generation."""

    def test_invalid_shell_raises(self):
        parser = build_parser()
        with self.assertRaises(ValueError):
            generate_completion("fish", parser)


if __name__ == "__main__":
    unittest.main()
