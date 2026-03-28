"""Tests for lib/completions.py — shared shell completion generator."""

import argparse
import unittest

from lib.completions import generate_completion, handle_completion, _extract_flags


def _make_parser():
    """Build a small test parser."""
    p = argparse.ArgumentParser()
    p.add_argument("-f", "--file", help="Path to file")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("--sort", choices=["name", "size"], help="Sort order")
    p.add_argument("--output", help="Output file path")
    return p


class TestExtractFlags(unittest.TestCase):
    """Test _extract_flags helper."""

    def test_extracts_long_flags(self):
        flags = _extract_flags(_make_parser())
        names = [f[0] for f in flags]
        self.assertIn("--file", names)
        self.assertIn("--verbose", names)
        self.assertIn("--sort", names)
        self.assertIn("--output", names)

    def test_boolean_detected(self):
        flags = _extract_flags(_make_parser())
        for flag, _choices, is_boolean, _help in flags:
            if flag == "--verbose":
                self.assertTrue(is_boolean)
            elif flag == "--file":
                self.assertFalse(is_boolean)

    def test_choices_extracted(self):
        flags = _extract_flags(_make_parser())
        for flag, choices, _is_boolean, _help in flags:
            if flag == "--sort":
                self.assertEqual(choices, ["name", "size"])

    def test_skips_positional(self):
        p = argparse.ArgumentParser()
        p.add_argument("input_file", help="Input file")
        p.add_argument("--verbose", action="store_true")
        flags = _extract_flags(p)
        names = [f[0] for f in flags]
        self.assertNotIn("input_file", names)
        self.assertIn("--verbose", names)


class TestBashCompletion(unittest.TestCase):
    """Test bash completion script generation."""

    def setUp(self):
        self.result = generate_completion(
            "bash", _make_parser(), ["test_tool", "test_tool.py"]
        )

    def test_function_name(self):
        self.assertIn("_test_tool_complete()", self.result)

    def test_complete_commands(self):
        self.assertIn("complete -F _test_tool_complete test_tool", self.result)
        self.assertIn("complete -F _test_tool_complete test_tool.py", self.result)

    def test_sort_choices(self):
        self.assertIn("name size", self.result)

    def test_flags_in_opts(self):
        self.assertIn("--file", self.result)
        self.assertIn("--verbose", self.result)
        self.assertIn("--sort", self.result)
        self.assertIn("--output", self.result)

    def test_file_completion_for_file_flags(self):
        self.assertIn("--file", self.result)
        self.assertIn("compgen -f", self.result)

    def test_boolean_no_case_entry(self):
        lines = self.result.split("\n")
        case_lines = [ln for ln in lines if ln.strip().startswith("--verbose)")]
        self.assertEqual(len(case_lines), 0)


class TestZshCompletion(unittest.TestCase):
    """Test zsh completion script generation."""

    def setUp(self):
        self.result = generate_completion(
            "zsh", _make_parser(), ["test_tool", "test_tool.py"]
        )

    def test_compdef(self):
        self.assertIn("#compdef test_tool test_tool.py", self.result)

    def test_function_name(self):
        self.assertIn("_test_tool()", self.result)

    def test_arguments(self):
        self.assertIn("_arguments", self.result)

    def test_sort_choices(self):
        self.assertIn("(name size)", self.result)

    def test_boolean_no_value(self):
        for line in self.result.split("\n"):
            if "'--verbose[" in line:
                self.assertNotIn(":value:", line)
                break

    def test_file_flag_completion(self):
        for line in self.result.split("\n"):
            if "'--file[" in line:
                self.assertIn("_files", line)
                break

    def test_output_flag_completion(self):
        for line in self.result.split("\n"):
            if "'--output[" in line:
                self.assertIn("_files", line)
                break


class TestToolNames(unittest.TestCase):
    """Test that tool names are parameterized correctly."""

    def test_bash_custom_names(self):
        result = generate_completion(
            "bash", _make_parser(), ["my_tool", "my_tool.py"]
        )
        self.assertIn("_my_tool_complete()", result)
        self.assertIn("complete -F _my_tool_complete my_tool", result)
        self.assertIn("complete -F _my_tool_complete my_tool.py", result)

    def test_zsh_custom_names(self):
        result = generate_completion(
            "zsh", _make_parser(), ["my_tool", "my_tool.py"]
        )
        self.assertIn("#compdef my_tool my_tool.py", result)
        self.assertIn("_my_tool()", result)


class TestErrors(unittest.TestCase):
    """Test error handling."""

    def test_invalid_shell_raises(self):
        with self.assertRaises(ValueError):
            generate_completion("fish", _make_parser(), ["test_tool"])


class TestHandleCompletion(unittest.TestCase):
    """Test handle_completion early-exit helper."""

    def test_returns_false_without_flag(self):
        result = handle_completion(
            ["-f", "foo.txt"], _make_parser, ["test_tool"]
        )
        self.assertFalse(result)

    def test_returns_true_with_bash(self):
        result = handle_completion(
            ["--generate-completion", "bash"], _make_parser, ["test_tool"]
        )
        self.assertTrue(result)

    def test_returns_true_with_zsh(self):
        result = handle_completion(
            ["--generate-completion", "zsh"], _make_parser, ["test_tool"]
        )
        self.assertTrue(result)

    def test_returns_false_without_shell_arg(self):
        result = handle_completion(
            ["--generate-completion"], _make_parser, ["test_tool"]
        )
        self.assertFalse(result)

    def test_returns_false_with_invalid_shell(self):
        result = handle_completion(
            ["--generate-completion", "fish"], _make_parser, ["test_tool"]
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
