"""Tests for shell completion generation in rop tools."""

import unittest

from lib.completions import generate_completion
from rop.get_base_address import _build_parser as build_base_parser
from rop.get_rop_gadgets import build_arg_parser as build_gadgets_parser


class TestGadgetsBashCompletion(unittest.TestCase):
    """Test bash completion for get_rop_gadgets."""

    def setUp(self):
        self.parser = build_gadgets_parser()
        self.result = generate_completion(
            "bash", self.parser, ["get_rop_gadgets", "get_rop_gadgets.py"]
        )

    def test_function_name(self):
        self.assertIn("_get_rop_gadgets_complete()", self.result)

    def test_complete_commands(self):
        self.assertIn(
            "complete -F _get_rop_gadgets_complete get_rop_gadgets", self.result
        )
        self.assertIn(
            "complete -F _get_rop_gadgets_complete get_rop_gadgets.py", self.result
        )

    def test_position_choices(self):
        self.assertIn("any first last", self.result)

    def test_group_choices(self):
        self.assertIn("category-register", self.result)

    def test_sort_choices(self):
        self.assertIn("count address", self.result)

    def test_all_major_flags(self):
        for flag in [
            "--file",
            "--instruction",
            "--position",
            "--bad-chars",
            "--max-instructions",
            "--group",
            "--category",
            "--regex",
            "--exclude",
            "--register",
            "--modified-only",
            "--deref",
            "--limit",
            "--stats",
            "--show-category",
            "--show-count",
            "--highlight",
            "--no-color",
            "--sort",
            "--offset",
            "--keep-bad-instructions",
        ]:
            self.assertIn(flag, self.result, f"{flag} missing from bash completion")

    def test_file_flag_completion(self):
        self.assertIn("compgen -f", self.result)

    def test_boolean_flags_no_case(self):
        lines = self.result.split("\n")
        for bool_flag in ["--stats", "--modified-only", "--highlight"]:
            case_lines = [ln for ln in lines if ln.strip().startswith(f"{bool_flag})")]
            self.assertEqual(
                len(case_lines), 0, f"{bool_flag} should not have case entry"
            )


class TestGadgetsZshCompletion(unittest.TestCase):
    """Test zsh completion for get_rop_gadgets."""

    def setUp(self):
        self.parser = build_gadgets_parser()
        self.result = generate_completion(
            "zsh", self.parser, ["get_rop_gadgets", "get_rop_gadgets.py"]
        )

    def test_compdef(self):
        self.assertIn("#compdef get_rop_gadgets get_rop_gadgets.py", self.result)

    def test_function_name(self):
        self.assertIn("_get_rop_gadgets()", self.result)

    def test_position_choices(self):
        self.assertIn("(any first last)", self.result)

    def test_sort_choices(self):
        self.assertIn("(count address)", self.result)

    def test_file_flag_has_files(self):
        for line in self.result.split("\n"):
            if "'--file[" in line:
                self.assertIn("_files", line)
                break


class TestBaseAddressBashCompletion(unittest.TestCase):
    """Test bash completion for get_base_address."""

    def setUp(self):
        self.parser = build_base_parser()
        self.result = generate_completion(
            "bash", self.parser, ["get_base_address", "get_base_address.py"]
        )

    def test_function_name(self):
        self.assertIn("_get_base_address_complete()", self.result)

    def test_complete_commands(self):
        self.assertIn(
            "complete -F _get_base_address_complete get_base_address", self.result
        )
        self.assertIn(
            "complete -F _get_base_address_complete get_base_address.py", self.result
        )

    def test_all_flags(self):
        for flag in ["--verbose", "--no-color", "--quiet", "--iat", "--dll"]:
            self.assertIn(flag, self.result, f"{flag} missing from bash completion")

    def test_boolean_flags_no_case(self):
        lines = self.result.split("\n")
        for bool_flag in ["--verbose", "--quiet", "--iat", "--no-color"]:
            case_lines = [ln for ln in lines if ln.strip().startswith(f"{bool_flag})")]
            self.assertEqual(
                len(case_lines), 0, f"{bool_flag} should not have case entry"
            )


class TestBaseAddressZshCompletion(unittest.TestCase):
    """Test zsh completion for get_base_address."""

    def setUp(self):
        self.parser = build_base_parser()
        self.result = generate_completion(
            "zsh", self.parser, ["get_base_address", "get_base_address.py"]
        )

    def test_compdef(self):
        self.assertIn("#compdef get_base_address get_base_address.py", self.result)

    def test_function_name(self):
        self.assertIn("_get_base_address()", self.result)

    def test_boolean_verbose_no_value(self):
        for line in self.result.split("\n"):
            if "'--verbose[" in line:
                self.assertNotIn(":value:", line)
                break

    def test_completion_choices(self):
        self.assertIn("(bash zsh)", self.result)


if __name__ == "__main__":
    unittest.main()
