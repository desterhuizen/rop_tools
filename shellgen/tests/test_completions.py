"""Tests for shell completion in shellgen tools."""

import sys
import unittest
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from lib.completions import generate_completion  # noqa: E402


def _shellgen_parser():
    """Build shellgen parser (import deferred to avoid heavy deps)."""
    sys.path.insert(0, str(REPO_ROOT / "shellgen"))
    from src.cli import create_parser

    return create_parser()


def _hash_parser():
    """Build hash_generator parser."""
    sys.path.insert(0, str(REPO_ROOT / "shellgen"))
    from hash_generator import create_parser

    return create_parser()


# ── shellgen bash ──────────────────────────────────────────────────────


class TestShellgenBashCompletion(unittest.TestCase):
    """Test bash completion for shellgen."""

    def setUp(self):
        self.result = generate_completion(
            "bash", _shellgen_parser(), ["shellgen", "shellgen_cli.py"]
        )

    def test_function_name(self):
        self.assertIn("_shellgen_complete()", self.result)

    def test_complete_commands(self):
        self.assertIn("complete -F _shellgen_complete shellgen", self.result)
        self.assertIn("complete -F _shellgen_complete shellgen_cli.py", self.result)

    def test_platform_choices(self):
        self.assertIn("windows linux", self.result)

    def test_arch_choices(self):
        self.assertIn("x86 x64 arm arm64", self.result)

    def test_format_choices(self):
        self.assertIn("asm python c raw pyasm", self.result)

    def test_major_flags_present(self):
        for flag in [
            "--platform",
            "--payload",
            "--arch",
            "--bad-chars",
            "--format",
            "--verify",
            "--debug-shellcode",
            "--no-exit",
            "--output",
            "--host",
            "--port",
        ]:
            self.assertIn(flag, self.result)

    def test_file_completion(self):
        self.assertIn("compgen -f", self.result)

    def test_boolean_no_case_entry(self):
        lines = self.result.split("\n")
        case_lines = [ln for ln in lines if ln.strip().startswith("--verify)")]
        self.assertEqual(len(case_lines), 0)


# ── shellgen zsh ───────────────────────────────────────────────────────


class TestShellgenZshCompletion(unittest.TestCase):
    """Test zsh completion for shellgen."""

    def setUp(self):
        self.result = generate_completion(
            "zsh", _shellgen_parser(), ["shellgen", "shellgen_cli.py"]
        )

    def test_compdef(self):
        self.assertIn("#compdef shellgen shellgen_cli.py", self.result)

    def test_function_name(self):
        self.assertIn("_shellgen()", self.result)

    def test_arguments(self):
        self.assertIn("_arguments", self.result)

    def test_platform_choices(self):
        self.assertIn("(windows linux)", self.result)

    def test_file_flag_completion(self):
        for line in self.result.split("\n"):
            if "'--output[" in line:
                self.assertIn("_files", line)
                break


# ── hash_generator bash ────────────────────────────────────────────────


class TestHashBashCompletion(unittest.TestCase):
    """Test bash completion for hash_generator."""

    def setUp(self):
        self.result = generate_completion(
            "bash", _hash_parser(), ["hash_generator", "hash_generator.py"]
        )

    def test_function_name(self):
        self.assertIn("_hash_generator_complete()", self.result)

    def test_complete_commands(self):
        self.assertIn(
            "complete -F _hash_generator_complete hash_generator", self.result
        )
        self.assertIn(
            "complete -F _hash_generator_complete hash_generator.py", self.result
        )

    def test_format_choices(self):
        self.assertIn("text python c asm json", self.result)

    def test_major_flags_present(self):
        for flag in ["--file", "--format", "--case-insensitive", "--verify"]:
            self.assertIn(flag, self.result)

    def test_boolean_no_case_entry(self):
        lines = self.result.split("\n")
        case_lines = [
            ln for ln in lines if ln.strip().startswith("--case-insensitive)")
        ]
        self.assertEqual(len(case_lines), 0)


# ── hash_generator zsh ─────────────────────────────────────────────────


class TestHashZshCompletion(unittest.TestCase):
    """Test zsh completion for hash_generator."""

    def setUp(self):
        self.result = generate_completion(
            "zsh", _hash_parser(), ["hash_generator", "hash_generator.py"]
        )

    def test_compdef(self):
        self.assertIn("#compdef hash_generator hash_generator.py", self.result)

    def test_function_name(self):
        self.assertIn("_hash_generator()", self.result)

    def test_format_choices(self):
        self.assertIn("(text python c asm json)", self.result)

    def test_boolean_no_value(self):
        for line in self.result.split("\n"):
            if "'--case-insensitive[" in line:
                self.assertNotIn(":value:", line)
                break


if __name__ == "__main__":
    unittest.main()
