"""
Tests for worksheet/repl/completer.py

Tests tab completion functionality for commands, registers, stack offsets,
named values, and file names.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rop.worksheet.repl.completer import WorksheetCompleter


class TestWorksheetCompleter(unittest.TestCase):
    """Test cases for WorksheetCompleter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.ws = {
            "registers": {
                "EAX": 0x12345678,
                "EBX": 0xDEADBEEF,
                "ESP": 0x0012FF00,
            },
            "stack": {
                "+0x00": 0x11111111,
                "+0x04": 0x22222222,
                "+0x08": 0x33333333,
            },
            "named": {
                "shellcode": 0x00501000,
                "kernel32": 0x77000000,
                "gadget1": 0x10001234,
            },
            "chain": [
                {"addr": 0x10001234, "gadget": "pop eax ; ret",
                 "effect": "Load value"},
                {"addr": 0x10005678, "gadget": "pop ebx ; ret",
                 "effect": "Load value"},
            ],
        }
        self.completer = WorksheetCompleter(self.ws)

    def test_initialization(self):
        """Test completer initialization."""
        self.assertEqual(self.completer.ws, self.ws)
        self.assertIn("mov", self.completer.commands)
        self.assertIn("EAX", self.completer.registers)
        self.assertIn("ESP+0x00", self.completer.common_stack_offsets)

    @patch("readline.get_line_buffer")
    def test_command_completion(self, mock_readline):
        """Test command name completion."""
        # Test 'mo' -> 'mov'
        mock_readline.return_value = "mo"
        result = self.completer.complete("mo", 0)
        self.assertEqual(result, "mov")

        # Test 'pu' -> 'push'
        mock_readline.return_value = "pu"
        result = self.completer.complete("pu", 0)
        self.assertEqual(result, "push")

        # Test 'sa' -> 'save'
        mock_readline.return_value = "sa"
        result = self.completer.complete("sa", 0)
        self.assertEqual(result, "save")

        # Test no match
        mock_readline.return_value = "xyz"
        result = self.completer.complete("xyz", 0)
        self.assertIsNone(result)

    @patch("readline.get_line_buffer")
    def test_register_completion_after_mov(self, mock_readline):
        """Test register completion after 'mov' command."""
        # Test 'mov ea' -> 'EAX'
        mock_readline.return_value = "mov ea"
        result = self.completer.complete("ea", 0)
        self.assertEqual(result, "EAX")

        # Test 'mov eb' -> 'EBX', 'EBP'
        mock_readline.return_value = "mov eb"
        result = self.completer.complete("eb", 0)
        self.assertIn(result, ["EBX", "EBP"])

        # Test 'mov e' -> multiple registers
        mock_readline.return_value = "mov e"
        result = self.completer.complete("e", 0)
        self.assertIn(
            result,
            ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]
        )

    @patch("readline.get_line_buffer")
    def test_stack_offset_completion(self, mock_readline):
        """Test stack offset completion."""
        # Test 'mov esp+0x' -> stack offsets
        mock_readline.return_value = "mov esp+0x"
        result = self.completer.complete("esp+0x", 0)
        self.assertIn(result, self.completer.common_stack_offsets)

        # Test case insensitive
        mock_readline.return_value = "mov ESP+0x"
        result = self.completer.complete("ESP+0x", 0)
        self.assertIsNotNone(result)

    @patch("readline.get_line_buffer")
    def test_named_value_completion(self, mock_readline):
        """Test named value completion from worksheet."""
        # Test 'mov shell' -> 'shellcode'
        mock_readline.return_value = "mov shell"
        result = self.completer.complete("shell", 0)
        self.assertEqual(result, "shellcode")

        # Test 'mov ker' -> 'kernel32'
        mock_readline.return_value = "mov ker"
        result = self.completer.complete("ker", 0)
        self.assertEqual(result, "kernel32")

        # Test 'mov gad' -> 'gadget1'
        mock_readline.return_value = "mov gad"
        result = self.completer.complete("gad", 0)
        self.assertEqual(result, "gadget1")

    @patch("readline.get_line_buffer")
    def test_stack_entry_completion_from_worksheet(self, mock_readline):
        """Test stack entry completion from worksheet stack."""
        # Test 'mov ESP+0x00' -> should complete from worksheet stack
        mock_readline.return_value = "mov esp+0x00"
        result = self.completer.complete("esp+0x00", 0)
        # Should match common stack offset
        self.assertIsNotNone(result)

    @patch("readline.get_line_buffer")
    def test_chain_index_completion_after_del(self, mock_readline):
        """Test chain index completion after 'del' command."""
        # Test 'del 1' -> should complete with chain indices
        mock_readline.return_value = "del 1"
        result = self.completer.complete("1", 0)
        self.assertEqual(result, "1")

        # Test 'del 2'
        mock_readline.return_value = "del 2"
        result = self.completer.complete("2", 0)
        self.assertEqual(result, "2")

        # Test 'del 3' -> should return None (only 2 entries in chain)
        mock_readline.return_value = "del 3"
        result = self.completer.complete("3", 0)
        self.assertIsNone(result)

    @patch("readline.get_line_buffer")
    @patch("os.listdir")
    def test_file_completion_after_save(self, mock_listdir, mock_readline):
        """Test file completion after 'save' command."""
        # Mock JSON files in directory
        mock_listdir.return_value = [
            "rop.json",
            "test.json",
            "backup.json",
            "other.txt",
        ]

        # Test 'save rop' -> 'rop.json'
        mock_readline.return_value = "save rop"
        result = self.completer.complete("rop", 0)
        self.assertEqual(result, "rop.json")

        # Test 'save test' -> 'test.json'
        mock_readline.return_value = "save test"
        result = self.completer.complete("test", 0)
        self.assertEqual(result, "test.json")

        # Test 'save ' -> should list all JSON files
        mock_readline.return_value = "save "
        result = self.completer.complete("", 0)
        self.assertIn(result, ["rop.json", "test.json", "backup.json"])
        # Should NOT include non-JSON files
        self.assertNotEqual(result, "other.txt")

    @patch("readline.get_line_buffer")
    @patch("os.listdir")
    def test_file_completion_after_load(self, mock_listdir, mock_readline):
        """Test file completion after 'load' command."""
        mock_listdir.return_value = ["rop.json", "test.json"]

        # Test 'load rop' -> 'rop.json'
        mock_readline.return_value = "load rop"
        result = self.completer.complete("rop", 0)
        self.assertEqual(result, "rop.json")

    @patch("readline.get_line_buffer")
    @patch("os.listdir")
    def test_file_completion_error_handling(self, mock_listdir, mock_readline):
        """Test file completion handles errors gracefully."""
        # Simulate directory access error
        mock_listdir.side_effect = OSError("Permission denied")

        mock_readline.return_value = "save test"
        result = self.completer.complete("test", 0)
        self.assertIsNone(result)

    @patch("readline.get_line_buffer")
    def test_completion_with_multiple_states(self, mock_readline):
        """Test completion with multiple candidates."""
        # Test 'mov e' -> should have multiple matches
        mock_readline.return_value = "mov e"

        # Get first candidate (state=0)
        result0 = self.completer.complete("e", 0)
        self.assertIsNotNone(result0)

        # Get second candidate (state=1)
        result1 = self.completer.complete("e", 1)
        self.assertIsNotNone(result1)

        # Results should be different
        self.assertNotEqual(result0, result1)

        # Both should start with 'E'
        self.assertTrue(result0.startswith("E"))
        self.assertTrue(result1.startswith("E"))

    @patch("readline.get_line_buffer")
    def test_completion_for_xchg_command(self, mock_readline):
        """Test completion works for xchg command."""
        mock_readline.return_value = "xchg ea"
        result = self.completer.complete("ea", 0)
        self.assertEqual(result, "EAX")

    @patch("readline.get_line_buffer")
    def test_completion_for_set_command(self, mock_readline):
        """Test completion works for set command."""
        mock_readline.return_value = "set ea"
        result = self.completer.complete("ea", 0)
        self.assertEqual(result, "EAX")

    @patch("readline.get_line_buffer")
    def test_completion_for_clr_command(self, mock_readline):
        """Test completion works for clr command."""
        mock_readline.return_value = "clr ea"
        result = self.completer.complete("ea", 0)
        self.assertEqual(result, "EAX")

    @patch("readline.get_line_buffer")
    def test_completion_for_stack_command(self, mock_readline):
        """Test completion works for stack command."""
        mock_readline.return_value = "stack ea"
        result = self.completer.complete("ea", 0)
        self.assertEqual(result, "EAX")

    @patch("readline.get_line_buffer")
    def test_no_completion_for_unknown_context(self, mock_readline):
        """Test no completion for unknown contexts."""
        # Test after 'help' command (no special completion)
        mock_readline.return_value = "help something"
        result = self.completer.complete("something", 0)
        self.assertIsNone(result)

    @patch("readline.get_line_buffer")
    def test_empty_worksheet_named_values(self, mock_readline):
        """Test completion with empty named values."""
        # Create completer with empty named values
        ws_empty = self.ws.copy()
        ws_empty["named"] = {}
        completer = WorksheetCompleter(ws_empty)

        # Should still complete registers
        mock_readline.return_value = "mov ea"
        result = completer.complete("ea", 0)
        self.assertEqual(result, "EAX")

    @patch("readline.get_line_buffer")
    def test_empty_chain(self, mock_readline):
        """Test completion with empty chain."""
        # Create completer with empty chain
        ws_empty = self.ws.copy()
        ws_empty["chain"] = []
        completer = WorksheetCompleter(ws_empty)

        # Test 'del ' with no chain entries
        mock_readline.return_value = "del 1"
        result = completer.complete("1", 0)
        self.assertIsNone(result)

    @patch("readline.get_line_buffer")
    def test_case_insensitive_command_completion(self, mock_readline):
        """Test case insensitive command completion."""
        # Test 'MO' -> 'mov'
        mock_readline.return_value = "MO"
        result = self.completer.complete("MO", 0)
        self.assertEqual(result, "mov")

        # Test 'PU' -> 'push'
        mock_readline.return_value = "PU"
        result = self.completer.complete("PU", 0)
        self.assertEqual(result, "push")


if __name__ == "__main__":
    unittest.main()
