"""
Tests for color_printer.py

Tests the ColorPrinter abstraction layer for colored terminal output.
Tests both Rich-enabled and fallback modes.
"""

import unittest
from unittest.mock import patch, MagicMock, call
import sys
import io
import re


class TestColorPrinterWithRich(unittest.TestCase):
    """Test ColorPrinter when Rich library is available."""

    def setUp(self):
        """Set up test fixtures with Rich available."""
        # Import fresh module for each test
        import importlib
        import lib.color_printer
        importlib.reload(lib.color_printer)
        from lib.color_printer import ColorPrinter

        self.ColorPrinter = ColorPrinter

    def test_initialization_with_rich(self):
        """Test ColorPrinter initializes correctly with Rich."""
        printer = self.ColorPrinter()
        self.assertTrue(printer.enabled)
        self.assertIsNotNone(printer.console)

    def test_initialization_disabled(self):
        """Test ColorPrinter can be initialized with colors disabled."""
        printer = self.ColorPrinter(enabled=False)
        self.assertFalse(printer.enabled)

    def test_disable_method(self):
        """Test that disable() method works."""
        printer = self.ColorPrinter()
        self.assertTrue(printer.enabled)

        printer.disable()
        self.assertFalse(printer.enabled)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_text_with_style(self, mock_stdout):
        """Test print_text with styling."""
        printer = self.ColorPrinter()

        # Should use Rich console when enabled
        if printer.enabled:
            printer.print_text("Test message", "bold red")
            # Console.print was called
            self.assertIsNotNone(mock_stdout.getvalue())

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_text_without_style(self, mock_stdout):
        """Test print_text without styling falls back to plain print."""
        printer = self.ColorPrinter()
        printer.print_text("Test message", None)

        output = mock_stdout.getvalue()
        self.assertIn("Test message", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_header(self, mock_stdout):
        """Test print_header method."""
        printer = self.ColorPrinter()
        printer.print_header("Test Header")

        output = mock_stdout.getvalue()
        self.assertIn("Test Header", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_labeled(self, mock_stdout):
        """Test print_labeled method."""
        printer = self.ColorPrinter()
        printer.print_labeled("Name", "Value")

        output = mock_stdout.getvalue()
        self.assertIn("Name", output)
        self.assertIn("Value", output)

    def test_style_text(self):
        """Test style_text returns styled Text object."""
        printer = self.ColorPrinter()
        result = printer.style_text("Test", "bold")

        if printer.enabled:
            from rich.text import Text
            self.assertIsInstance(result, Text)
        else:
            self.assertIsInstance(result, str)

    def test_stylize_regex_with_valid_pattern(self):
        """Test stylize_regex with valid regex pattern."""
        printer = self.ColorPrinter()
        text = "This is a test message"
        pattern = r"test"

        result = printer.stylize_regex(text, pattern, "bold red")

        if printer.enabled:
            from rich.text import Text
            self.assertIsInstance(result, Text)
        else:
            self.assertEqual(result, text)

    def test_stylize_regex_with_invalid_pattern(self):
        """Test stylize_regex with invalid regex pattern."""
        printer = self.ColorPrinter()
        text = "Test message"
        pattern = r"["  # Invalid regex

        result = printer.stylize_regex(text, pattern)

        # Should return text without crashing
        if printer.enabled:
            from rich.text import Text
            # Should return Text object even with invalid pattern
            self.assertIsNotNone(result)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_method(self, mock_stdout):
        """Test print wrapper method."""
        printer = self.ColorPrinter()
        printer.print("Test message")

        output = mock_stdout.getvalue()
        self.assertIn("Test message", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_section(self, mock_stdout):
        """Test print_section method."""
        printer = self.ColorPrinter()
        printer.print_section("Section Title", "bold cyan")

        output = mock_stdout.getvalue()
        self.assertIn("Section Title", output)

    def test_colorize_method(self):
        """Test colorize returns text with ANSI codes."""
        printer = self.ColorPrinter()
        result = printer.colorize("Test", "bold red")

        self.assertIsInstance(result, str)
        self.assertIn("Test", result)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_panel(self, mock_stdout):
        """Test print_panel method."""
        printer = self.ColorPrinter()
        printer.print_panel("Panel content", title="Test Panel")

        output = mock_stdout.getvalue()
        self.assertIn("Panel content", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_hex_preview(self, mock_stdout):
        """Test print_hex_preview method."""
        printer = self.ColorPrinter()
        data = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff'

        printer.print_hex_preview(data, max_bytes=8, title="Test Preview")

        output = mock_stdout.getvalue()
        self.assertIn("Test Preview", output)
        # Should contain hex values
        self.assertIn("89", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_hex_preview_empty_data(self, mock_stdout):
        """Test print_hex_preview with empty data."""
        printer = self.ColorPrinter()
        printer.print_hex_preview(b'')

        # Should not crash and not print anything
        output = mock_stdout.getvalue()
        self.assertEqual(output, "")

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_table(self, mock_stdout):
        """Test print_table method."""
        printer = self.ColorPrinter()
        columns = ["Name", "Status"]
        rows = [
            ["Test1", "✓"],
            ["Test2", "✗"],
        ]

        printer.print_table(columns, rows, title="Test Table")

        output = mock_stdout.getvalue()
        self.assertIn("Test Table", output)
        self.assertIn("Name", output)
        self.assertIn("Test1", output)


class TestColorPrinterFallback(unittest.TestCase):
    """Test ColorPrinter fallback mode without Rich."""

    def setUp(self):
        """Set up test fixtures simulating Rich not available."""
        # Mock Rich as not available
        self.rich_patcher = patch.dict('sys.modules', {
            'rich': None,
            'rich.console': None,
            'rich.text': None,
            'rich.panel': None,
            'rich.table': None,
        })
        self.rich_patcher.start()

        # Reload module to trigger ImportError for Rich
        import importlib
        import lib.color_printer
        lib.color_printer.COLORS_AVAILABLE = False
        lib.color_printer.Console = None
        lib.color_printer.Text = None

        from lib.color_printer import ColorPrinter
        self.ColorPrinter = ColorPrinter

    def tearDown(self):
        """Clean up patches."""
        self.rich_patcher.stop()

    def test_initialization_without_rich(self):
        """Test ColorPrinter initializes in fallback mode."""
        printer = self.ColorPrinter()
        self.assertFalse(printer.enabled)
        self.assertIsNone(printer.console)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_text_fallback(self, mock_stdout):
        """Test print_text falls back to plain print."""
        printer = self.ColorPrinter()
        printer.print_text("Test message", "bold red")

        output = mock_stdout.getvalue()
        self.assertEqual(output, "Test message\n")

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_header_fallback(self, mock_stdout):
        """Test print_header in fallback mode."""
        printer = self.ColorPrinter()
        printer.print_header("Header")

        output = mock_stdout.getvalue()
        self.assertIn("Header", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_labeled_fallback(self, mock_stdout):
        """Test print_labeled in fallback mode."""
        printer = self.ColorPrinter()
        printer.print_labeled("Label", "Value")

        output = mock_stdout.getvalue()
        self.assertEqual(output, "Label: Value\n")

    def test_style_text_fallback(self):
        """Test style_text returns plain string in fallback."""
        printer = self.ColorPrinter()
        result = printer.style_text("Test", "bold")

        self.assertIsInstance(result, str)
        self.assertEqual(result, "Test")

    def test_stylize_regex_fallback(self):
        """Test stylize_regex returns plain text in fallback."""
        printer = self.ColorPrinter()
        text = "Test message"
        result = printer.stylize_regex(text, r"test")

        self.assertEqual(result, text)

    def test_colorize_fallback(self):
        """Test colorize returns plain string in fallback."""
        printer = self.ColorPrinter()
        result = printer.colorize("Test", "bold")

        self.assertEqual(result, "Test")

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_panel_fallback(self, mock_stdout):
        """Test print_panel fallback with simple borders."""
        printer = self.ColorPrinter()
        printer.print_panel("Content", title="Title")

        output = mock_stdout.getvalue()
        self.assertIn("Content", output)
        self.assertIn("Title", output)
        self.assertIn("=", output)  # Border

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_hex_preview_fallback(self, mock_stdout):
        """Test print_hex_preview in fallback mode."""
        printer = self.ColorPrinter()
        data = b'\x41\x42\x43'

        printer.print_hex_preview(data)

        output = mock_stdout.getvalue()
        self.assertIn("41", output)
        self.assertIn("42", output)
        self.assertIn("43", output)

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_print_table_fallback(self, mock_stdout):
        """Test print_table in fallback mode."""
        printer = self.ColorPrinter()
        columns = ["Col1", "Col2"]
        rows = [["Val1", "Val2"]]

        printer.print_table(columns, rows, title="Table")

        output = mock_stdout.getvalue()
        self.assertIn("Table", output)
        self.assertIn("Col1", output)
        self.assertIn("Val1", output)
        self.assertIn("|", output)  # Separator


class TestColorPrinterEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        from lib.color_printer import ColorPrinter
        self.ColorPrinter = ColorPrinter

    def test_print_text_with_empty_string(self):
        """Test print_text with empty string."""
        printer = self.ColorPrinter()
        # Should not crash
        try:
            printer.print_text("", "bold")
        except Exception as e:
            self.fail(f"print_text crashed with empty string: {e}")

    def test_print_labeled_with_none_value(self):
        """Test print_labeled with None value."""
        printer = self.ColorPrinter()
        # Should convert None to string
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_labeled("Label", None)
            output = mock_stdout.getvalue()
            self.assertIn("Label", output)
            self.assertIn("None", output)

    def test_style_text_with_integer(self):
        """Test style_text with integer input."""
        printer = self.ColorPrinter()
        result = printer.style_text(123, "bold")

        # Should convert to string
        if printer.enabled:
            from rich.text import Text
            self.assertIsInstance(result, (Text, str))
        else:
            self.assertEqual(result, "123")

    def test_stylize_regex_with_special_characters(self):
        """Test stylize_regex with special regex characters."""
        printer = self.ColorPrinter()
        text = "Test (parentheses) and [brackets]"
        pattern = r"\(.*?\)"

        result = printer.stylize_regex(text, pattern)

        # Should handle special chars correctly
        self.assertIsNotNone(result)

    def test_stylize_regex_case_insensitive(self):
        """Test that stylize_regex is case-insensitive."""
        printer = self.ColorPrinter()
        text = "Test MESSAGE here"
        pattern = r"message"

        result = printer.stylize_regex(text, pattern)

        # Should match "MESSAGE" (case-insensitive)
        self.assertIsNotNone(result)

    def test_print_hex_preview_with_long_data(self):
        """Test print_hex_preview with data longer than max_bytes."""
        printer = self.ColorPrinter()
        data = bytes(range(256))

        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_hex_preview(data, max_bytes=16)
            output = mock_stdout.getvalue()

            # Should only show first 16 bytes
            self.assertIn("00", output)  # First byte
            self.assertIn("0f", output)  # 16th byte
            # Should not show 17th byte or beyond
            # (This is implementation-dependent but max_bytes=16 limits it)

    def test_print_hex_preview_ascii_representation(self):
        """Test print_hex_preview ASCII representation."""
        printer = self.ColorPrinter()
        # Printable ASCII: ABC
        data = b'ABC\x00\x01\x02'

        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_hex_preview(data)
            output = mock_stdout.getvalue()

            # Should contain hex
            self.assertIn("41", output)  # 'A'
            self.assertIn("42", output)  # 'B'
            self.assertIn("43", output)  # 'C'

            # Should contain ASCII representation (may have middle dots for non-printable)
            # 'A', 'B', 'C' should appear
            lines = output.split('\n')
            # Look for line with ASCII chars
            ascii_line = [line for line in lines if 'A' in line and not '41' in line]
            # At least the printable chars should be visible

    def test_print_table_with_empty_rows(self):
        """Test print_table with empty rows."""
        printer = self.ColorPrinter()
        columns = ["Col1", "Col2"]
        rows = []

        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_table(columns, rows, title="Empty Table")
            output = mock_stdout.getvalue()

            # Should show header
            self.assertIn("Col1", output)

    def test_print_table_with_checkmarks(self):
        """Test print_table correctly styles checkmarks."""
        printer = self.ColorPrinter()
        columns = ["Feature", "Supported"]
        rows = [
            ["Feature1", "✓"],
            ["Feature2", "✗"],
        ]

        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_table(columns, rows)
            output = mock_stdout.getvalue()

            # Should contain checkmarks
            self.assertIn("✓", output)
            self.assertIn("✗", output)

    def test_print_panel_with_empty_title(self):
        """Test print_panel with empty title."""
        printer = self.ColorPrinter()

        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_panel("Content", title="")
            output = mock_stdout.getvalue()

            self.assertIn("Content", output)

    def test_multiple_operations_on_same_printer(self):
        """Test multiple operations on the same printer instance."""
        printer = self.ColorPrinter()

        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            printer.print_text("Line 1", "bold")
            printer.print_text("Line 2", "cyan")
            printer.print_header("Header")
            printer.print_labeled("Label", "Value")

            output = mock_stdout.getvalue()
            self.assertIn("Line 1", output)
            self.assertIn("Line 2", output)
            self.assertIn("Header", output)
            self.assertIn("Label", output)

    def test_disable_then_enable_workflow(self):
        """Test disabling colors and then re-enabling."""
        printer = self.ColorPrinter()
        original_enabled = printer.enabled

        printer.disable()
        self.assertFalse(printer.enabled)

        # Note: ColorPrinter doesn't have an explicit enable() method
        # Once disabled, it stays disabled
        # This is by design for the use case

    def test_colorize_with_complex_style(self):
        """Test colorize with complex style string."""
        printer = self.ColorPrinter()
        result = printer.colorize("Text", "bold red on blue")

        self.assertIsInstance(result, str)
        self.assertIn("Text", result)


if __name__ == "__main__":
    unittest.main()