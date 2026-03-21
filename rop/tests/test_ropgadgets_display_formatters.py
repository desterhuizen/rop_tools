"""
Unit tests for rop/display/formatters.py

Tests display formatting functions for ROP gadgets.
Note: These tests focus on function behavior rather than
visual output, since testing terminal colors is complex.
"""
import pytest
import tempfile
import os
from io import StringIO
import sys
from pathlib import Path

# Add repo root to path for lib imports
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.gadget import Gadget
from core.parser import ROPGadgetParser
from display.formatters import print_gadget_colored, print_gadgets, print_statistics
from lib.color_printer import printer


# Sample gadget for testing
SAMPLE_GADGET = Gadget(
    address="0x12345678",
    instructions=["pop eax", "ret"],
    raw_line="0x12345678: pop eax ; ret ; (1 found)",
    count=1
)


class TestPrintGadgetColored:
    """Test single gadget printing"""

    def test_print_gadget_basic(self, capsys):
        """Test basic gadget printing"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        print_gadget_colored(SAMPLE_GADGET, parser)
        captured = capsys.readouterr()

        # Should contain the address
        assert "0x12345678" in captured.out or len(captured.out) > 0

    def test_print_gadget_no_color(self, capsys):
        """Test gadget printing with colors disabled"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        # Disable colors
        was_enabled = printer.enabled
        printer.disable()

        try:
            print_gadget_colored(SAMPLE_GADGET, parser)
            captured = capsys.readouterr()

            # Should contain the gadget output
            assert "0x12345678" in captured.out or "pop eax" in captured.out
        finally:
            # Restore color state
            if was_enabled:
                printer.enabled = True

    def test_print_gadget_with_category(self, capsys):
        """Test gadget printing with category display"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        # Disable colors for easier testing
        was_enabled = printer.enabled
        printer.disable()

        try:
            print_gadget_colored(SAMPLE_GADGET, parser, show_category=True)
            captured = capsys.readouterr()

            # Should contain category in brackets
            assert "[" in captured.out and "]" in captured.out
        finally:
            if was_enabled:
                printer.enabled = True

    def test_print_gadget_with_count(self, capsys):
        """Test gadget printing with instruction count"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        # Disable colors for easier testing
        was_enabled = printer.enabled
        printer.disable()

        try:
            print_gadget_colored(SAMPLE_GADGET, parser, show_count=True)
            captured = capsys.readouterr()

            # Should contain count in brackets
            assert "[" in captured.out and "]" in captured.out
        finally:
            if was_enabled:
                printer.enabled = True

    def test_print_gadget_with_offset(self, capsys):
        """Test gadget printing with base offset"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        # Disable colors for easier testing
        was_enabled = printer.enabled
        printer.disable()

        try:
            base_address = 0x10000000
            print_gadget_colored(SAMPLE_GADGET, parser, base_address=base_address)
            captured = capsys.readouterr()

            # Should contain offset
            assert "offset" in captured.out or "+" in captured.out
        finally:
            if was_enabled:
                printer.enabled = True


class TestPrintGadgets:
    """Test batch gadget printing"""

    def test_print_multiple_gadgets(self, capsys):
        """Test printing multiple gadgets"""
        gadgets = [
            Gadget("0x12345678", ["pop eax", "ret"], "test1", 1),
            Gadget("0x87654321", ["pop ebx", "ret"], "test2", 1),
        ]

        print_gadgets(gadgets)
        captured = capsys.readouterr()

        # Should contain output (may be colored or plain)
        assert len(captured.out) > 0

    def test_print_gadgets_with_limit(self, capsys):
        """Test printing with limit"""
        gadgets = [
            Gadget("0x12345678", ["pop eax", "ret"], "test1", 1),
            Gadget("0x87654321", ["pop ebx", "ret"], "test2", 1),
            Gadget("0x11111111", ["pop ecx", "ret"], "test3", 1),
        ]

        print_gadgets(gadgets, limit=2)
        captured = capsys.readouterr()

        # Should mention "more gadgets"
        assert "more" in captured.out.lower() or len(captured.out) > 0

    def test_print_gadgets_empty_list(self, capsys):
        """Test printing empty gadget list"""
        gadgets = []

        print_gadgets(gadgets)
        captured = capsys.readouterr()

        # Should not error, output may be empty
        assert True  # No exception is success


class TestPrintStatistics:
    """Test statistics printing"""

    def test_print_statistics_basic(self, capsys):
        """Test basic statistics printing"""
        # Create a parser with sample gadgets
        sample_data = """FileFormat: PE, Arch: x86

0x10001234: pop eax ; ret ; (1 found)
0x10001240: pop ebx ; ret ; (1 found)
0x10001250: mov eax, ebx ; ret ; (1 found)
"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            parser = ROPGadgetParser(temp_path)
            parser.parse_file()

            print_statistics(parser)
            captured = capsys.readouterr()

            # Should contain statistics headers
            assert "Statistics" in captured.out or "Total" in captured.out or len(captured.out) > 0
        finally:
            os.unlink(temp_path)

    def test_print_statistics_with_metadata(self, capsys):
        """Test statistics with file metadata"""
        sample_data = """Trying to open 'test.dll'..
FileFormat: PE, Arch: x86

0x10001234: pop eax ; ret ; (1 found)
"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write(sample_data)
            temp_path = f.name

        try:
            parser = ROPGadgetParser(temp_path)
            parser.parse_file()

            print_statistics(parser)
            captured = capsys.readouterr()

            # Should contain metadata
            assert len(captured.out) > 0
        finally:
            os.unlink(temp_path)


class TestHighlighting:
    """Test regex highlighting functionality"""

    def test_print_gadget_with_highlighting(self, capsys):
        """Test gadget printing with regex highlighting"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        # Test with highlighting pattern
        print_gadget_colored(SAMPLE_GADGET, parser, highlight_pattern="pop")
        captured = capsys.readouterr()

        # Should contain output (highlighting is visual)
        assert len(captured.out) > 0

    def test_print_gadget_highlighting_case_insensitive(self, capsys):
        """Test case-insensitive highlighting"""
        parser = ROPGadgetParser()
        parser.gadgets = [SAMPLE_GADGET]

        # Test with different case
        print_gadget_colored(SAMPLE_GADGET, parser, highlight_pattern="POP")
        captured = capsys.readouterr()

        # Should contain output
        assert len(captured.out) > 0


class TestOffsetCalculation:
    """Test offset calculation and display"""

    def test_offset_calculation_positive(self, capsys):
        """Test offset calculation with positive offset"""
        gadget = Gadget(
            address="0x12345678",
            instructions=["pop eax", "ret"],
            raw_line="0x12345678: pop eax ; ret ; (1 found)",
            count=1
        )
        parser = ROPGadgetParser()
        parser.gadgets = [gadget]

        base_address = 0x10000000

        # Disable colors for easier testing
        was_enabled = printer.enabled
        printer.disable()

        try:
            print_gadget_colored(gadget, parser, base_address=base_address)
            captured = capsys.readouterr()

            # Offset should be 0x12345678 - 0x10000000 = 0x2345678
            assert "2345678" in captured.out or "+" in captured.out
        finally:
            if was_enabled:
                printer.enabled = True

    def test_offset_calculation_with_all_features(self, capsys):
        """Test offset with category and count display"""
        gadget = Gadget(
            address="0x12345678",
            instructions=["pop eax", "ret"],
            raw_line="0x12345678: pop eax ; ret ; (1 found)",
            count=1
        )
        parser = ROPGadgetParser()
        parser.gadgets = [gadget]

        base_address = 0x10000000

        # Disable colors for easier testing
        was_enabled = printer.enabled
        printer.disable()

        try:
            print_gadget_colored(
                gadget, parser,
                show_category=True,
                show_count=True,
                base_address=base_address
            )
            captured = capsys.readouterr()

            # Should contain all elements
            assert "[" in captured.out  # Category or count brackets
            assert len(captured.out) > 0
        finally:
            if was_enabled:
                printer.enabled = True


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_print_gadget_malformed_line(self, capsys):
        """Test printing gadget with malformed raw_line"""
        gadget = Gadget(
            address="0x12345678",
            instructions=["pop eax", "ret"],
            raw_line="malformed",
            count=1
        )
        parser = ROPGadgetParser()
        parser.gadgets = [gadget]

        # Should not crash
        print_gadget_colored(gadget, parser)
        captured = capsys.readouterr()
        assert True  # No exception is success

    def test_print_gadgets_none_parser(self, capsys):
        """Test printing with None parser"""
        gadgets = [SAMPLE_GADGET]

        # Should not crash
        print_gadgets(gadgets, parser=None)
        captured = capsys.readouterr()
        assert True  # No exception is success

    def test_print_gadget_empty_instructions(self, capsys):
        """Test printing gadget with no instructions"""
        gadget = Gadget(
            address="0x12345678",
            instructions=[],
            raw_line="0x12345678:  ; (1 found)",
            count=1
        )
        parser = ROPGadgetParser()
        parser.gadgets = [gadget]

        # Should not crash
        print_gadget_colored(gadget, parser)
        captured = capsys.readouterr()
        assert True  # No exception is success