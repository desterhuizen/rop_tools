"""
Unit tests for worksheet.ui.display module.

Note: These tests verify that the display functions execute without errors
and return valid Rich objects. Full visual testing would require manual inspection.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.ui.display import build_worksheet_view

# Try to import Rich, skip tests if not available
try:
    from rich.console import Group

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@unittest.skipIf(not RICH_AVAILABLE, reason="Rich library not installed")
class TestBuildWorksheetView(unittest.TestCase):
    """Test the build_worksheet_view function."""

    def test_build_view_with_blank_worksheet(self):
        """Test building view with blank worksheet."""
        ws = blank_worksheet()

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_register_values(self):
        """Test building view with register values."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"
        ws["registers"]["EBX"] = "0x12345678"

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_stack_values(self):
        """Test building view with stack values."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0xdeadbeef"
        ws["stack"]["+0x04"] = "0x12345678"

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_named_values(self):
        """Test building view with named values."""
        ws = blank_worksheet()
        ws["named"]["shellgen"] = "0x00501000"
        ws["named"]["base_addr"] = "0x10000000"

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_gadgets(self):
        """Test building view with gadgets in library."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"
        ws["gadgets"]["0x10002345"] = "pop ebx ; ret"

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_chain(self):
        """Test building view with ROP chain."""
        ws = blank_worksheet()
        ws["chain"] = [
            {"type": "address", "value": "0x10001234"},
            {"type": "address", "value": "0x10002345"},
        ]

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_execution_log(self):
        """Test building view with execution log."""
        ws = blank_worksheet()
        ws["execution_log"] = [
            {"type": "manual", "source": "User",
             "operation": "mov EAX, 0x12345678"},
            {"type": "auto", "source": "0x10001234", "operation": "pop eax"},
        ]

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_notes(self):
        """Test building view with notes."""
        ws = blank_worksheet()
        ws["notes"] = "This is a test note"

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_fully_populated(self):
        """Test building view with fully populated worksheet."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0x11111111"
        ws["named"]["shellgen"] = "0x00501000"
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"
        ws["chain"] = [{"type": "address", "value": "0x10001234"}]
        ws["notes"] = "Test notes"
        ws["execution_log"] = [
            {"type": "manual", "source": "User",
             "operation": "mov EAX, 0xdeadbeef"}
        ]

        result = build_worksheet_view(ws)

        assert result is not None
        assert isinstance(result, Group)

    def test_build_view_with_matching_named_values(self):
        """Test that named value matching works in display."""
        ws = blank_worksheet()
        ws["named"]["test_value"] = "0xdeadbeef"
        ws["registers"]["EAX"] = "0xdeadbeef"  # Should match named value

        # Should not raise exception
        result = build_worksheet_view(ws)

        assert result is not None

    def test_build_view_with_multiple_names_for_same_value(self):
        """Test display handles multiple names for same value."""
        ws = blank_worksheet()
        ws["named"]["val1"] = "0x12345678"
        ws["named"]["val2"] = "0x12345678"
        ws["registers"]["EAX"] = "0x12345678"

        result = build_worksheet_view(ws)

        assert result is not None
