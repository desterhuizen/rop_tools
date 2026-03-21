"""
Unit tests for worksheet.operations.quick_ops module.
"""
import pytest
from worksheet.core.data import blank_worksheet
from worksheet.operations.quick_ops import cmd_set, cmd_clear


class TestCmdSet:
    """Test the cmd_set operation."""

    def test_set_register(self):
        """Test setting register value."""
        ws = blank_worksheet()

        success, msg = cmd_set(ws, "EAX", "0x12345678")

        assert success is True
        assert ws["registers"]["EAX"] == "0x12345678"

    def test_set_stack(self):
        """Test setting stack value."""
        ws = blank_worksheet()

        success, msg = cmd_set(ws, "ESP+0x10", "0xdeadbeef")

        assert success is True
        assert ws["stack"]["+0x10"] == "0xdeadbeef"

    def test_set_named(self):
        """Test setting named value."""
        ws = blank_worksheet()

        success, msg = cmd_set(ws, "shellgen", "0x00501000")

        assert success is True
        assert ws["named"]["shellgen"] == "0x00501000"

    def test_set_resolves_register_value(self):
        """Test that set resolves register values."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"

        success, msg = cmd_set(ws, "EBX", "EAX")

        assert success is True
        assert ws["registers"]["EBX"] == "0xdeadbeef"

    def test_set_resolves_named_value(self):
        """Test that set resolves named values."""
        ws = blank_worksheet()
        ws["named"]["base"] = "0x10000000"

        success, msg = cmd_set(ws, "EAX", "base")

        assert success is True
        assert ws["registers"]["EAX"] == "0x10000000"


class TestCmdClear:
    """Test the cmd_clear operation."""

    def test_clear_register(self):
        """Test clearing register."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"

        success, msg = cmd_clear(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == ""

    def test_clear_stack(self):
        """Test clearing stack value."""
        ws = blank_worksheet()
        ws["stack"]["+0x10"] = "0xdeadbeef"

        success, msg = cmd_clear(ws, "ESP+0x10")

        assert success is True
        assert "+0x10" not in ws["stack"]

    def test_clear_named(self):
        """Test clearing named value."""
        ws = blank_worksheet()
        ws["named"]["shellgen"] = "0x00501000"

        success, msg = cmd_clear(ws, "shellgen")

        assert success is True
        assert "shellgen" not in ws["named"]

    def test_clear_nonexistent_stack(self):
        """Test clearing non-existent stack value doesn't error."""
        ws = blank_worksheet()

        success, msg = cmd_clear(ws, "ESP+0x10")

        assert success is True

    def test_clear_nonexistent_named(self):
        """Test clearing non-existent named value doesn't error."""
        ws = blank_worksheet()

        success, msg = cmd_clear(ws, "nonexistent")

        assert success is True