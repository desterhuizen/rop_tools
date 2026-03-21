"""
Unit tests for worksheet.gadgets.library module.
"""
import unittest
from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.gadgets.library import cmd_gadget_add, cmd_gadget_del, cmd_gadget_clear


class TestCmdGadgetAdd(unittest.TestCase):
    """Test the cmd_gadget_add operation."""

    def test_add_gadget(self):
        """Test adding a gadget to library."""
        ws = blank_worksheet()

        success, msg = cmd_gadget_add(ws, "0x10001234", "pop eax ; ret")

        assert success is True
        assert "0x10001234" in ws["gadgets"]
        assert ws["gadgets"]["0x10001234"] == "pop eax ; ret"

    def test_add_gadget_without_0x_prefix(self):
        """Test adding gadget without 0x prefix."""
        ws = blank_worksheet()

        success, msg = cmd_gadget_add(ws, "10001234", "pop ebx ; ret")

        assert success is True
        assert "0x10001234" in ws["gadgets"]

    def test_add_gadget_normalizes_to_lowercase(self):
        """Test that addresses are normalized to lowercase."""
        ws = blank_worksheet()

        cmd_gadget_add(ws, "0x1000ABCD", "pop ecx ; ret")

        assert "0x1000abcd" in ws["gadgets"]

    def test_add_multiple_gadgets(self):
        """Test adding multiple gadgets."""
        ws = blank_worksheet()

        cmd_gadget_add(ws, "0x10001000", "pop eax ; ret")
        cmd_gadget_add(ws, "0x10002000", "pop ebx ; ret")
        cmd_gadget_add(ws, "0x10003000", "pop ecx ; ret")

        assert len(ws["gadgets"]) == 3
        assert "0x10001000" in ws["gadgets"]
        assert "0x10002000" in ws["gadgets"]
        assert "0x10003000" in ws["gadgets"]

    def test_add_gadget_overwrites_existing(self):
        """Test that adding gadget with same address overwrites."""
        ws = blank_worksheet()

        cmd_gadget_add(ws, "0x10001234", "pop eax ; ret")
        cmd_gadget_add(ws, "0x10001234", "pop ebx ; ret")

        assert ws["gadgets"]["0x10001234"] == "pop ebx ; ret"


class TestCmdGadgetDel(unittest.TestCase):
    """Test the cmd_gadget_del operation."""

    def test_delete_existing_gadget(self):
        """Test deleting an existing gadget."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"

        success, msg = cmd_gadget_del(ws, "0x10001234")

        assert success is True
        assert "0x10001234" not in ws["gadgets"]

    def test_delete_nonexistent_gadget(self):
        """Test deleting non-existent gadget returns error."""
        ws = blank_worksheet()

        success, msg = cmd_gadget_del(ws, "0x10001234")

        assert success is False
        assert "not found" in msg

    def test_delete_normalizes_address(self):
        """Test that delete normalizes address."""
        ws = blank_worksheet()
        ws["gadgets"]["0x1000abcd"] = "pop eax ; ret"

        success, msg = cmd_gadget_del(ws, "0x1000ABCD")

        assert success is True
        assert "0x1000abcd" not in ws["gadgets"]


class TestCmdGadgetClear(unittest.TestCase):
    """Test the cmd_gadget_clear operation."""

    def test_clear_empty_library(self):
        """Test clearing empty library."""
        ws = blank_worksheet()

        success, msg = cmd_gadget_clear(ws)

        assert success is True
        assert len(ws["gadgets"]) == 0

    def test_clear_populated_library(self):
        """Test clearing library with gadgets."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001000"] = "pop eax ; ret"
        ws["gadgets"]["0x10002000"] = "pop ebx ; ret"
        ws["gadgets"]["0x10003000"] = "pop ecx ; ret"

        success, msg = cmd_gadget_clear(ws)

        assert success is True
        assert len(ws["gadgets"]) == 0
        assert ws["gadgets"] == {}