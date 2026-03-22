"""
Unit tests for worksheet.chain.manager module.
"""

import unittest

from rop.worksheet.chain.manager import cmd_chain_add, cmd_chain_clear, cmd_chain_del
from rop.worksheet.core.data import blank_worksheet


class TestCmdChainAdd(unittest.TestCase):
    """Test the cmd_chain_add operation."""

    def test_add_hex_address(self):
        """Test adding hex address to chain."""
        ws = blank_worksheet()

        success, msg = cmd_chain_add(ws, "0x10001234")

        assert success is True
        assert len(ws["chain"]) == 1
        assert ws["chain"][0]["type"] == "address"
        assert ws["chain"][0]["value"] == "0x10001234"

    def test_add_address_without_0x_prefix(self):
        """Test adding address without 0x prefix."""
        ws = blank_worksheet()

        success, msg = cmd_chain_add(ws, "10001234")

        assert success is True
        assert ws["chain"][0]["value"] == "0x10001234"

    def test_add_gadget_by_id(self):
        """Test adding gadget by ID (G1, G2, etc.)."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001000"] = "pop eax ; ret"
        ws["gadgets"]["0x10002000"] = "pop ebx ; ret"

        success, msg = cmd_chain_add(ws, "G1")

        assert success is True
        assert ws["chain"][0]["type"] == "address"
        # Should get first gadget by address order
        assert ws["chain"][0]["value"] in ["0x10001000", "0x10002000"]

    def test_add_gadget_id_case_insensitive(self):
        """Test that gadget ID is case insensitive."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"

        success, msg = cmd_chain_add(ws, "g1")

        assert success is True
        assert ws["chain"][0]["value"] == "0x10001234"

    def test_add_invalid_gadget_id(self):
        """Test adding invalid gadget ID returns error."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"

        success, msg = cmd_chain_add(ws, "G99")

        assert success is False
        assert "not found" in msg

    def test_add_literal_value(self):
        """Test adding literal value (placeholder)."""
        ws = blank_worksheet()

        success, msg = cmd_chain_add(ws, "PLACEHOLDER")

        assert success is True
        assert ws["chain"][0]["type"] == "literal"
        assert ws["chain"][0]["value"] == "PLACEHOLDER"

    def test_add_multiple_entries(self):
        """Test adding multiple chain entries."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"

        cmd_chain_add(ws, "G1")
        cmd_chain_add(ws, "0xdeadbeef")
        cmd_chain_add(ws, "PADDING")

        assert len(ws["chain"]) == 3
        assert ws["chain"][0]["type"] == "address"
        assert ws["chain"][1]["type"] == "address"
        assert ws["chain"][1]["value"] == "0xdeadbeef"
        assert ws["chain"][2]["type"] == "literal"


class TestCmdChainDel(unittest.TestCase):
    """Test the cmd_chain_del operation."""

    def test_delete_valid_index(self):
        """Test deleting entry by valid index."""
        ws = blank_worksheet()
        ws["chain"] = [
            {"type": "address", "value": "0x10001000"},
            {"type": "address", "value": "0x10002000"},
            {"type": "address", "value": "0x10003000"},
        ]

        success, msg = cmd_chain_del(ws, "2")

        assert success is True
        assert len(ws["chain"]) == 2
        assert ws["chain"][0]["value"] == "0x10001000"
        assert ws["chain"][1]["value"] == "0x10003000"

    def test_delete_first_entry(self):
        """Test deleting first entry."""
        ws = blank_worksheet()
        ws["chain"] = [
            {"type": "address", "value": "0x10001000"},
            {"type": "address", "value": "0x10002000"},
        ]

        success, msg = cmd_chain_del(ws, "1")

        assert success is True
        assert len(ws["chain"]) == 1
        assert ws["chain"][0]["value"] == "0x10002000"

    def test_delete_invalid_index(self):
        """Test deleting with invalid index returns error."""
        ws = blank_worksheet()
        ws["chain"] = [{"type": "address", "value": "0x10001000"}]

        success, msg = cmd_chain_del(ws, "99")

        assert success is False
        assert "Invalid index" in msg

    def test_delete_non_numeric_index(self):
        """Test deleting with non-numeric index returns error."""
        ws = blank_worksheet()
        ws["chain"] = [{"type": "address", "value": "0x10001000"}]

        success, msg = cmd_chain_del(ws, "abc")

        assert success is False
        assert "Invalid index" in msg

    def test_delete_zero_index(self):
        """Test deleting with zero index returns error."""
        ws = blank_worksheet()
        ws["chain"] = [{"type": "address", "value": "0x10001000"}]

        success, msg = cmd_chain_del(ws, "0")

        assert success is False


class TestCmdChainClear(unittest.TestCase):
    """Test the cmd_chain_clear operation."""

    def test_clear_empty_chain(self):
        """Test clearing empty chain."""
        ws = blank_worksheet()

        success, msg = cmd_chain_clear(ws)

        assert success is True
        assert ws["chain"] == []

    def test_clear_populated_chain(self):
        """Test clearing populated chain."""
        ws = blank_worksheet()
        ws["chain"] = [
            {"type": "address", "value": "0x10001000"},
            {"type": "address", "value": "0x10002000"},
            {"type": "address", "value": "0x10003000"},
        ]

        success, msg = cmd_chain_clear(ws)

        assert success is True
        assert ws["chain"] == []
