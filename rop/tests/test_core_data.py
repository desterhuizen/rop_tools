"""
Unit tests for worksheet.core.data module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet


class TestBlankWorksheet(unittest.TestCase):
    """Test the blank_worksheet factory function."""

    def test_blank_worksheet_structure(self):
        """Test that blank worksheet has all required keys."""
        ws = blank_worksheet()

        assert "registers" in ws
        assert "stack" in ws
        assert "named" in ws
        assert "gadgets" in ws
        assert "chain" in ws
        assert "notes" in ws
        assert "auto_gadget" in ws
        assert "execution_log" in ws
        assert "log_manual" in ws

    def test_blank_worksheet_register_defaults(self):
        """Test that all registers are initialized to 0x00000000."""
        ws = blank_worksheet()

        expected_registers = [
            "EAX",
            "EBX",
            "ECX",
            "EDX",
            "ESI",
            "EDI",
            "EBP",
            "ESP",
            "EIP",
        ]

        # Check all expected registers exist
        for reg in expected_registers:
            assert reg in ws["registers"]
            assert ws["registers"][reg] == "0x00000000"

        # Check we have exactly these registers
        assert len(ws["registers"]) == len(expected_registers)

    def test_blank_worksheet_empty_collections(self):
        """Test that stack, named, gadgets, and chain are empty."""
        ws = blank_worksheet()

        assert ws["stack"] == {}
        assert ws["named"] == {}
        assert ws["gadgets"] == {}
        assert ws["chain"] == []

    def test_blank_worksheet_default_flags(self):
        """Test default flag values."""
        ws = blank_worksheet()

        assert ws["auto_gadget"] is True
        assert ws["log_manual"] is True
        assert ws["notes"] == ""
        assert ws["execution_log"] == []

    def test_blank_worksheet_independence(self):
        """Test that multiple blank worksheets are independent."""
        ws1 = blank_worksheet()
        ws2 = blank_worksheet()

        # Modify ws1
        ws1["registers"]["EAX"] = "0xdeadbeef"
        ws1["stack"]["+0x00"] = "0x12345678"
        ws1["named"]["test"] = "0xabcdef"

        # Check ws2 is unchanged
        assert ws2["registers"]["EAX"] == "0x00000000"
        assert ws2["stack"] == {}
        assert ws2["named"] == {}
