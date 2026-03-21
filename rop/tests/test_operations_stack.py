"""
Unit tests for worksheet.operations.stack_ops module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.operations.stack_ops import cmd_pop, cmd_push, cmd_stack


class TestCmdPush(unittest.TestCase):
    """Test the cmd_push operation."""

    def test_push_value(self):
        """Test pushing a value to stack."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"

        success, msg = cmd_push(ws, "0xdeadbeef")

        assert success is True
        assert ws["registers"]["ESP"] == "0x00fffffc"  # ESP decremented by 4
        assert ws["stack"]["+0x00"] == "0xdeadbeef"

    def test_push_register(self):
        """Test pushing register value to stack."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["registers"]["EAX"] = "0x12345678"

        success, msg = cmd_push(ws, "EAX")

        assert success is True
        assert ws["stack"]["+0x00"] == "0x12345678"

    def test_push_adjusts_existing_offsets(self):
        """Test that push adjusts existing stack offsets."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0x11111111"
        ws["stack"]["+0x04"] = "0x22222222"

        success, msg = cmd_push(ws, "0xdeadbeef")

        assert success is True
        # New value at +0x00
        assert ws["stack"]["+0x00"] == "0xdeadbeef"
        # Previous values shifted up
        assert ws["stack"]["+0x04"] == "0x11111111"
        assert ws["stack"]["+0x08"] == "0x22222222"

    def test_push_multiple_times(self):
        """Test pushing multiple values."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"

        cmd_push(ws, "0xaaaaaaaa")
        cmd_push(ws, "0xbbbbbbbb")
        cmd_push(ws, "0xcccccccc")

        assert ws["registers"]["ESP"] == "0x00fffff4"  # ESP -= 12
        assert ws["stack"]["+0x00"] == "0xcccccccc"  # Last pushed
        assert ws["stack"]["+0x04"] == "0xbbbbbbbb"
        assert ws["stack"]["+0x08"] == "0xaaaaaaaa"  # First pushed


class TestCmdPop(unittest.TestCase):
    """Test the cmd_pop operation."""

    def test_pop_to_register(self):
        """Test popping value from stack to register."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0xdeadbeef"

        success, msg = cmd_pop(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0xdeadbeef"
        assert ws["registers"]["ESP"] == "0x01000004"  # ESP incremented by 4

    def test_pop_empty_stack(self):
        """Test popping from empty stack returns error."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"

        success, msg = cmd_pop(ws, "EAX")

        assert success is False
        assert "No value" in msg

    def test_pop_adjusts_existing_offsets(self):
        """Test that pop adjusts existing stack offsets."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0x11111111"
        ws["stack"]["+0x04"] = "0x22222222"
        ws["stack"]["+0x08"] = "0x33333333"

        success, msg = cmd_pop(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x11111111"
        # Remaining values shifted down
        assert ws["stack"]["+0x00"] == "0x22222222"
        assert ws["stack"]["+0x04"] == "0x33333333"

    def test_push_pop_round_trip(self):
        """Test that push/pop is reversible."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["registers"]["EAX"] = "0xdeadbeef"

        # Push
        cmd_push(ws, "EAX")
        assert ws["registers"]["ESP"] == "0x00fffffc"

        # Clear EAX
        ws["registers"]["EAX"] = "0x00000000"

        # Pop
        cmd_pop(ws, "EAX")
        assert ws["registers"]["ESP"] == "0x01000000"  # Back to original
        assert ws["registers"]["EAX"] == "0xdeadbeef"


class TestCmdStack(unittest.TestCase):
    """Test the cmd_stack operation."""

    def test_set_stack_value(self):
        """Test directly setting stack value."""
        ws = blank_worksheet()

        success, msg = cmd_stack(ws, "+0x10", "0xdeadbeef")

        assert success is True
        assert ws["stack"]["+0x10"] == "0xdeadbeef"

    def test_set_stack_with_esp_prefix(self):
        """Test setting stack with ESP prefix."""
        ws = blank_worksheet()

        success, msg = cmd_stack(ws, "ESP+0x10", "0x12345678")

        assert success is True
        assert ws["stack"]["+0x10"] == "0x12345678"

    def test_set_stack_register_as_offset(self):
        """Test using register containing stack address as offset."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["registers"]["ECX"] = "0x01000010"  # ESP+0x10

        success, msg = cmd_stack(ws, "ECX", "0xdeadbeef")

        assert success is True
        assert ws["stack"]["+0x10"] == "0xdeadbeef"

    def test_set_stack_negative_offset(self):
        """Test setting stack at negative offset."""
        ws = blank_worksheet()

        success, msg = cmd_stack(ws, "-0x04", "0xaaaaaaaa")

        assert success is True
        assert ws["stack"]["-0x04"] == "0xaaaaaaaa"

    def test_set_stack_resolves_register_value(self):
        """Test that stack command resolves register values."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"

        success, msg = cmd_stack(ws, "+0x00", "EAX")

        assert success is True
        assert ws["stack"]["+0x00"] == "0xdeadbeef"

    def test_set_stack_invalid_offset_format(self):
        """Test setting stack with invalid offset format."""
        ws = blank_worksheet()

        success, msg = cmd_stack(ws, "invalid", "0x12345678")

        assert success is False
        assert "Invalid offset format" in msg

    def test_set_stack_register_not_set(self):
        """Test using unset register as offset returns error."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x00000000"
        ws["registers"]["ECX"] = "0x00000000"

        success, msg = cmd_stack(ws, "ECX", "0xdeadbeef")

        assert success is False
        assert "does not contain a valid address" in msg
