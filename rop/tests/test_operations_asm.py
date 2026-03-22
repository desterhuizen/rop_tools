"""
Unit tests for worksheet.operations.asm_ops module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.operations.asm_ops import (
    cmd_add,
    cmd_dec,
    cmd_inc,
    cmd_move,
    cmd_neg,
    cmd_xchg,
    cmd_xor,
)


class TestCmdMove(unittest.TestCase):
    """Test the cmd_move operation."""

    def test_move_to_register(self):
        """Test moving value to register."""
        ws = blank_worksheet()
        success, msg = cmd_move(ws, "EAX", "0xdeadbeef")

        assert success is True
        assert ws["registers"]["EAX"] == "0xdeadbeef"

    def test_move_register_to_register(self):
        """Test moving register value to another register."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"

        success, msg = cmd_move(ws, "EBX", "EAX")

        assert success is True
        assert ws["registers"]["EBX"] == "0x12345678"

    def test_move_to_stack(self):
        """Test moving value to stack."""
        ws = blank_worksheet()
        success, msg = cmd_move(ws, "ESP+0x10", "0xdeadbeef")

        assert success is True
        assert ws["stack"]["+0x10"] == "0xdeadbeef"

    def test_move_to_named(self):
        """Test moving value to named value."""
        ws = blank_worksheet()
        success, msg = cmd_move(ws, "shellgen", "0x00501000")

        assert success is True
        assert ws["named"]["shellgen"] == "0x00501000"

    def test_move_invalid_source(self):
        """Test moving invalid source returns error."""
        ws = blank_worksheet()
        success, msg = cmd_move(ws, "EAX", "nonexistent")

        assert success is False
        assert "Cannot resolve source" in msg

    def test_move_to_dereferenced_register(self):
        """Test moving to dereferenced register."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["registers"]["ECX"] = "0x01000010"  # Points to ESP+0x10

        success, msg = cmd_move(ws, "[ECX]", "0xdeadbeef")

        assert success is True
        assert ws["stack"]["+0x10"] == "0xdeadbeef"


class TestCmdAdd(unittest.TestCase):
    """Test the cmd_add operation."""

    def test_add_to_register(self):
        """Test adding to register."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"

        success, msg = cmd_add(ws, "EAX", "0x00000002")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000003"

    def test_add_register_to_register(self):
        """Test adding register to register."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000010"
        ws["registers"]["EBX"] = "0x00000020"

        success, msg = cmd_add(ws, "EAX", "EBX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000030"

    def test_add_with_overflow(self):
        """Test that add wraps at 32-bit boundary."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"

        success, msg = cmd_add(ws, "EAX", "0x00000001")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000000"  # Wrapped

    def test_add_to_stack(self):
        """Test adding to stack value."""
        ws = blank_worksheet()
        ws["stack"]["+0x00"] = "0x00000100"

        success, msg = cmd_add(ws, "ESP+0x00", "0x00000050")

        assert success is True
        assert ws["stack"]["+0x00"] == "0x00000150"

    def test_add_invalid_operands(self):
        """Test adding with invalid operands returns error."""
        ws = blank_worksheet()
        success, msg = cmd_add(ws, "EAX", "nonexistent")

        assert success is False
        assert "Cannot resolve operands" in msg


class TestCmdXor(unittest.TestCase):
    """Test the cmd_xor operation."""

    def test_xor_register_with_value(self):
        """Test XOR register with value."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"

        success, msg = cmd_xor(ws, "EAX", "0x0000ffff")

        assert success is True
        assert ws["registers"]["EAX"] == "0xffff0000"

    def test_xor_register_with_itself(self):
        """Test XOR register with itself (zero out)."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"

        success, msg = cmd_xor(ws, "EAX", "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000000"

    def test_xor_registers(self):
        """Test XOR between two registers."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaaaa5555"
        ws["registers"]["EBX"] = "0x5555aaaa"

        success, msg = cmd_xor(ws, "EAX", "EBX")

        assert success is True
        assert ws["registers"]["EAX"] == "0xffffffff"


class TestCmdXchg(unittest.TestCase):
    """Test the cmd_xchg operation."""

    def test_xchg_registers(self):
        """Test exchanging two registers."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"
        ws["registers"]["EBX"] = "0x12345678"

        success, msg = cmd_xchg(ws, "EAX", "EBX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x12345678"
        assert ws["registers"]["EBX"] == "0xdeadbeef"

    def test_xchg_register_with_stack(self):
        """Test exchanging register with stack value."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaaaaaaaa"
        ws["stack"]["+0x00"] = "0xbbbbbbbb"

        success, msg = cmd_xchg(ws, "EAX", "ESP+0x00")

        assert success is True
        assert ws["registers"]["EAX"] == "0xbbbbbbbb"
        assert ws["stack"]["+0x00"] == "0xaaaaaaaa"

    def test_xchg_named_values(self):
        """Test exchanging named values."""
        ws = blank_worksheet()
        ws["named"]["val1"] = "0x11111111"
        ws["named"]["val2"] = "0x22222222"

        success, msg = cmd_xchg(ws, "val1", "val2")

        assert success is True
        assert ws["named"]["val1"] == "0x22222222"
        assert ws["named"]["val2"] == "0x11111111"


class TestCmdInc(unittest.TestCase):
    """Test the cmd_inc operation."""

    def test_inc_register(self):
        """Test incrementing register."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000005"

        success, msg = cmd_inc(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000006"

    def test_inc_with_overflow(self):
        """Test increment wraps at 32-bit boundary."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"

        success, msg = cmd_inc(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000000"


class TestCmdDec(unittest.TestCase):
    """Test the cmd_dec operation."""

    def test_dec_register(self):
        """Test decrementing register."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000005"

        success, msg = cmd_dec(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000004"

    def test_dec_with_underflow(self):
        """Test decrement wraps at 32-bit boundary."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"

        success, msg = cmd_dec(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0xffffffff"


class TestCmdNeg(unittest.TestCase):
    """Test the cmd_neg operation."""

    def test_neg_positive_value(self):
        """Test negating positive value."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"

        success, msg = cmd_neg(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0xffffffff"  # -1 in two's complement

    def test_neg_negative_value(self):
        """Test negating negative value."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"  # -1

        success, msg = cmd_neg(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000001"

    def test_neg_zero(self):
        """Test negating zero."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"

        success, msg = cmd_neg(ws, "EAX")

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000000"


class TestLogging(unittest.TestCase):
    """Test that operations are logged correctly."""

    def test_move_creates_log_entry(self):
        """Test that manual operations create log entries."""
        ws = blank_worksheet()
        ws["log_manual"] = True

        cmd_move(ws, "EAX", "0x12345678")

        assert len(ws["execution_log"]) == 1
        assert ws["execution_log"][0]["type"] == "manual"
        assert ws["execution_log"][0]["source"] == "User"
        assert "mov" in ws["execution_log"][0]["operation"]

    def test_logging_disabled(self):
        """Test that logging can be disabled."""
        ws = blank_worksheet()
        ws["log_manual"] = False

        cmd_move(ws, "EAX", "0x12345678")

        assert len(ws["execution_log"]) == 0

    def test_log_max_entries(self):
        """Test that log keeps only last 10 entries."""
        ws = blank_worksheet()
        ws["log_manual"] = True

        # Add 15 operations
        for _i in range(15):
            cmd_inc(ws, "EAX")

        assert len(ws["execution_log"]) == 10
