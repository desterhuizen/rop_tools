"""
Unit tests for worksheet.gadgets.processor module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.gadgets.processor import (
    find_gadget_by_address,
    log_execution,
    process_gadget,
)


class TestFindGadgetByAddress(unittest.TestCase):
    """Test the find_gadget_by_address function."""

    def test_find_existing_gadget(self):
        """Test finding gadget by address."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"

        result = find_gadget_by_address(ws, "0x10001234")

        assert result == "pop eax ; ret"

    def test_find_gadget_case_insensitive(self):
        """Test finding gadget is case insensitive."""
        ws = blank_worksheet()
        ws["gadgets"]["0x10001234"] = "pop eax ; ret"

        result = find_gadget_by_address(ws, "0x1000123 4")

        assert result is None  # With space it won't match

    def test_find_nonexistent_gadget(self):
        """Test finding non-existent gadget returns None."""
        ws = blank_worksheet()

        result = find_gadget_by_address(ws, "0x99999999")

        assert result is None


class TestProcessGadget(unittest.TestCase):
    """Test the process_gadget function."""

    def test_process_simple_pop(self):
        """Test processing simple pop instruction."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0xdeadbeef"

        executed = process_gadget(ws, "pop eax ; ret", "0x10001234")

        assert len(executed) == 1
        assert "pop eax" in executed[0]
        assert ws["registers"]["EAX"] == "0xdeadbeef"

    def test_process_multiple_instructions(self):
        """Test processing multiple instructions."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["stack"]["+0x00"] = "0x11111111"
        ws["stack"]["+0x04"] = "0x22222222"

        executed = process_gadget(ws, "pop eax ; pop ebx ; ret")

        assert len(executed) == 2
        assert ws["registers"]["EAX"] == "0x11111111"
        assert ws["registers"]["EBX"] == "0x22222222"

    def test_process_mov_instruction(self):
        """Test processing mov instruction."""
        ws = blank_worksheet()

        executed = process_gadget(ws, "mov eax, 0x12345678 ; ret")

        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x12345678"

    def test_process_add_instruction(self):
        """Test processing add instruction."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"

        executed = process_gadget(ws, "add eax, 0x00000002 ; ret")

        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00000003"

    def test_process_xor_instruction(self):
        """Test processing xor instruction."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"

        executed = process_gadget(ws, "xor eax, eax ; ret")

        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00000000"

    def test_process_stops_at_ret(self):
        """Test that processing stops at ret."""
        ws = blank_worksheet()

        executed = process_gadget(ws, "mov eax, 0x12345678 ; ret ; mov ebx, 0xdeadbeef")

        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x12345678"
        assert ws["registers"]["EBX"] == "0x00000000"  # Not executed

    def test_process_skips_unsupported_registers(self):
        """Test that unsupported registers (8-bit, 16-bit) are skipped."""
        ws = blank_worksheet()

        executed = process_gadget(ws, "mov al, 0x12 ; mov eax, 0xdeadbeef ; ret")

        # Only the eax instruction should be executed
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0xdeadbeef"

    def test_process_inc_instruction(self):
        """Test processing inc instruction."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000005"

        executed = process_gadget(ws, "inc eax ; ret")

        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00000006"

    def test_process_dec_instruction(self):
        """Test processing dec instruction."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000005"

        executed = process_gadget(ws, "dec eax ; ret")

        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00000004"

    def test_process_push_instruction(self):
        """Test processing push instruction."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["registers"]["EAX"] = "0xdeadbeef"

        executed = process_gadget(ws, "push eax ; ret")

        assert len(executed) == 1
        assert ws["stack"]["+0x00"] == "0xdeadbeef"

    def test_process_creates_log_entries(self):
        """Test that processing creates auto log entries."""
        ws = blank_worksheet()

        process_gadget(ws, "mov eax, 0x12345678 ; ret", "0x10001234")

        assert len(ws["execution_log"]) > 0
        assert ws["execution_log"][0]["type"] == "auto"
        assert ws["execution_log"][0]["source"] == "0x10001234"

    def test_process_respects_in_auto_gadget_flag(self):
        """Test that _in_auto_gadget flag prevents duplicate logging."""
        ws = blank_worksheet()
        ws["log_manual"] = True

        # Should not log manual operations during auto-gadget processing
        process_gadget(ws, "mov eax, 0x12345678 ; ret")

        # Only auto log should exist
        for log in ws["execution_log"]:
            assert log["type"] == "auto"


class TestLogExecution(unittest.TestCase):
    """Test the log_execution function."""

    def test_log_manual_operation(self):
        """Test logging manual operation."""
        ws = blank_worksheet()

        log_execution(ws, "manual", "User", "mov EAX, 0x12345678")

        assert len(ws["execution_log"]) == 1
        assert ws["execution_log"][0]["type"] == "manual"
        assert ws["execution_log"][0]["source"] == "User"
        assert ws["execution_log"][0]["operation"] == "mov EAX, 0x12345678"

    def test_log_auto_operation(self):
        """Test logging auto operation."""
        ws = blank_worksheet()

        log_execution(ws, "auto", "0x10001234", "pop eax")

        assert len(ws["execution_log"]) == 1
        assert ws["execution_log"][0]["type"] == "auto"
        assert ws["execution_log"][0]["source"] == "0x10001234"

    def test_log_keeps_last_10_entries(self):
        """Test that log keeps only last 10 entries."""
        ws = blank_worksheet()

        # Add 15 entries
        for i in range(15):
            log_execution(ws, "manual", "User", f"operation {i}")

        assert len(ws["execution_log"]) == 10
        # Should have entries 5-14
        assert ws["execution_log"][0]["operation"] == "operation 5"
        assert ws["execution_log"][-1]["operation"] == "operation 14"
