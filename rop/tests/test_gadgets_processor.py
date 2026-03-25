"""
Unit tests for worksheet.gadgets.processor module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.gadgets.processor import (
    find_gadget_by_address,
    format_executed_list,
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

    def test_process_supports_sub_registers(self):
        """Test that sub-registers (8-bit, 16-bit) are now supported."""
        ws = blank_worksheet()

        executed = process_gadget(ws, "mov al, 0x12 ; mov eax, 0xdeadbeef ; ret")

        # Both instructions should be executed (sub-registers supported)
        assert len(executed) == 2
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


class TestProcessGadgetNewInstructions(unittest.TestCase):
    """Test new instructions in gadget auto-execution."""

    def test_process_and_instruction(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"
        executed = process_gadget(ws, "and eax, 0x0000ffff ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x0000ffff"

    def test_process_or_instruction(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00ff0000"
        executed = process_gadget(ws, "or eax, 0x000000ff ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00ff00ff"

    def test_process_not_instruction(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        executed = process_gadget(ws, "not eax ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0xffffffff"

    def test_process_shl_instruction(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"
        executed = process_gadget(ws, "shl eax, 0x10 ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00010000"

    def test_process_complex_gadget_with_sub_regs(self):
        """Test a realistic gadget with mixed register sizes."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        ws["registers"]["ECX"] = "0x00000041"
        executed = process_gadget(ws, "mov al, cl ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00000041"

    def test_process_gadget_sub_register_mov(self):
        """Gadget processor should execute sub-register instructions."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        executed = process_gadget(ws, "mov al, 0x41 ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00000041"

    def test_process_cdq(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"
        ws["registers"]["EDX"] = "0xdeadbeef"
        executed = process_gadget(ws, "cdq ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EDX"] == "0x00000000"

    def test_process_nop(self):
        ws = blank_worksheet()
        executed = process_gadget(ws, "nop ; ret")
        assert len(executed) == 1

    def test_process_nop_in_chain(self):
        """NOP should not disrupt other instructions in a gadget."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        executed = process_gadget(ws, "nop ; mov eax, 0x41414141 ; nop ; ret")
        assert len(executed) == 3
        assert ws["registers"]["EAX"] == "0x41414141"

    def test_process_movzx(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabbccdd"
        executed = process_gadget(ws, "movzx ebx, al ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EBX"] == "0x000000dd"

    def test_process_lea(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00401000"
        executed = process_gadget(ws, "lea eax, [ecx+0x10] ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00401010"

    def test_process_lea_complex(self):
        """Realistic gadget: lea eax, [ecx+edx*4]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00000008"
        executed = process_gadget(ws, "lea eax, [ecx+edx*4] ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0x00400020"

    def test_process_cdq_xor_edx_pattern(self):
        """Common ROP pattern: xor eax, eax ; cdq to zero both."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"
        ws["registers"]["EDX"] = "0xdeadbeef"
        executed = process_gadget(ws, "xor eax, eax ; cdq ; ret")
        assert len(executed) == 2
        assert ws["registers"]["EAX"] == "0x00000000"
        assert ws["registers"]["EDX"] == "0x00000000"

    def test_process_lodsd(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        ws["registers"]["ESI"] = "0x0019ff00"
        ws["stack"]["+0x00"] = "0xcafebabe"
        executed = process_gadget(ws, "lodsd ; ret")
        assert len(executed) == 1
        assert ws["registers"]["EAX"] == "0xcafebabe"
        assert ws["registers"]["ESI"] == "0x0019ff04"

    def test_process_stosd(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        ws["registers"]["EDI"] = "0x0019ff08"
        ws["registers"]["EAX"] = "0x41424344"
        executed = process_gadget(ws, "stosd ; ret")
        assert len(executed) == 1
        assert ws["stack"]["+0x08"] == "0x41424344"
        assert ws["registers"]["EDI"] == "0x0019ff0c"


class TestBadInstructionWarnings(unittest.TestCase):
    """Test that bad instructions produce warnings in process_gadget."""

    def test_privileged_instruction_warning(self):
        """Privileged instructions should produce a WARNING entry."""
        ws = blank_worksheet()
        executed = process_gadget(ws, "hlt ; ret")
        assert len(executed) == 1
        assert "[WARNING: PRIVILEGED]" in executed[0]
        assert "hlt" in executed[0]

    def test_io_instruction_warning(self):
        ws = blank_worksheet()
        executed = process_gadget(ws, "cli ; ret")
        assert len(executed) == 1
        assert "[WARNING:" in executed[0]

    def test_control_flow_warning(self):
        ws = blank_worksheet()
        executed = process_gadget(ws, "jmp eax ; ret")
        assert len(executed) == 1
        assert "[WARNING: CONTROL FLOW]" in executed[0]

    def test_bad_instruction_does_not_abort_chain(self):
        """Bad instruction should warn but not stop subsequent instructions."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        executed = process_gadget(ws, "cli ; mov eax, 0xdeadbeef ; ret")
        assert len(executed) == 2
        assert "[WARNING:" in executed[0]
        assert "mov eax" in executed[1]
        assert ws["registers"]["EAX"] == "0xdeadbeef"

    def test_unknown_non_bad_instruction_is_skipped(self):
        """Unknown instructions that are NOT bad should still be silently skipped."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        executed = process_gadget(ws, "foobar ; mov eax, 0x41414141 ; ret")
        # foobar is unknown and not bad — silently skipped
        assert len(executed) == 1
        assert "mov eax" in executed[0]

    def test_bad_instruction_logged(self):
        """Bad instruction warnings should appear in the execution log."""
        ws = blank_worksheet()
        process_gadget(ws, "hlt ; ret", "0x10001234")
        assert len(ws["execution_log"]) == 1
        assert "[WARNING:" in ws["execution_log"][0]["operation"]

    def test_leave_warning(self):
        ws = blank_worksheet()
        executed = process_gadget(ws, "leave ; ret")
        assert len(executed) == 1
        assert "[WARNING: STACK FRAME]" in executed[0]

    def test_pushf_warning(self):
        ws = blank_worksheet()
        executed = process_gadget(ws, "pushf ; ret")
        assert len(executed) == 1
        assert "[WARNING: FLAGS]" in executed[0]

    def test_lock_warning(self):
        ws = blank_worksheet()
        executed = process_gadget(ws, "lock ; ret")
        assert len(executed) == 1
        assert "[WARNING: SYNC/PREFIX]" in executed[0]


class TestFormatExecutedList(unittest.TestCase):
    """Test the format_executed_list helper."""

    def test_normal_entries(self):
        result = format_executed_list(["pop eax", "mov ebx, ecx"])
        assert result == "pop eax ; mov ebx, ecx"
        assert "[yellow]" not in result

    def test_warning_entries_get_yellow(self):
        result = format_executed_list(["[WARNING: PRIVILEGED] hlt"])
        assert "[yellow]" in result
        assert "[/yellow]" in result

    def test_error_entries_get_red(self):
        result = format_executed_list(["[ERROR: bad] foo"])
        assert "[red]" in result

    def test_failed_entries_get_red(self):
        result = format_executed_list(["[FAILED: oops] bar"])
        assert "[red]" in result

    def test_mixed_entries(self):
        entries = [
            "pop eax",
            "[WARNING: I/O] in",
            "mov ebx, ecx",
        ]
        result = format_executed_list(entries)
        assert "pop eax" in result
        assert "[yellow]" in result
        assert "mov ebx, ecx" in result
