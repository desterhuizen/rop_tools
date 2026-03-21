"""
Unit tests for worksheet.io.windbg module.
"""
import unittest
from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.io.windbg import cmd_import_regs, cmd_import_stack


class TestCmdImportRegs(unittest.TestCase):
    """Test the cmd_import_regs function."""

    def test_import_single_line(self):
        """Test importing registers from single line."""
        ws = blank_worksheet()
        text = "eax=00000001 ebx=00000000 ecx=005cdeaa edx=0000034e"

        success, msg = cmd_import_regs(ws, text)

        assert success is True
        assert "4 register(s)" in msg
        assert ws["registers"]["EAX"] == "0x00000001"
        assert ws["registers"]["EBX"] == "0x00000000"
        assert ws["registers"]["ECX"] == "0x005cdeaa"
        assert ws["registers"]["EDX"] == "0x0000034e"

    def test_import_multiple_lines(self):
        """Test importing registers from multiple lines."""
        ws = blank_worksheet()
        text = """
        eax=00000001 ebx=00000000 ecx=005cdeaa edx=0000034e esi=005c1716 edi=010237f8
        eip=41414141 esp=01bd744c ebp=005c4018 iopl=0         nv up ei pl nz na pe nc
        """

        success, msg = cmd_import_regs(ws, text)

        assert success is True
        assert ws["registers"]["EAX"] == "0x00000001"
        assert ws["registers"]["EIP"] == "0x41414141"
        assert ws["registers"]["ESP"] == "0x01bd744c"
        assert ws["registers"]["EBP"] == "0x005c4018"

    def test_import_case_insensitive(self):
        """Test that import is case insensitive."""
        ws = blank_worksheet()
        text = "EAX=DEADBEEF EBX=12345678"

        success, msg = cmd_import_regs(ws, text)

        assert success is True
        assert ws["registers"]["EAX"] == "0xDEADBEEF"
        assert ws["registers"]["EBX"] == "0x12345678"

    def test_import_partial_registers(self):
        """Test importing only some registers."""
        ws = blank_worksheet()
        text = "eax=deadbeef esp=01000000"

        success, msg = cmd_import_regs(ws, text)

        assert success is True
        assert "2 register(s)" in msg
        assert ws["registers"]["EAX"] == "0xdeadbeef"
        assert ws["registers"]["ESP"] == "0x01000000"
        # Others remain at default
        assert ws["registers"]["EBX"] == "0x00000000"

    def test_import_no_valid_registers(self):
        """Test importing text with no valid registers."""
        ws = blank_worksheet()
        text = "This is not valid register output"

        success, msg = cmd_import_regs(ws, text)

        assert success is False
        assert "No valid registers" in msg

    def test_import_with_extra_text(self):
        """Test importing with extra text around registers."""
        ws = blank_worksheet()
        text = "0:000> r\neax=deadbeef ebx=12345678\nsome other text"

        success, msg = cmd_import_regs(ws, text)

        assert success is True
        assert ws["registers"]["EAX"] == "0xdeadbeef"
        assert ws["registers"]["EBX"] == "0x12345678"


class TestCmdImportStack(unittest.TestCase):
    """Test the cmd_import_stack function."""

    def test_import_stack_single_line(self):
        """Test importing stack from single line."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01bd744c"
        text = "01bd744c  1012b413 10168060 1014dc4c 10154399"

        success, msg = cmd_import_stack(ws, text)

        assert success is True
        assert "4 stack value(s)" in msg
        assert ws["stack"]["+0x00"] == "0x1012b413"
        assert ws["stack"]["+0x04"] == "0x10168060"
        assert ws["stack"]["+0x08"] == "0x1014dc4c"
        assert ws["stack"]["+0x0c"] == "0x10154399"

    def test_import_stack_multiple_lines(self):
        """Test importing stack from multiple lines."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01bd744c"
        text = """
        01bd744c  1012b413 10168060 1014dc4c 10154399
        01bd745c  ffffc360 100fcd71 10154399 ffffffd0
        """

        success, msg = cmd_import_stack(ws, text)

        assert success is True
        assert ws["stack"]["+0x00"] == "0x1012b413"
        assert ws["stack"]["+0x10"] == "0xffffc360"
        assert ws["stack"]["+0x1c"] == "0xffffffd0"

    def test_import_stack_without_esp(self):
        """Test importing stack without ESP set returns error."""
        ws = blank_worksheet()
        text = "01bd744c  1012b413 10168060"

        success, msg = cmd_import_stack(ws, text)

        assert success is False
        assert "ESP not set" in msg

    def test_import_stack_calculates_correct_offsets(self):
        """Test that stack offsets are calculated correctly."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        text = "01000010  deadbeef 12345678"

        success, msg = cmd_import_stack(ws, text)

        assert success is True
        assert ws["stack"]["+0x10"] == "0xdeadbeef"
        assert ws["stack"]["+0x14"] == "0x12345678"

    def test_import_stack_negative_offsets(self):
        """Test importing stack with values before ESP."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000010"
        text = "01000000  deadbeef 12345678"

        success, msg = cmd_import_stack(ws, text)

        assert success is True
        assert ws["stack"]["-0x10"] == "0xdeadbeef"
        assert ws["stack"]["-0x0c"] == "0x12345678"

    def test_import_stack_with_fewer_values(self):
        """Test importing stack line with fewer than 4 values."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01bd744c"
        text = "01bd744c  1012b413 10168060"

        success, msg = cmd_import_stack(ws, text)

        assert success is True
        assert "2 stack value(s)" in msg
        assert ws["stack"]["+0x00"] == "0x1012b413"
        assert ws["stack"]["+0x04"] == "0x10168060"

    def test_import_stack_no_valid_values(self):
        """Test importing invalid stack dump."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        text = "This is not a valid stack dump"

        success, msg = cmd_import_stack(ws, text)

        assert success is False
        assert "No valid stack values" in msg

    def test_import_stack_with_colon_separator(self):
        """Test importing stack with colon after address."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01bd744c"
        text = "01bd744c:  1012b413 10168060"

        success, msg = cmd_import_stack(ws, text)

        assert success is True
        assert ws["stack"]["+0x00"] == "0x1012b413"