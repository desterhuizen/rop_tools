"""
Unit tests for worksheet.core.resolver module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.core.resolver import (
    parse_target,
    read_sub_register,
    resolve_lea_expression,
    resolve_value,
    write_sub_register,
)


class TestResolveValue(unittest.TestCase):
    """Test the resolve_value function."""

    def test_resolve_direct_hex(self):
        """Test resolution of direct hex values."""
        ws = blank_worksheet()

        assert resolve_value("0x12345678", ws) == "0x12345678"
        assert resolve_value("0xdeadbeef", ws) == "0xdeadbeef"
        assert resolve_value("0x00000000", ws) == "0x00000000"

    def test_resolve_register(self):
        """Test resolution of register values."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"
        ws["registers"]["EBX"] = "0x12345678"

        assert resolve_value("EAX", ws) == "0xdeadbeef"
        assert resolve_value("EBX", ws) == "0x12345678"
        assert resolve_value("eax", ws) == "0xdeadbeef"  # Case insensitive
        assert resolve_value("ECX", ws) == "0x00000000"  # Default value

    def test_resolve_named_value(self):
        """Test resolution of named values."""
        ws = blank_worksheet()
        ws["named"]["shellgen"] = "0x00501000"
        ws["named"]["base_addr"] = "0x10000000"

        assert resolve_value("shellgen", ws) == "0x00501000"
        assert resolve_value("base_addr", ws) == "0x10000000"

    def test_resolve_stack_offset(self):
        """Test resolution of stack offsets."""
        ws = blank_worksheet()
        ws["stack"]["+0x00"] = "0xdeadbeef"
        ws["stack"]["+0x10"] = "0x12345678"
        ws["stack"]["-0x04"] = "0xabcdef00"

        assert resolve_value("ESP+0x00", ws) == "0xdeadbeef"
        assert resolve_value("[ESP+0x10]", ws) == "0x12345678"
        assert resolve_value("esp+0x00", ws) == "0xdeadbeef"  # Case insensitive
        assert resolve_value("ESP-0x04", ws) == "0xabcdef00"

    def test_resolve_dereferenced_register(self):
        """Test resolution of dereferenced registers."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x01000000"
        ws["registers"]["ECX"] = "0x01000010"  # Points to ESP+0x10
        ws["stack"]["+0x10"] = "0xdeadbeef"

        assert resolve_value("[ECX]", ws) == "0xdeadbeef"

    def test_resolve_arithmetic_addition(self):
        """Test resolution of arithmetic expressions (addition)."""
        ws = blank_worksheet()
        ws["named"]["base"] = "0x10000000"

        result = resolve_value("base+0x100", ws)
        assert result == "0x10000100"

    def test_resolve_arithmetic_subtraction(self):
        """Test resolution of arithmetic expressions (subtraction)."""
        ws = blank_worksheet()
        ws["named"]["base"] = "0x10000100"

        result = resolve_value("base-0x50", ws)
        assert result == "0x100000b0"

    def test_resolve_empty_string(self):
        """Test resolution of empty string returns None."""
        ws = blank_worksheet()
        assert resolve_value("", ws) is None
        assert resolve_value("   ", ws) is None

    def test_resolve_nonexistent_named(self):
        """Test resolution of non-existent named value returns None."""
        ws = blank_worksheet()
        assert resolve_value("nonexistent", ws) is None

    def test_resolve_stack_offset_missing(self):
        """Test resolution of ESP+offset uses arithmetic when stack offset is missing."""
        ws = blank_worksheet()
        # ESP is 0x00000000 by default, so ESP+0x100 resolves via arithmetic
        assert resolve_value("ESP+0x100", ws) == "0x00000100"


class TestParseTarget(unittest.TestCase):
    """Test the parse_target function."""

    def test_parse_register(self):
        """Test parsing of register targets."""
        assert parse_target("EAX") == ("reg", "EAX")
        assert parse_target("EBX") == ("reg", "EBX")
        assert parse_target("eax") == ("reg", "EAX")  # Case normalized
        assert parse_target("ESP") == ("reg", "ESP")
        assert parse_target("EIP") == ("reg", "EIP")

    def test_parse_all_registers(self):
        """Test parsing of all valid registers."""
        registers = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]

        for reg in registers:
            tgt_type, tgt_key = parse_target(reg)
            assert tgt_type == "reg"
            assert tgt_key == reg

    def test_parse_stack_offset(self):
        """Test parsing of stack offset targets."""
        assert parse_target("ESP+0x10") == ("stack", "+0x10")
        assert parse_target("[ESP+0x10]") == ("stack", "+0x10")
        assert parse_target(
            "esp+0x00",
        ) == (
            "stack",
            "+0x00",
        )  # Case insensitive
        assert parse_target("ESP-0x04") == ("stack", "-0x04")

    def test_parse_dereferenced_register(self):
        """Test parsing of dereferenced register targets."""
        assert parse_target("[EAX]") == ("deref", "EAX")
        assert parse_target("[ECX]") == ("deref", "ECX")
        assert parse_target("[eax]") == ("deref", "EAX")  # Case normalized
        assert parse_target("[EIP]") == ("deref", "EIP")

    def test_parse_named_value(self):
        """Test parsing of named value targets."""
        assert parse_target("shellgen") == ("named", "shellgen")
        assert parse_target("base_addr") == ("named", "base_addr")
        assert parse_target("test123") == ("named", "test123")

    def test_parse_preserves_case_for_named(self):
        """Test that named values preserve original case."""
        assert parse_target("myValue") == ("named", "myValue")
        assert parse_target("MyValue") == ("named", "MyValue")

    def test_parse_sub_register_al(self):
        """Test parsing sub-register AL as subreg type."""
        assert parse_target("AL") == ("subreg", "AL")

    def test_parse_sub_register_ax(self):
        """Test parsing sub-register AX as subreg type."""
        assert parse_target("AX") == ("subreg", "AX")

    def test_parse_sub_register_dh(self):
        """Test parsing sub-register DH as subreg type."""
        assert parse_target("DH") == ("subreg", "DH")

    def test_parse_sub_register_si(self):
        """Test parsing 16-bit register SI as subreg type."""
        assert parse_target("SI") == ("subreg", "SI")

    def test_parse_sub_register_bp(self):
        """Test parsing 16-bit register BP as subreg type."""
        assert parse_target("BP") == ("subreg", "BP")

    def test_parse_eax_still_reg(self):
        """32-bit registers should still parse as 'reg' type."""
        assert parse_target("EAX") == ("reg", "EAX")


class TestReadSubRegister(unittest.TestCase):
    """Test reading sub-registers from 32-bit parents."""

    def test_read_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"
        assert read_sub_register("AL", ws) == "0x78"

    def test_read_ah(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"
        assert read_sub_register("AH", ws) == "0x56"

    def test_read_ax(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"
        assert read_sub_register("AX", ws) == "0x5678"

    def test_read_bl(self):
        ws = blank_worksheet()
        ws["registers"]["EBX"] = "0xaabbccdd"
        assert read_sub_register("BL", ws) == "0xdd"

    def test_read_bh(self):
        ws = blank_worksheet()
        ws["registers"]["EBX"] = "0xaabbccdd"
        assert read_sub_register("BH", ws) == "0xcc"

    def test_read_cx(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0xffff1234"
        assert read_sub_register("CX", ws) == "0x1234"

    def test_read_si(self):
        ws = blank_worksheet()
        ws["registers"]["ESI"] = "0xabcd0042"
        assert read_sub_register("SI", ws) == "0x0042"

    def test_read_sp(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        assert read_sub_register("SP", ws) == "0xff00"

    def test_read_unknown_returns_none(self):
        ws = blank_worksheet()
        assert read_sub_register("EAX", ws) is None  # Not a sub-register
        assert read_sub_register("XYZ", ws) is None


class TestWriteSubRegister(unittest.TestCase):
    """Test writing to sub-registers (merge into parent)."""

    def test_write_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345600"
        write_sub_register("AL", "0x78", ws)
        assert ws["registers"]["EAX"] == "0x12345678"

    def test_write_ah(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12340078"
        write_sub_register("AH", "0x56", ws)
        assert ws["registers"]["EAX"] == "0x12345678"

    def test_write_ax(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12340000"
        write_sub_register("AX", "0x5678", ws)
        assert ws["registers"]["EAX"] == "0x12345678"

    def test_write_al_preserves_upper(self):
        """Writing AL should not affect upper 24 bits."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabbccdd"
        write_sub_register("AL", "0x41", ws)
        assert ws["registers"]["EAX"] == "0xaabbcc41"

    def test_write_ah_preserves_other_bits(self):
        """Writing AH should not affect bits outside 8-15."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabbccdd"
        write_sub_register("AH", "0x41", ws)
        assert ws["registers"]["EAX"] == "0xaabb41dd"

    def test_write_ax_preserves_upper(self):
        """Writing AX should not affect upper 16 bits."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabb0000"
        write_sub_register("AX", "0x1234", ws)
        assert ws["registers"]["EAX"] == "0xaabb1234"

    def test_write_dl(self):
        ws = blank_worksheet()
        ws["registers"]["EDX"] = "0x00000000"
        write_sub_register("DL", "0xff", ws)
        assert ws["registers"]["EDX"] == "0x000000ff"


class TestResolveValueSubRegisters(unittest.TestCase):
    """Test resolve_value() with sub-registers."""

    def test_resolve_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x000000ff"
        assert resolve_value("AL", ws) == "0xff"

    def test_resolve_ax_case_insensitive(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x0000abcd"
        assert resolve_value("ax", ws) == "0xabcd"

    def test_resolve_ch(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00001200"
        assert resolve_value("CH", ws) == "0x12"


class TestResolveLeaExpression(unittest.TestCase):
    """Test the LEA bracket expression resolver."""

    def test_lea_simple_reg(self):
        """[ecx] -- just the register value."""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00401000"
        assert resolve_lea_expression("[ecx]", ws) == "0x00401000"

    def test_lea_reg_plus_offset(self):
        """[ecx+0x10]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00401000"
        assert resolve_lea_expression("[ecx+0x10]", ws) == "0x00401010"

    def test_lea_reg_minus_offset(self):
        """[ecx-0x10]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00401010"
        assert resolve_lea_expression("[ecx-0x10]", ws) == "0x00401000"

    def test_lea_reg_plus_reg(self):
        """[ecx+edx]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00001000"
        assert resolve_lea_expression("[ecx+edx]", ws) == "0x00401000"

    def test_lea_reg_plus_reg_times_scale(self):
        """[ecx+edx*4]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00000010"
        assert resolve_lea_expression("[ecx+edx*4]", ws) == "0x00400040"

    def test_lea_reg_plus_reg_times_scale_plus_offset(self):
        """[ecx+edx*4+0x10]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00000010"
        assert resolve_lea_expression("[ecx+edx*4+0x10]", ws) == "0x00400050"

    def test_lea_reg_plus_reg_plus_offset(self):
        """[ecx+edx+0x10]"""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00001000"
        assert resolve_lea_expression("[ecx+edx+0x10]", ws) == "0x00401010"

    def test_lea_scale_2(self):
        """[eax+ecx*2]"""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00100000"
        ws["registers"]["ECX"] = "0x00000008"
        assert resolve_lea_expression("[eax+ecx*2]", ws) == "0x00100010"

    def test_lea_scale_8(self):
        """[eax+ecx*8]"""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00100000"
        ws["registers"]["ECX"] = "0x00000002"
        assert resolve_lea_expression("[eax+ecx*8]", ws) == "0x00100010"

    def test_lea_overflow_wraps(self):
        """LEA result should wrap at 32 bits."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"
        assert resolve_lea_expression("[eax+0x01]", ws) == "0x00000000"

    def test_lea_no_brackets(self):
        """Should handle expression without brackets."""
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00401000"
        assert resolve_lea_expression("ecx+0x10", ws) == "0x00401010"

    def test_lea_unknown_reg_returns_none(self):
        ws = blank_worksheet()
        assert resolve_lea_expression("[xyz]", ws) is None
