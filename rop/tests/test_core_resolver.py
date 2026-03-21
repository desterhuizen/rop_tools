"""
Unit tests for worksheet.core.resolver module.
"""
import unittest
from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.core.resolver import resolve_value, parse_target


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
        """Test resolution of non-existent stack offset returns None."""
        ws = blank_worksheet()
        assert resolve_value("ESP+0x100", ws) is None


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
        assert parse_target("esp+0x00", ) == ("stack", "+0x00")  # Case insensitive
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