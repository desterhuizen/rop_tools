"""
Unit tests for rop/core/gadget.py

Tests the Gadget dataclass and its methods for analyzing
ROP gadgets including instruction parsing, register analysis,
and bad character detection.
"""
import unittest
from rop.core.gadget import Gadget


class TestGadgetBasics(unittest.TestCase):
    """Test basic Gadget functionality"""

    def test_gadget_creation(self):
        """Test creating a gadget instance"""
        g = Gadget(
            address="0x12345678",
            instructions=["pop eax", "ret"],
            raw_line="0x12345678: pop eax ; ret ; (1 found)",
            count=1
        )
        assert g.address == "0x12345678"
        assert len(g.instructions) == 2
        assert g.count == 1

    def test_get_instruction_chain(self):
        """Test instruction chain formatting"""
        g = Gadget(
            address="0x12345678",
            instructions=["pop eax", "pop ebx", "ret"],
            raw_line="test",
            count=1
        )
        assert g.get_instruction_chain() == "pop eax ; pop ebx ; ret"

    def test_get_first_instruction(self):
        """Test getting first instruction"""
        g = Gadget(
            address="0x12345678",
            instructions=["pop eax", "pop ebx", "ret"],
            raw_line="test",
            count=1
        )
        assert g.get_first_instruction() == "pop eax"

    def test_get_last_instruction(self):
        """Test getting last instruction"""
        g = Gadget(
            address="0x12345678",
            instructions=["pop eax", "pop ebx", "ret"],
            raw_line="test",
            count=1
        )
        assert g.get_last_instruction() == "ret"

    def test_empty_instructions(self):
        """Test gadget with no instructions"""
        g = Gadget(
            address="0x12345678",
            instructions=[],
            raw_line="test",
            count=1
        )
        assert g.get_first_instruction() == ""
        assert g.get_last_instruction() == ""
        assert g.get_instruction_chain() == ""


class TestBadCharacterDetection(unittest.TestCase):
    """Test bad character detection in gadget addresses"""

    def test_contains_no_bad_chars(self):
        """Test address with no bad characters"""
        g = Gadget(
            address="0x12345678",
            instructions=["pop eax", "ret"],
            raw_line="test",
            count=1
        )
        bad_chars = {"00", "0a", "0d"}
        assert not g.contains_bad_chars(bad_chars)

    def test_contains_bad_char_null(self):
        """Test address containing null byte"""
        g = Gadget(
            address="0x00123456",
            instructions=["pop eax", "ret"],
            raw_line="test",
            count=1
        )
        bad_chars = {"00"}
        assert g.contains_bad_chars(bad_chars)

    def test_contains_bad_char_newline(self):
        """Test address containing newline byte"""
        g = Gadget(
            address="0x1234560a",
            instructions=["pop eax", "ret"],
            raw_line="test",
            count=1
        )
        bad_chars = {"0a"}
        assert g.contains_bad_chars(bad_chars)

    def test_multiple_bad_chars(self):
        """Test address with multiple bad characters"""
        g = Gadget(
            address="0x00340a56",
            instructions=["pop eax", "ret"],
            raw_line="test",
            count=1
        )
        bad_chars = {"00", "0a", "0d"}
        assert g.contains_bad_chars(bad_chars)


class TestRegisterAnalysis(unittest.TestCase):
    """Test register extraction and analysis"""

    def test_get_affected_registers_32bit(self):
        """Test extracting affected registers (32-bit)"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, ebx", "add ecx, edx"],
            raw_line="test",
            count=1
        )
        regs = g.get_affected_registers()
        assert "eax" in regs
        assert "ebx" in regs
        assert "ecx" in regs
        assert "edx" in regs

    def test_get_affected_registers_64bit(self):
        """Test extracting affected registers (64-bit)"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov rax, rbx", "pop rdi"],
            raw_line="test",
            count=1
        )
        regs = g.get_affected_registers()
        assert "rax" in regs
        assert "rbx" in regs
        assert "rdi" in regs

    def test_get_modified_registers_mov(self):
        """Test extracting modified registers with mov"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, ebx", "ret"],
            raw_line="test",
            count=1
        )
        modified = g.get_modified_registers()
        assert "eax" in modified
        assert "ebx" not in modified  # ebx is source, not destination

    def test_get_modified_registers_pop(self):
        """Test extracting modified registers with pop"""
        g = Gadget(
            address="0x12345678",
            instructions=["pop eax", "pop ebx", "ret"],
            raw_line="test",
            count=1
        )
        modified = g.get_modified_registers()
        assert "eax" in modified
        assert "ebx" in modified

    def test_get_modified_registers_arithmetic(self):
        """Test extracting modified registers with arithmetic ops"""
        g = Gadget(
            address="0x12345678",
            instructions=["add eax, 0x10", "sub ebx, ecx"],
            raw_line="test",
            count=1
        )
        modified = g.get_modified_registers()
        assert "eax" in modified
        assert "ebx" in modified
        assert "ecx" not in modified  # ecx is source

    def test_get_modified_registers_xchg(self):
        """Test extracting modified registers with xchg"""
        g = Gadget(
            address="0x12345678",
            instructions=["xchg eax, ebx", "ret"],
            raw_line="test",
            count=1
        )
        modified = g.get_modified_registers()
        assert "eax" in modified
        assert "ebx" in modified


class TestDereferencedRegisters(unittest.TestCase):
    """Test dereferenced register detection"""

    def test_get_dereferenced_simple(self):
        """Test simple dereferenced register [eax]"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, [ebx]", "ret"],
            raw_line="test",
            count=1
        )
        derefs = g.get_dereferenced_registers()
        assert "ebx" in derefs

    def test_get_dereferenced_with_offset(self):
        """Test dereferenced register with offset [eax+4]"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, [ebx+4]", "ret"],
            raw_line="test",
            count=1
        )
        derefs = g.get_dereferenced_registers()
        assert "ebx" in derefs

    def test_get_dereferenced_64bit(self):
        """Test dereferenced 64-bit register [rsp+8]"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov rax, [rsp+8]", "ret"],
            raw_line="test",
            count=1
        )
        derefs = g.get_dereferenced_registers()
        assert "rsp" in derefs

    def test_get_dereferenced_multiple(self):
        """Test multiple dereferenced registers"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, [ebx]", "add ecx, [edx+8]"],
            raw_line="test",
            count=1
        )
        derefs = g.get_dereferenced_registers()
        assert "ebx" in derefs
        assert "edx" in derefs

    def test_has_dereferenced_register_any(self):
        """Test checking for any dereferenced register"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, [ebx]", "ret"],
            raw_line="test",
            count=1
        )
        assert g.has_dereferenced_register()

    def test_has_dereferenced_register_specific(self):
        """Test checking for specific dereferenced register"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, [ebx]", "ret"],
            raw_line="test",
            count=1
        )
        assert g.has_dereferenced_register("ebx")
        assert not g.has_dereferenced_register("eax")

    def test_no_dereferenced_registers(self):
        """Test gadget with no dereferenced registers"""
        g = Gadget(
            address="0x12345678",
            instructions=["mov eax, ebx", "ret"],
            raw_line="test",
            count=1
        )
        assert not g.has_dereferenced_register()
        derefs = g.get_dereferenced_registers()
        assert len(derefs) == 0