"""
Integration tests for the ROP worksheet.

These tests verify that all components work correctly together,
ensuring backward compatibility after refactoring.
"""
import unittest
from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.core.resolver import resolve_value, parse_target
from rop.worksheet.operations.asm_ops import cmd_move, cmd_add, cmd_xor
from rop.worksheet.operations.stack_ops import cmd_push, cmd_pop
from rop.worksheet.operations.quick_ops import cmd_set, cmd_clear
from rop.worksheet.gadgets.library import cmd_gadget_add
from rop.worksheet.gadgets.processor import process_gadget
from rop.worksheet.chain.manager import cmd_chain_add
from rop.worksheet.io.windbg import cmd_import_regs



def test_core_integration():
    """Test core data structures."""
    print("Testing core data structures...")
    ws = blank_worksheet()
    assert "registers" in ws
    assert "stack" in ws
    assert "named" in ws
    assert "gadgets" in ws
    assert "chain" in ws
    assert ws["registers"]["EAX"] == "0x00000000"
    print("✓ Core data structures OK")



def test_resolver_integration():
    """Test value resolution."""
    print("\nTesting value resolution...")
    ws = blank_worksheet()
    ws["registers"]["EAX"] = "0xdeadbeef"
    ws["named"]["shellgen"] = "0x00501000"

    # Test register resolution
    assert resolve_value("EAX", ws) == "0xdeadbeef"

    # Test named value resolution
    assert resolve_value("shellgen", ws) == "0x00501000"

    # Test hex value
    assert resolve_value("0x12345678", ws) == "0x12345678"

    # Test target parsing
    assert parse_target("EAX") == ("reg", "EAX")
    assert parse_target("ESP+0x10") == ("stack", "+0x10")
    assert parse_target("shellgen") == ("named", "shellgen")

    print("✓ Value resolution OK")



def test_operations_integration():
    """Test ASM operations."""
    print("\nTesting ASM operations...")
    ws = blank_worksheet()

    # Test mov
    success, msg = cmd_move(ws, "EAX", "0xdeadbeef")
    assert success
    assert ws["registers"]["EAX"] == "0xdeadbeef"

    # Test add
    success, msg = cmd_add(ws, "EAX", "0x1")
    assert success
    assert ws["registers"]["EAX"] == "0xdeadbef0"

    # Test xor (zero out)
    success, msg = cmd_xor(ws, "EAX", "EAX")
    assert success
    assert ws["registers"]["EAX"] == "0x00000000"

    print("✓ ASM operations OK")



def test_stack_ops_integration():
    """Test stack operations."""
    print("\nTesting stack operations...")
    ws = blank_worksheet()
    ws["registers"]["ESP"] = "0x01000000"

    # Test push
    success, msg = cmd_push(ws, "0xdeadbeef")
    assert success
    assert ws["registers"]["ESP"] == "0x00fffffc"  # ESP-4
    assert ws["stack"]["+0x00"] == "0xdeadbeef"

    # Test pop
    success, msg = cmd_pop(ws, "EAX")
    assert success
    assert ws["registers"]["ESP"] == "0x01000000"  # ESP+4
    assert ws["registers"]["EAX"] == "0xdeadbeef"

    print("✓ Stack operations OK")



def test_gadgets_integration():
    """Test gadget processing."""
    print("\nTesting gadget processing...")
    ws = blank_worksheet()

    # Add gadget to library
    success, msg = cmd_gadget_add(ws, "0x10001234", "pop eax ; ret")
    assert success
    assert "0x10001234" in ws["gadgets"]

    # Test gadget processing
    ws["registers"]["ESP"] = "0x01000000"
    ws["stack"]["+0x00"] = "0xdeadbeef"

    executed = process_gadget(ws, "pop eax ; ret", "0x10001234")
    assert len(executed) == 1
    assert "pop eax" in executed[0]
    assert ws["registers"]["EAX"] == "0xdeadbeef"

    print("✓ Gadget processing OK")



def test_chain_integration():
    """Test ROP chain management."""
    print("\nTesting ROP chain management...")
    ws = blank_worksheet()

    # Add gadget first
    cmd_gadget_add(ws, "0x10001234", "pop eax ; ret")

    # Add to chain by gadget ID
    success, msg = cmd_chain_add(ws, "G1")
    assert success
    assert len(ws["chain"]) == 1
    assert ws["chain"][0]["type"] == "address"
    assert ws["chain"][0]["value"] == "0x10001234"

    # Add literal value
    success, msg = cmd_chain_add(ws, "0xdeadbeef")
    assert success
    assert len(ws["chain"]) == 2

    print("✓ ROP chain management OK")



def test_windbg_import_integration():
    """Test WinDbg import."""
    print("\nTesting WinDbg import...")
    ws = blank_worksheet()

    # Test register import
    windbg_output = "eax=00000001 ebx=00000000 ecx=005cdeaa edx=0000034e esi=005c1716 edi=010237f8"
    success, msg = cmd_import_regs(ws, windbg_output)
    assert success
    assert ws["registers"]["EAX"] == "0x00000001"
    assert ws["registers"]["EBX"] == "0x00000000"
    assert ws["registers"]["ECX"] == "0x005cdeaa"

    print("✓ WinDbg import OK")



def test_quick_ops_integration():
    """Test quick operations."""
    print("\nTesting quick operations...")
    ws = blank_worksheet()

    # Test set
    success, msg = cmd_set(ws, "EAX", "0x12345678")
    assert success
    assert ws["registers"]["EAX"] == "0x12345678"

    # Test clear
    success, msg = cmd_clear(ws, "EAX")
    assert success
    assert ws["registers"]["EAX"] == ""

    print("✓ Quick operations OK")