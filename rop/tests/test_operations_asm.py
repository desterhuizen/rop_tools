"""
Unit tests for worksheet.operations.asm_ops module.
"""

import unittest

from rop.worksheet.core.data import blank_worksheet
from rop.worksheet.operations.asm_ops import (
    cmd_add,
    cmd_and,
    cmd_cdq,
    cmd_dec,
    cmd_inc,
    cmd_lea,
    cmd_lodsd,
    cmd_move,
    cmd_movsxd,
    cmd_movzx,
    cmd_neg,
    cmd_nop,
    cmd_not,
    cmd_or,
    cmd_rol,
    cmd_ror,
    cmd_shl,
    cmd_shr,
    cmd_stosd,
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


class TestSubRegisterInOperations(unittest.TestCase):
    """Test that operations work with sub-registers."""

    def test_mov_to_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabb0000"
        success, _ = cmd_move(ws, "AL", "0x41")
        assert success
        assert ws["registers"]["EAX"] == "0xaabb0041"

    def test_mov_from_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000042"
        success, _ = cmd_move(ws, "EBX", "AL")
        assert success
        assert ws["registers"]["EBX"] == "0x42"

    def test_xor_al_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabbccdd"
        success, _ = cmd_xor(ws, "AL", "AL")
        assert success
        assert ws["registers"]["EAX"] == "0xaabbcc00"

    def test_inc_al(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000041"
        success, _ = cmd_inc(ws, "AL")
        assert success
        assert ws["registers"]["EAX"] == "0x00000042"


class TestCmdAnd(unittest.TestCase):
    """Test the cmd_and operation."""

    def test_and_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xff00ff00"
        success, _ = cmd_and(ws, "EAX", "0x0000ffff")
        assert success
        assert ws["registers"]["EAX"] == "0x0000ff00"

    def test_and_align_esp(self):
        """Common ROP pattern: and esp, 0xfffffff0 to align stack."""
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff7c"
        success, _ = cmd_and(ws, "ESP", "0xfffffff0")
        assert success
        assert ws["registers"]["ESP"] == "0x0019ff70"

    def test_and_unresolvable(self):
        ws = blank_worksheet()
        success, msg = cmd_and(ws, "EAX", "unknown")
        assert not success


class TestCmdOr(unittest.TestCase):
    """Test the cmd_or operation."""

    def test_or_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xff000000"
        success, _ = cmd_or(ws, "EAX", "0x000000ff")
        assert success
        assert ws["registers"]["EAX"] == "0xff0000ff"

    def test_or_set_bit(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        success, _ = cmd_or(ws, "EAX", "0x00000040")
        assert success
        assert ws["registers"]["EAX"] == "0x00000040"


class TestCmdShl(unittest.TestCase):
    """Test the cmd_shl operation."""

    def test_shl_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"
        success, _ = cmd_shl(ws, "EAX", "0x04")
        assert success
        assert ws["registers"]["EAX"] == "0x00000010"

    def test_shl_multiply_by_4(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000010"
        success, _ = cmd_shl(ws, "EAX", "0x02")
        assert success
        assert ws["registers"]["EAX"] == "0x00000040"

    def test_shl_overflow_wraps(self):
        """Shift left should wrap at 32 bits."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x80000000"
        success, _ = cmd_shl(ws, "EAX", "0x01")
        assert success
        assert ws["registers"]["EAX"] == "0x00000000"

    def test_shl_masks_count(self):
        """x86 masks shift count to 5 bits (0-31)."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"
        success, _ = cmd_shl(ws, "EAX", "0x20")
        assert success
        assert ws["registers"]["EAX"] == "0x00000001"


class TestCmdShr(unittest.TestCase):
    """Test the cmd_shr operation."""

    def test_shr_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000010"
        success, _ = cmd_shr(ws, "EAX", "0x04")
        assert success
        assert ws["registers"]["EAX"] == "0x00000001"

    def test_shr_logical(self):
        """SHR is logical (fills with 0, not sign bit)."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x80000000"
        success, _ = cmd_shr(ws, "EAX", "0x01")
        assert success
        assert ws["registers"]["EAX"] == "0x40000000"


class TestCmdRor(unittest.TestCase):
    """Test the cmd_ror operation."""

    def test_ror_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000001"
        success, _ = cmd_ror(ws, "EAX", "0x01")
        assert success
        assert ws["registers"]["EAX"] == "0x80000000"

    def test_ror_by_8(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"
        success, _ = cmd_ror(ws, "EAX", "0x08")
        assert success
        assert ws["registers"]["EAX"] == "0x78123456"


class TestCmdRol(unittest.TestCase):
    """Test the cmd_rol operation."""

    def test_rol_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x80000000"
        success, _ = cmd_rol(ws, "EAX", "0x01")
        assert success
        assert ws["registers"]["EAX"] == "0x00000001"

    def test_rol_by_8(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"
        success, _ = cmd_rol(ws, "EAX", "0x08")
        assert success
        assert ws["registers"]["EAX"] == "0x34567812"


class TestCmdNot(unittest.TestCase):
    """Test the cmd_not operation."""

    def test_not_basic(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        success, _ = cmd_not(ws, "EAX")
        assert success
        assert ws["registers"]["EAX"] == "0xffffffff"

    def test_not_inverse(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xffffffff"
        success, _ = cmd_not(ws, "EAX")
        assert success
        assert ws["registers"]["EAX"] == "0x00000000"

    def test_not_pattern(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xff00ff00"
        success, _ = cmd_not(ws, "EAX")
        assert success
        assert ws["registers"]["EAX"] == "0x00ff00ff"

    def test_not_sub_register(self):
        """NOT should work with sub-registers."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabb00ff"
        success, _ = cmd_not(ws, "AL")
        assert success
        assert ws["registers"]["EAX"] == "0xaabb0000"


class TestCmdCdq(unittest.TestCase):
    """Test the cdq instruction."""

    def test_cdq_zeros_edx_when_eax_positive(self):
        """CDQ zeros EDX when EAX bit 31 is clear."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x7fffffff"
        ws["registers"]["EDX"] = "0xdeadbeef"
        success, _ = cmd_cdq(ws)
        assert success
        assert ws["registers"]["EDX"] == "0x00000000"

    def test_cdq_sets_edx_when_eax_negative(self):
        """CDQ sets EDX to 0xFFFFFFFF when EAX bit 31 is set."""
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x80000000"
        success, _ = cmd_cdq(ws)
        assert success
        assert ws["registers"]["EDX"] == "0xffffffff"

    def test_cdq_eax_at_boundary(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x80000001"
        success, _ = cmd_cdq(ws)
        assert success
        assert ws["registers"]["EDX"] == "0xffffffff"

    def test_cdq_eax_zero(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000000"
        ws["registers"]["EDX"] = "0xffffffff"
        success, _ = cmd_cdq(ws)
        assert success
        assert ws["registers"]["EDX"] == "0x00000000"

    def test_cdq_preserves_eax(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x12345678"
        success, _ = cmd_cdq(ws)
        assert success
        assert ws["registers"]["EAX"] == "0x12345678"


class TestCmdLodsd(unittest.TestCase):
    """Test the lodsd instruction."""

    def test_lodsd_reads_from_esi(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        ws["registers"]["ESI"] = "0x0019ff00"
        ws["stack"]["+0x00"] = "0xdeadbeef"
        success, _ = cmd_lodsd(ws)
        assert success
        assert ws["registers"]["EAX"] == "0xdeadbeef"
        assert ws["registers"]["ESI"] == "0x0019ff04"

    def test_lodsd_fails_when_esi_invalid(self):
        ws = blank_worksheet()
        ws["registers"]["ESI"] = "0x00000000"
        success, _ = cmd_lodsd(ws)
        assert not success

    def test_lodsd_sequential_reads(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        ws["registers"]["ESI"] = "0x0019ff00"
        ws["stack"]["+0x00"] = "0x11111111"
        ws["stack"]["+0x04"] = "0x22222222"
        cmd_lodsd(ws)
        assert ws["registers"]["EAX"] == "0x11111111"
        cmd_lodsd(ws)
        assert ws["registers"]["EAX"] == "0x22222222"


class TestCmdStosd(unittest.TestCase):
    """Test the stosd instruction."""

    def test_stosd_writes_eax_to_edi(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        ws["registers"]["EDI"] = "0x0019ff10"
        ws["registers"]["EAX"] = "0xdeadbeef"
        success, _ = cmd_stosd(ws)
        assert success
        assert ws["stack"]["+0x10"] == "0xdeadbeef"
        assert ws["registers"]["EDI"] == "0x0019ff14"

    def test_stosd_fails_when_edi_invalid(self):
        ws = blank_worksheet()
        ws["registers"]["EDI"] = "0x00000000"
        ws["registers"]["EAX"] = "0xdeadbeef"
        success, _ = cmd_stosd(ws)
        assert not success

    def test_stosd_sequential_writes(self):
        ws = blank_worksheet()
        ws["registers"]["ESP"] = "0x0019ff00"
        ws["registers"]["EDI"] = "0x0019ff00"
        ws["registers"]["EAX"] = "0x41414141"
        cmd_stosd(ws)
        assert ws["stack"]["+0x00"] == "0x41414141"
        ws["registers"]["EAX"] = "0x42424242"
        cmd_stosd(ws)
        assert ws["stack"]["+0x04"] == "0x42424242"


class TestCmdNop(unittest.TestCase):
    """Test the nop instruction."""

    def test_nop_succeeds(self):
        ws = blank_worksheet()
        success, _ = cmd_nop(ws)
        assert success

    def test_nop_changes_nothing(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xdeadbeef"
        ws["registers"]["ESP"] = "0x0019ff00"
        cmd_nop(ws)
        assert ws["registers"]["EAX"] == "0xdeadbeef"
        assert ws["registers"]["ESP"] == "0x0019ff00"


class TestCmdMovzx(unittest.TestCase):
    """Test the movzx instruction."""

    def test_movzx_byte_to_dword(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabbccdd"
        success, _ = cmd_movzx(ws, "EBX", "AL")
        assert success
        assert ws["registers"]["EBX"] == "0x000000dd"

    def test_movzx_word_to_dword(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0xaabb1234"
        success, _ = cmd_movzx(ws, "ECX", "AX")
        assert success
        assert ws["registers"]["ECX"] == "0x00001234"

    def test_movzx_high_byte(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x0000ff00"
        success, _ = cmd_movzx(ws, "EBX", "AH")
        assert success
        assert ws["registers"]["EBX"] == "0x000000ff"

    def test_movzx_hex_immediate(self):
        ws = blank_worksheet()
        success, _ = cmd_movzx(ws, "EAX", "0xff")
        assert success
        assert ws["registers"]["EAX"] == "0x000000ff"


class TestCmdMovsxd(unittest.TestCase):
    """Test the movsxd instruction."""

    def test_movsxd_positive_byte(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x0000007f"
        success, _ = cmd_movsxd(ws, "EBX", "AL")
        assert success
        assert ws["registers"]["EBX"] == "0x0000007f"

    def test_movsxd_negative_byte(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00000080"
        success, _ = cmd_movsxd(ws, "EBX", "AL")
        assert success
        assert ws["registers"]["EBX"] == "0xffffff80"

    def test_movsxd_positive_word(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00007fff"
        success, _ = cmd_movsxd(ws, "EBX", "AX")
        assert success
        assert ws["registers"]["EBX"] == "0x00007fff"

    def test_movsxd_negative_word(self):
        ws = blank_worksheet()
        ws["registers"]["EAX"] = "0x00008000"
        success, _ = cmd_movsxd(ws, "EBX", "AX")
        assert success
        assert ws["registers"]["EBX"] == "0xffff8000"

    def test_movsxd_ff_byte(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x000000ff"
        success, _ = cmd_movsxd(ws, "EAX", "CL")
        assert success
        assert ws["registers"]["EAX"] == "0xffffffff"


class TestCmdLea(unittest.TestCase):
    """Test the lea command."""

    def test_lea_basic(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00401000"
        success, _ = cmd_lea(ws, "EAX", "[ecx+0x10]")
        assert success
        assert ws["registers"]["EAX"] == "0x00401010"

    def test_lea_reg_plus_reg(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00001234"
        success, _ = cmd_lea(ws, "EAX", "[ecx+edx]")
        assert success
        assert ws["registers"]["EAX"] == "0x00401234"

    def test_lea_complex(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00400000"
        ws["registers"]["EDX"] = "0x00000004"
        success, _ = cmd_lea(ws, "EAX", "[ecx+edx*4+0x08]")
        assert success
        assert ws["registers"]["EAX"] == "0x00400018"

    def test_lea_invalid_expression(self):
        ws = blank_worksheet()
        success, _ = cmd_lea(ws, "EAX", "[unknown_reg]")
        assert not success

    def test_lea_to_subreg(self):
        ws = blank_worksheet()
        ws["registers"]["ECX"] = "0x00000010"
        ws["registers"]["EAX"] = "0xaabb0000"
        success, _ = cmd_lea(ws, "AX", "[ecx+0x05]")
        assert success
        assert ws["registers"]["EAX"] == "0xaabb0015"
