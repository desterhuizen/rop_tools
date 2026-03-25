"""
Unit tests for rop.core.instructions module.
"""

import unittest

from rop.core.instructions import (
    BAD_INSTRUCTION_CATEGORIES,
    CATEGORY_LABELS,
    classify_bad_instruction,
    get_flat_bad_instructions,
)


class TestClassifyBadInstruction(unittest.TestCase):
    """Test classify_bad_instruction()."""

    def test_privileged_instructions(self):
        for op in ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt", "lldt",
                    "invlpg", "invd", "swapgs", "wbinvd"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "PRIVILEGED", f"{op} should be PRIVILEGED")

    def test_privileged_mov_cr(self):
        result = classify_bad_instruction("mov", ["cr0", "eax"])
        self.assertEqual(result, "PRIVILEGED")

    def test_privileged_mov_dr(self):
        result = classify_bad_instruction("mov", ["dr7", "eax"])
        self.assertEqual(result, "PRIVILEGED")

    def test_privileged_mov_tr(self):
        result = classify_bad_instruction("mov", ["tr6", "eax"])
        self.assertEqual(result, "PRIVILEGED")

    def test_normal_mov_is_not_bad(self):
        result = classify_bad_instruction("mov", ["eax", "ebx"])
        self.assertIsNone(result)

    def test_io_instructions(self):
        for op in ["in", "ins", "insb", "insw", "insd",
                    "out", "outs", "outsb", "outsw", "outsd"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "I/O", f"{op} should be I/O")

    def test_interrupt_instructions(self):
        for op in ["int", "int3", "into", "iret", "iretd",
                    "cli", "sti", "syscall", "sysenter", "sysret", "sysexit"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "INTERRUPT", f"{op} should be INTERRUPT")

    def test_control_flow_instructions(self):
        for op in ["call", "jmp", "ja", "jae", "jne", "jz", "loop", "loopne"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "CONTROL FLOW", f"{op} should be CONTROL FLOW")

    def test_stack_frame_instructions(self):
        for op in ["leave", "enter"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "STACK FRAME", f"{op} should be STACK FRAME")

    def test_flags_instructions(self):
        for op in ["pushf", "pushfd", "popf", "popfd"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "FLAGS", f"{op} should be FLAGS")

    def test_sync_instructions(self):
        for op in ["lock", "wait", "fwait"]:
            result = classify_bad_instruction(op)
            self.assertEqual(result, "SYNC/PREFIX", f"{op} should be SYNC/PREFIX")

    def test_good_instructions_return_none(self):
        for op in ["mov", "add", "sub", "xor", "pop", "push", "inc", "dec",
                    "neg", "not", "and", "or", "shl", "shr", "nop", "ret",
                    "lea", "xchg", "cdq", "movzx"]:
            result = classify_bad_instruction(op)
            self.assertIsNone(result, f"{op} should NOT be classified as bad")

    def test_unknown_instruction_returns_none(self):
        result = classify_bad_instruction("foobar")
        self.assertIsNone(result)

    def test_no_operands_mov_is_safe(self):
        """mov without operands should not match privileged_mov."""
        result = classify_bad_instruction("mov")
        self.assertIsNone(result)


class TestGetFlatBadInstructions(unittest.TestCase):
    """Test get_flat_bad_instructions()."""

    def test_returns_list(self):
        result = get_flat_bad_instructions()
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)

    def test_contains_key_entries(self):
        result = get_flat_bad_instructions()
        # Check representative entries from each category
        self.assertIn("hlt", result)
        self.assertIn("mov cr", result)
        self.assertIn("cli", result)
        self.assertIn("call", result)
        self.assertIn("jmp", result)
        self.assertIn("leave", result)
        self.assertIn("lock", result)

    def test_in_has_trailing_space(self):
        """'in ' must have trailing space to avoid matching 'inc'."""
        result = get_flat_bad_instructions()
        self.assertIn("in ", result)
        # 'in' without space should NOT be in the list
        self.assertNotIn("in", result)


class TestCategoryLabels(unittest.TestCase):
    """Verify every category has a label."""

    def test_all_categories_have_labels(self):
        for cat in BAD_INSTRUCTION_CATEGORIES:
            self.assertIn(cat, CATEGORY_LABELS,
                          f"Category '{cat}' missing from CATEGORY_LABELS")


if __name__ == "__main__":
    unittest.main()