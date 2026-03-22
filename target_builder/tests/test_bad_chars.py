"""Tests for bad_chars.py — C++ filter code generation."""

import unittest

from target_builder.src.bad_chars import generate_bad_char_filter
from target_builder.src.config import BadCharAction


class TestBadCharFilter(unittest.TestCase):
    """Test bad character filter generation."""

    def test_empty_bad_chars_passthrough(self):
        result = generate_bad_char_filter([], BadCharAction.DROP)
        self.assertIn("No bad character filtering", result)
        self.assertIn("return len", result)

    def test_drop_mode_structure(self):
        result = generate_bad_char_filter([0x0A, 0x0D], BadCharAction.DROP)
        self.assertIn("drop mode", result)
        self.assertIn("0x0a", result)
        self.assertIn("0x0d", result)
        self.assertIn("write_pos", result)
        self.assertIn("is_bad", result)

    def test_replace_mode_structure(self):
        result = generate_bad_char_filter([0x0A], BadCharAction.REPLACE)
        self.assertIn("replace mode", result)
        self.assertIn("0x41", result)
        self.assertIn("return len", result)

    def test_terminate_mode_structure(self):
        result = generate_bad_char_filter([0x00, 0x0A], BadCharAction.TERMINATE)
        self.assertIn("terminate mode", result)
        self.assertIn("return i", result)

    def test_deduplication(self):
        result = generate_bad_char_filter([0x0A, 0x0A, 0x0D, 0x0D], BadCharAction.DROP)
        # Should have bad_count = 2 (deduplicated)
        self.assertIn("bad_count = 2", result)

    def test_sorted_output(self):
        result = generate_bad_char_filter([0xFF, 0x01, 0x0A], BadCharAction.DROP)
        # Values should appear sorted
        idx_01 = result.index("0x01")
        idx_0a = result.index("0x0a")
        idx_ff = result.index("0xff")
        self.assertLess(idx_01, idx_0a)
        self.assertLess(idx_0a, idx_ff)

    def test_single_bad_char(self):
        result = generate_bad_char_filter([0x25], BadCharAction.DROP)
        self.assertIn("0x25", result)
        self.assertIn("bad_count = 1", result)

    def test_all_modes_return_int(self):
        """All modes must return an int (the filtered length)."""
        for action in BadCharAction:
            result = generate_bad_char_filter([0x0A], action)
            self.assertIn("int filter_bad_chars", result)
            self.assertIn("return", result)

    def test_function_signature(self):
        """All generated functions have the same signature."""
        for action in BadCharAction:
            result = generate_bad_char_filter([0x0A], action)
            self.assertIn("int filter_bad_chars(char* buf, int len)", result)


if __name__ == "__main__":
    unittest.main()
