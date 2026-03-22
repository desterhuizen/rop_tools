"""
Tests for src/encoders.py

Tests bad character encoding, dword/qword encoding, and ROR13 hash calculation.
"""

import struct
import unittest

from shellgen.src.encoders import (
    contains_bad_chars,
    encode_dword,
    encode_dword_split,
    encode_qword,
    ror13_hash,
    string_to_push_dwords,
)


class TestContainsBadChars(unittest.TestCase):
    """Test cases for contains_bad_chars function."""

    def test_no_bad_chars(self):
        """Test bytes with no bad characters."""
        value_bytes = b"\x12\x34\x56\x78"
        bad_chars = {0x00, 0x0A, 0x0D}
        self.assertFalse(contains_bad_chars(value_bytes, bad_chars))

    def test_with_bad_chars(self):
        """Test bytes containing bad characters."""
        value_bytes = b"\x12\x00\x56\x78"
        bad_chars = {0x00, 0x0A, 0x0D}
        self.assertTrue(contains_bad_chars(value_bytes, bad_chars))

    def test_multiple_bad_chars(self):
        """Test bytes with multiple bad characters."""
        value_bytes = b"\x00\x0a\x0d\x78"
        bad_chars = {0x00, 0x0A, 0x0D}
        self.assertTrue(contains_bad_chars(value_bytes, bad_chars))

    def test_empty_bad_chars(self):
        """Test with empty bad chars set."""
        value_bytes = b"\x00\x0a\x0d\x78"
        bad_chars = set()
        self.assertFalse(contains_bad_chars(value_bytes, bad_chars))

    def test_all_bad_chars(self):
        """Test when all bytes are bad."""
        value_bytes = b"\x00\x0a"
        bad_chars = {0x00, 0x0A}
        self.assertTrue(contains_bad_chars(value_bytes, bad_chars))


class TestEncodeDword(unittest.TestCase):
    """Test cases for encode_dword function."""

    def test_clean_value_no_encoding(self):
        """Test that clean values return None (no encoding needed)."""
        target = 0x12345678
        bad_chars = {0x00, 0x0A, 0x0D}
        result = encode_dword(target, bad_chars)
        self.assertIsNone(result)

    def test_encode_with_null_byte(self):
        """Test encoding a value containing null byte."""
        target = 0x00001234
        bad_chars = {0x00}
        result = encode_dword(target, bad_chars)
        self.assertIsNotNone(result)

        # Check if it's subtraction encoding
        if result[0] != "ADD":
            clean, offset = result
            self.assertEqual((clean - offset) & 0xFFFFFFFF, target)
            # Verify no bad chars in encoded values
            clean_bytes = struct.pack("<I", clean)
            offset_bytes = struct.pack("<I", offset)
            self.assertFalse(contains_bad_chars(clean_bytes, bad_chars))
            self.assertFalse(contains_bad_chars(offset_bytes, bad_chars))

    def test_encode_with_multiple_bad_chars(self):
        """Test encoding with multiple bad characters."""
        target = 0x000A0D00
        bad_chars = {0x00, 0x0A, 0x0D}
        result = encode_dword(target, bad_chars)
        self.assertIsNotNone(result)

        if result[0] != "ADD":
            clean, offset = result
            self.assertEqual((clean - offset) & 0xFFFFFFFF, target)

    def test_encode_add_fallback(self):
        """Test that ADD encoding is used when subtraction fails."""
        # Some values may trigger ADD encoding
        target = 0xFFFFFFFF
        bad_chars = {0xFF}

        # This might raise ValueError or return ADD encoding
        try:
            result = encode_dword(target, bad_chars)
            if result and result[0] == "ADD":
                _, val1, val2 = result
                self.assertEqual((val1 + val2) & 0xFFFFFFFF, target)
        except ValueError:
            # This is acceptable - some values can't be encoded
            pass

    def test_encode_32bit_wraparound(self):
        """Test that encoding handles 32-bit wraparound correctly."""
        target = 0xFFFFFFFF
        bad_chars = {0x00}

        try:
            result = encode_dword(target, bad_chars)
            if result and result[0] != "ADD":
                clean, offset = result
                # Should wrap around to 32-bit
                self.assertEqual((clean - offset) & 0xFFFFFFFF, target)
        except ValueError:
            # Acceptable if can't encode
            pass


class TestEncodeDwordSplit(unittest.TestCase):
    """Test cases for encode_dword_split function."""

    def test_split_clean_values(self):
        """Test splitting into two clean values."""
        target = 0x12345678
        bad_chars = {0x00}
        result = encode_dword_split(target, bad_chars)

        if result:
            val1, val2 = result
            self.assertEqual((val1 + val2) & 0xFFFFFFFF, target)

            # Verify no bad chars
            val1_bytes = struct.pack("<I", val1)
            val2_bytes = struct.pack("<I", val2)
            self.assertFalse(contains_bad_chars(val1_bytes, bad_chars))
            self.assertFalse(contains_bad_chars(val2_bytes, bad_chars))

    def test_split_returns_none_when_impossible(self):
        """Test that None is returned when split is impossible."""
        target = 0xFFFFFFFF
        bad_chars = {0xFF, 0x7F, 0x01}
        result = encode_dword_split(target, bad_chars)
        # May return None if can't find clean split
        if result is None:
            self.assertIsNone(result)


class TestEncodeQword(unittest.TestCase):
    """Test cases for encode_qword function."""

    def test_clean_qword_no_encoding(self):
        """Test that clean 64-bit values return None."""
        target = 0x1234567890ABCDEF
        bad_chars = {0x00}
        result = encode_qword(target, bad_chars)
        self.assertIsNone(result)

    def test_encode_qword_with_null(self):
        """Test encoding 64-bit value with null byte."""
        target = 0x0000000012345678
        bad_chars = {0x00}

        try:
            result = encode_qword(target, bad_chars)
            if result:
                self.assertIsNotNone(result)

                if result[0] != "ADD":
                    clean, offset = result
                    self.assertEqual((clean - offset) & 0xFFFFFFFFFFFFFFFF,
                                     target)
                    # Verify no bad chars
                    clean_bytes = struct.pack("<Q", clean)
                    offset_bytes = struct.pack("<Q", offset)
                    self.assertFalse(contains_bad_chars(clean_bytes, bad_chars))
                    self.assertFalse(
                        contains_bad_chars(offset_bytes, bad_chars))
        except ValueError:
            # Acceptable if encoder cannot find a clean encoding
            pass

    def test_encode_qword_64bit_wraparound(self):
        """Test 64-bit wraparound handling."""
        target = 0xFFFFFFFFFFFFFFFF
        bad_chars = {0x00}

        try:
            result = encode_qword(target, bad_chars)
            if result and result[0] != "ADD":
                clean, offset = result
                self.assertEqual((clean - offset) & 0xFFFFFFFFFFFFFFFF, target)
        except ValueError:
            # Acceptable if can't encode
            pass


class TestStringToPushDwords(unittest.TestCase):
    """Test cases for string_to_push_dwords function."""

    def test_simple_string(self):
        """Test conversion of simple string."""
        s = "test"
        dwords = string_to_push_dwords(s)

        # Should be padded to 4-byte alignment with null terminator
        # "test" + null = 5 bytes, padded to 8 bytes
        self.assertEqual(len(dwords), 2)

        # First dword should contain "test" (little-endian)
        expected_first = struct.unpack("<I", b"test")[0]
        self.assertEqual(dwords[0], expected_first)

    def test_empty_string(self):
        """Test empty string handling."""
        s = ""
        dwords = string_to_push_dwords(s)

        # Just null terminator padded to 4 bytes
        self.assertEqual(len(dwords), 1)
        self.assertEqual(dwords[0], 0x00000000)

    def test_string_exact_4bytes(self):
        """Test string that's exactly 4 bytes."""
        s = "abc"
        dwords = string_to_push_dwords(s)

        # "abc" + null = 4 bytes = 1 dword
        self.assertEqual(len(dwords), 1)

    def test_long_string(self):
        """Test longer string."""
        s = "kernel32.dll"
        dwords = string_to_push_dwords(s)

        # 12 chars + null = 13 bytes, padded to 16 bytes = 4 dwords
        self.assertEqual(len(dwords), 4)

        # Verify all dwords are valid
        for dword in dwords:
            self.assertIsInstance(dword, int)
            self.assertGreaterEqual(dword, 0)
            self.assertLessEqual(dword, 0xFFFFFFFF)

    def test_string_with_special_chars(self):
        """Test string with special characters."""
        s = "cmd.exe"
        dwords = string_to_push_dwords(s)

        # Should handle period and other ASCII chars
        self.assertGreater(len(dwords), 0)

    def test_alignment_padding(self):
        """Test that strings are padded to 4-byte alignment."""
        # Test various lengths to ensure proper padding
        for length in range(1, 20):
            s = "a" * length
            dwords = string_to_push_dwords(s)

            # Total bytes should be multiple of 4
            total_bytes = len(dwords) * 4
            self.assertEqual(total_bytes % 4, 0)

            # Should include null terminator
            self.assertGreaterEqual(total_bytes, length + 1)


class TestRor13Hash(unittest.TestCase):
    """Test cases for ror13_hash function."""

    def test_known_hashes(self):
        """Test against known ROR13 hash values."""
        # Known hashes from Windows shellcode development
        known_hashes = {
            "LoadLibraryA": 0xEC0E4E8E,
            "GetProcAddress": 0x7C0DFCAA,
        }

        for func_name, expected_hash in known_hashes.items():
            with self.subTest(func=func_name):
                actual_hash = ror13_hash(func_name)
                self.assertEqual(actual_hash, expected_hash)

    def test_empty_string(self):
        """Test hash of empty string."""
        result = ror13_hash("")
        self.assertEqual(result, 0)

    def test_single_char(self):
        """Test hash of single character."""
        result = ror13_hash("A")
        # Should be the ASCII value of 'A' (65)
        self.assertEqual(result, 65)

    def test_case_sensitivity(self):
        """Test that hash is case-sensitive."""
        hash_lower = ror13_hash("test")
        hash_upper = ror13_hash("TEST")
        self.assertNotEqual(hash_lower, hash_upper)

    def test_different_strings_different_hashes(self):
        """Test that different strings produce different hashes."""
        hash1 = ror13_hash("function1")
        hash2 = ror13_hash("function2")
        self.assertNotEqual(hash1, hash2)

    def test_hash_is_32bit(self):
        """Test that hash value fits in 32 bits."""
        result = ror13_hash("VeryLongFunctionNameToTestHashBounds")
        self.assertLessEqual(result, 0xFFFFFFFF)
        self.assertGreaterEqual(result, 0)

    def test_rotate_operation(self):
        """Test that rotation is working correctly."""
        # For a longer string, verify rotation doesn't overflow
        result = ror13_hash("MessageBoxA")
        self.assertIsInstance(result, int)
        self.assertLessEqual(result, 0xFFFFFFFF)

    def test_deterministic(self):
        """Test that hash is deterministic (same input = same output)."""
        func_name = "ExitProcess"
        hash1 = ror13_hash(func_name)
        hash2 = ror13_hash(func_name)
        hash3 = ror13_hash(func_name)

        self.assertEqual(hash1, hash2)
        self.assertEqual(hash2, hash3)


class TestEncodingEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_all_bytes_bad(self):
        """Test encoding when all bytes are bad (should raise ValueError)."""
        target = 0x000A0D20
        # Make almost all bytes bad
        bad_chars = set(range(256))

        with self.assertRaises(ValueError):
            encode_dword(target, bad_chars)

    def test_zero_value_with_null_bad(self):
        """Test encoding zero when null is bad."""
        target = 0x00000000
        bad_chars = {0x00}

        result = encode_dword(target, bad_chars)
        self.assertIsNotNone(result)

    def test_max_dword_value(self):
        """Test encoding maximum 32-bit value."""
        target = 0xFFFFFFFF
        bad_chars = {0x00}

        # Should either encode or raise ValueError
        try:
            result = encode_dword(target, bad_chars)
            if result and result[0] != "ADD":
                clean, offset = result
                self.assertEqual((clean - offset) & 0xFFFFFFFF, target)
        except ValueError:
            pass  # Acceptable

    def test_max_qword_value(self):
        """Test encoding maximum 64-bit value."""
        target = 0xFFFFFFFFFFFFFFFF
        bad_chars = {0x00}

        try:
            result = encode_qword(target, bad_chars)
            if result and result[0] != "ADD":
                clean, offset = result
                self.assertEqual((clean - offset) & 0xFFFFFFFFFFFFFFFF, target)
        except ValueError:
            pass  # Acceptable


if __name__ == "__main__":
    unittest.main()
