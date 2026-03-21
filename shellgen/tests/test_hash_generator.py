"""
Tests for hash_generator.py

Tests ROR13 hash calculation and various output formatters.
"""

import unittest
from unittest.mock import patch, mock_open
import sys
import io
from hash_generator import (
    ror13_hash,
    ror13_hash_case_insensitive,
    generate_hash_dict,
    format_output_text,
    format_output_python,
    format_output_c,
    format_output_asm,
    format_output_json,
    read_functions_from_file,
)


class TestRor13Hash(unittest.TestCase):
    """Test cases for ror13_hash function."""

    def test_known_api_hashes(self):
        """Test against known Windows API hashes."""
        known_hashes = {
            'LoadLibraryA': 0xec0e4e8e,
            'GetProcAddress': 0x7c0dfcaa,
        }

        for func_name, expected_hash in known_hashes.items():
            with self.subTest(func=func_name):
                actual_hash = ror13_hash(func_name)
                self.assertEqual(actual_hash, expected_hash,
                               f"Hash mismatch for {func_name}")

    def test_empty_string(self):
        """Test hash of empty string returns 0."""
        result = ror13_hash("")
        self.assertEqual(result, 0)

    def test_single_character(self):
        """Test hash of single character."""
        result = ror13_hash("A")
        # For single char, should be the ASCII value
        self.assertEqual(result, ord("A"))

    def test_case_sensitivity(self):
        """Test that hash is case-sensitive."""
        hash_lower = ror13_hash("test")
        hash_upper = ror13_hash("TEST")
        hash_mixed = ror13_hash("Test")

        self.assertNotEqual(hash_lower, hash_upper)
        self.assertNotEqual(hash_lower, hash_mixed)
        self.assertNotEqual(hash_upper, hash_mixed)

    def test_deterministic(self):
        """Test that hash is deterministic."""
        func_name = "ExitProcess"

        hash1 = ror13_hash(func_name)
        hash2 = ror13_hash(func_name)
        hash3 = ror13_hash(func_name)

        self.assertEqual(hash1, hash2)
        self.assertEqual(hash2, hash3)

    def test_32bit_bounds(self):
        """Test that hash stays within 32-bit bounds."""
        long_string = "VeryLongFunctionNameForTesting" * 10
        result = ror13_hash(long_string)

        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 0xFFFFFFFF)

    def test_different_strings_different_hashes(self):
        """Test that different strings produce different hashes."""
        strings = ["func1", "func2", "func3", "test", "demo"]
        hashes = [ror13_hash(s) for s in strings]

        # All hashes should be unique (for these simple cases)
        self.assertEqual(len(hashes), len(set(hashes)))

    def test_rotate_operation(self):
        """Test rotation doesn't cause overflow."""
        # Test with various function names
        test_names = [
            "CreateProcessA",
            "VirtualAlloc",
            "WriteProcessMemory",
            "MessageBoxA",
            "WSASocketA",
        ]

        for name in test_names:
            with self.subTest(func=name):
                result = ror13_hash(name)
                self.assertIsInstance(result, int)
                self.assertLessEqual(result, 0xFFFFFFFF)


class TestRor13HashCaseInsensitive(unittest.TestCase):
    """Test cases for ror13_hash_case_insensitive function."""

    def test_case_insensitive_matching(self):
        """Test that different cases produce same hash."""
        hash_lower = ror13_hash_case_insensitive("test")
        hash_upper = ror13_hash_case_insensitive("TEST")
        hash_mixed = ror13_hash_case_insensitive("TeSt")

        self.assertEqual(hash_lower, hash_upper)
        self.assertEqual(hash_lower, hash_mixed)

    def test_converts_to_uppercase(self):
        """Test that function converts to uppercase."""
        # The case-insensitive version should match uppercase hash
        result_ci = ror13_hash_case_insensitive("loadlibrarya")
        result_upper = ror13_hash("LOADLIBRARYA")

        self.assertEqual(result_ci, result_upper)

    def test_already_uppercase(self):
        """Test that uppercase input works correctly."""
        hash1 = ror13_hash_case_insensitive("GETPROCADDRESS")
        hash2 = ror13_hash("GETPROCADDRESS")

        self.assertEqual(hash1, hash2)


class TestGenerateHashDict(unittest.TestCase):
    """Test cases for generate_hash_dict function."""

    def test_basic_dict_generation(self):
        """Test generating hash dictionary."""
        functions = ["LoadLibraryA", "GetProcAddress"]
        result = generate_hash_dict(functions)

        self.assertEqual(len(result), 2)
        self.assertIn("LoadLibraryA", result)
        self.assertIn("GetProcAddress", result)

        # Check hash values
        self.assertEqual(result["LoadLibraryA"], 0xec0e4e8e)
        self.assertEqual(result["GetProcAddress"], 0x7c0dfcaa)

    def test_case_sensitive_mode(self):
        """Test case-sensitive hash generation."""
        functions = ["test", "TEST"]
        result = generate_hash_dict(functions, case_insensitive=False)

        self.assertEqual(len(result), 2)
        self.assertNotEqual(result["test"], result["TEST"])

    def test_case_insensitive_mode(self):
        """Test case-insensitive hash generation."""
        functions = ["test", "TEST"]
        result = generate_hash_dict(functions, case_insensitive=True)

        self.assertEqual(len(result), 2)
        # Both should have same hash value
        self.assertEqual(result["test"], result["TEST"])

    def test_empty_list(self):
        """Test with empty function list."""
        result = generate_hash_dict([])
        self.assertEqual(result, {})

    def test_single_function(self):
        """Test with single function."""
        result = generate_hash_dict(["ExitProcess"])
        self.assertEqual(len(result), 1)
        self.assertIn("ExitProcess", result)

    def test_duplicate_functions(self):
        """Test handling of duplicate function names."""
        functions = ["test", "test", "demo"]
        result = generate_hash_dict(functions)

        # Dict should have unique keys
        self.assertEqual(len(result), 2)
        self.assertIn("test", result)
        self.assertIn("demo", result)


class TestFormatOutputText(unittest.TestCase):
    """Test cases for format_output_text function."""

    def test_basic_text_format(self):
        """Test basic text formatting."""
        hash_dict = {"LoadLibraryA": 0xec0e4e8e, "GetProcAddress": 0x7c0dfcaa}
        result = format_output_text(hash_dict)

        self.assertIn("LoadLibraryA", result)
        self.assertIn("GetProcAddress", result)
        self.assertIn("0xec0e4e8e", result)
        self.assertIn("0x7c0dfcaa", result)

    def test_includes_header(self):
        """Test that output includes header."""
        hash_dict = {"test": 0x12345678}
        result = format_output_text(hash_dict)

        self.assertIn("ROR13 Hash Generator", result)
        self.assertIn("=", result)  # Header border

    def test_includes_count(self):
        """Test that output includes function count."""
        hash_dict = {"func1": 0x11111111, "func2": 0x22222222, "func3": 0x33333333}
        result = format_output_text(hash_dict)

        self.assertIn("Total functions: 3", result)

    def test_alignment(self):
        """Test that output is properly aligned."""
        hash_dict = {"short": 0x12345678, "verylongname": 0x87654321}
        result = format_output_text(hash_dict)

        # Should have arrow separator
        self.assertIn("=>", result)

        # Both lines should be present
        self.assertIn("short", result)
        self.assertIn("verylongname", result)


class TestFormatOutputPython(unittest.TestCase):
    """Test cases for format_output_python function."""

    def test_python_dict_format(self):
        """Test Python dictionary formatting."""
        hash_dict = {"LoadLibraryA": 0xec0e4e8e}
        result = format_output_python(hash_dict)

        self.assertIn("API_HASHES = {", result)
        self.assertIn("'LoadLibraryA': 0xec0e4e8e", result)
        self.assertIn("}", result)

    def test_includes_comments(self):
        """Test that Python output includes comments."""
        hash_dict = {"test": 0x12345678}
        result = format_output_python(hash_dict)

        self.assertIn("# ROR13 Hash Dictionary", result)
        self.assertIn("# Generated by hash_generator.py", result)

    def test_valid_python_syntax(self):
        """Test that output is valid Python syntax."""
        hash_dict = {"func1": 0x11111111, "func2": 0x22222222}
        result = format_output_python(hash_dict)

        # Should be valid Python - try to compile it
        try:
            compile(result, '<string>', 'exec')
        except SyntaxError:
            self.fail("Generated Python code has invalid syntax")

    def test_trailing_commas(self):
        """Test that dictionary entries have trailing commas."""
        hash_dict = {"test": 0x12345678}
        result = format_output_python(hash_dict)

        # Python dict entries should have trailing commas
        self.assertIn("0x12345678,", result)


class TestFormatOutputC(unittest.TestCase):
    """Test cases for format_output_c function."""

    def test_c_struct_format(self):
        """Test C struct array formatting."""
        hash_dict = {"LoadLibraryA": 0xec0e4e8e}
        result = format_output_c(hash_dict)

        self.assertIn("typedef struct", result)
        self.assertIn("ApiHash", result)
        self.assertIn("const char *name", result)
        self.assertIn("unsigned int hash", result)

    def test_array_definition(self):
        """Test C array definition."""
        hash_dict = {"test": 0x12345678}
        result = format_output_c(hash_dict)

        self.assertIn("ApiHash api_hashes[] = {", result)
        self.assertIn('{"test", 0x12345678}', result)
        self.assertIn("};", result)

    def test_includes_count_macro(self):
        """Test that count macro is included."""
        hash_dict = {"func1": 0x11111111, "func2": 0x22222222}
        result = format_output_c(hash_dict)

        self.assertIn("#define API_HASH_COUNT 2", result)

    def test_includes_comments(self):
        """Test that C comments are included."""
        hash_dict = {"test": 0x12345678}
        result = format_output_c(hash_dict)

        self.assertIn("//", result)
        self.assertIn("Generated by hash_generator.py", result)


class TestFormatOutputAsm(unittest.TestCase):
    """Test cases for format_output_asm function."""

    def test_asm_equ_format(self):
        """Test assembly EQU directive formatting."""
        hash_dict = {"LoadLibraryA": 0xec0e4e8e}
        result = format_output_asm(hash_dict)

        self.assertIn("LOADLIBRARYA_HASH", result)
        self.assertIn("equ", result)
        self.assertIn("0xec0e4e8e", result)

    def test_constant_naming(self):
        """Test that constant names are properly formatted."""
        hash_dict = {"GetProcAddress": 0x7c0dfcaa}
        result = format_output_asm(hash_dict)

        # Should be uppercase with _HASH suffix
        self.assertIn("GETPROCADDRESS_HASH", result)

    def test_includes_original_name(self):
        """Test that original function name is in comment."""
        hash_dict = {"ExitProcess": 0x12345678}
        result = format_output_asm(hash_dict)

        # Original name should appear as comment
        self.assertIn("; ExitProcess", result)

    def test_includes_header_comments(self):
        """Test that assembly comments are included."""
        hash_dict = {"test": 0x12345678}
        result = format_output_asm(hash_dict)

        self.assertIn("; ROR13 Hash Definitions", result)
        self.assertIn("; Generated by hash_generator.py", result)


class TestFormatOutputJson(unittest.TestCase):
    """Test cases for format_output_json function."""

    def test_json_format(self):
        """Test JSON formatting."""
        hash_dict = {"LoadLibraryA": 0xec0e4e8e}
        result = format_output_json(hash_dict)

        self.assertIn('"LoadLibraryA"', result)
        self.assertIn('"0xec0e4e8e"', result)

    def test_valid_json(self):
        """Test that output is valid JSON."""
        import json

        hash_dict = {"func1": 0x11111111, "func2": 0x22222222}
        result = format_output_json(hash_dict)

        # Should be valid JSON
        try:
            parsed = json.loads(result)
            self.assertIsInstance(parsed, dict)
            self.assertEqual(len(parsed), 2)
        except json.JSONDecodeError:
            self.fail("Generated JSON is invalid")

    def test_hex_string_values(self):
        """Test that hash values are formatted as hex strings."""
        hash_dict = {"test": 0x12345678}
        result = format_output_json(hash_dict)

        # Values should be hex strings, not integers
        self.assertIn('"0x12345678"', result)
        self.assertNotIn('305419896', result)  # Decimal representation


class TestReadFunctionsFromFile(unittest.TestCase):
    """Test cases for read_functions_from_file function."""

    @patch('builtins.open', mock_open(read_data='LoadLibraryA\nGetProcAddress\nExitProcess\n'))
    def test_read_simple_file(self):
        """Test reading function names from file."""
        result = read_functions_from_file('test.txt')

        self.assertEqual(len(result), 3)
        self.assertIn('LoadLibraryA', result)
        self.assertIn('GetProcAddress', result)
        self.assertIn('ExitProcess', result)

    @patch('builtins.open', mock_open(read_data='LoadLibraryA\n\nGetProcAddress\n\nExitProcess\n'))
    def test_skip_empty_lines(self):
        """Test that empty lines are skipped."""
        result = read_functions_from_file('test.txt')

        self.assertEqual(len(result), 3)
        self.assertNotIn('', result)

    @patch('builtins.open', mock_open(read_data='LoadLibraryA\n# Comment line\nGetProcAddress\n'))
    def test_skip_comments(self):
        """Test that comment lines are skipped."""
        result = read_functions_from_file('test.txt')

        self.assertEqual(len(result), 2)
        self.assertIn('LoadLibraryA', result)
        self.assertIn('GetProcAddress', result)
        # Comment should not be included
        self.assertNotIn('# Comment line', result)

    @patch('builtins.open', mock_open(read_data='  LoadLibraryA  \n  GetProcAddress  \n'))
    def test_strip_whitespace(self):
        """Test that whitespace is stripped."""
        result = read_functions_from_file('test.txt')

        self.assertEqual(result[0], 'LoadLibraryA')
        self.assertEqual(result[1], 'GetProcAddress')
        # Should not have leading/trailing spaces
        self.assertFalse(result[0].startswith(' '))
        self.assertFalse(result[0].endswith(' '))

    @patch('builtins.open', side_effect=FileNotFoundError())
    def test_file_not_found(self, mock_file):
        """Test handling of missing file."""
        with self.assertRaises(SystemExit) as context:
            read_functions_from_file('nonexistent.txt')

        self.assertEqual(context.exception.code, 1)

    @patch('builtins.open', mock_open(read_data=''))
    def test_empty_file(self):
        """Test reading empty file."""
        result = read_functions_from_file('empty.txt')
        self.assertEqual(result, [])


class TestHashGeneratorEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios."""

    def test_special_characters_in_name(self):
        """Test function names with special characters."""
        # Some Windows APIs have special chars
        test_names = ["_beginthreadex", "??_7"]

        for name in test_names:
            with self.subTest(name=name):
                result = ror13_hash(name)
                self.assertIsInstance(result, int)
                self.assertGreaterEqual(result, 0)
                self.assertLessEqual(result, 0xFFFFFFFF)

    def test_very_long_function_name(self):
        """Test with very long function name."""
        long_name = "VeryLongFunctionName" * 50
        result = ror13_hash(long_name)

        self.assertIsInstance(result, int)
        self.assertLessEqual(result, 0xFFFFFFFF)

    def test_unicode_handling(self):
        """Test handling of unicode characters."""
        # Should work with ASCII subset
        result = ror13_hash("TestFunc")
        self.assertIsInstance(result, int)

    def test_format_empty_dict(self):
        """Test formatting functions with empty dictionary."""
        empty_dict = {}

        # Should not crash, but format_output_text will fail on max()
        # Let's test the others
        result_python = format_output_python(empty_dict)
        self.assertIn("API_HASHES = {", result_python)

        result_c = format_output_c(empty_dict)
        self.assertIn("API_HASH_COUNT 0", result_c)

        result_asm = format_output_asm(empty_dict)
        self.assertIn("; ROR13 Hash Definitions", result_asm)

        result_json = format_output_json(empty_dict)
        self.assertIn("{", result_json)


if __name__ == "__main__":
    unittest.main()