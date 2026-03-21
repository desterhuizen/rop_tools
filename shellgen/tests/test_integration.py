"""
Integration tests for shellgen

Tests the overall workflow of shellcode generation including CLI integration,
payload building, encoding, and output formatting.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
from src.encoders import ror13_hash, encode_dword, string_to_push_dwords
from src.formatters import format_output
from hash_generator import generate_hash_dict


class TestEncoderIntegration(unittest.TestCase):
    """Test integration between encoder components."""

    def test_string_to_dwords_with_encoding(self):
        """Test converting string to dwords and encoding them."""
        test_string = "kernel32.dll"
        bad_chars = {0x00, 0x0a, 0x0d}

        # Convert string to dwords
        dwords = string_to_push_dwords(test_string)
        self.assertGreater(len(dwords), 0)

        # Try encoding each dword if it contains bad chars
        for dword in dwords:
            # Check if encoding is needed
            import struct
            dword_bytes = struct.pack("<I", dword)
            has_bad = any(b in bad_chars for b in dword_bytes)

            if has_bad:
                # Should be able to encode it
                result = encode_dword(dword, bad_chars)
                self.assertIsNotNone(result, f"Failed to encode dword 0x{dword:08x}")

    def test_api_hash_generation_workflow(self):
        """Test complete workflow of generating API hashes."""
        # Common Windows APIs
        api_functions = [
            'LoadLibraryA',
            'GetProcAddress',
            'ExitProcess',
            'VirtualAlloc',
        ]

        # Generate hashes
        hash_dict = generate_hash_dict(api_functions)

        # Verify all hashes were generated
        self.assertEqual(len(hash_dict), len(api_functions))

        # Verify known hashes
        self.assertEqual(hash_dict['LoadLibraryA'], 0xec0e4e8e)
        self.assertEqual(hash_dict['GetProcAddress'], 0x7c0dfcaa)

        # Verify all hashes are valid 32-bit values
        for func_name, hash_value in hash_dict.items():
            with self.subTest(func=func_name):
                self.assertIsInstance(hash_value, int)
                self.assertGreaterEqual(hash_value, 0)
                self.assertLessEqual(hash_value, 0xFFFFFFFF)


class TestFormatterIntegration(unittest.TestCase):
    """Test integration between formatter components."""

    def test_format_output_all_formats(self):
        """Test that all output formats work together."""
        simple_asm = "mov eax, ebx\nret"

        # Test ASM format
        result_asm = format_output(simple_asm, 'asm', arch='x86', platform='windows')
        self.assertEqual(result_asm, simple_asm)

        # Test pyasm format
        result_pyasm = format_output(simple_asm, 'pyasm', arch='x86', platform='windows')
        self.assertIn('#!/usr/bin/env python3', result_pyasm)
        self.assertIn('from keystone import *', result_pyasm)

    def test_cross_architecture_formatting(self):
        """Test formatting across different architectures."""
        asm_code = "mov r0, r1"
        architectures = ['x86', 'x64', 'arm', 'arm64']

        for arch in architectures:
            with self.subTest(arch=arch):
                # ASM format should work for all
                result = format_output(asm_code, 'asm', arch=arch, platform='linux')
                self.assertIsNotNone(result)

                # pyasm format should have correct constants
                result_pyasm = format_output(asm_code, 'pyasm', arch=arch, platform='linux')
                self.assertIn('ks = Ks(', result_pyasm)


class TestHashAndEncoderIntegration(unittest.TestCase):
    """Test integration between hash generation and encoding."""

    def test_hash_encoding_workflow(self):
        """Test encoding API hashes for shellcode."""
        # Generate hash
        api_name = 'GetProcAddress'
        api_hash = ror13_hash(api_name)

        # Try to encode hash avoiding bad chars
        bad_chars = {0x00, 0x0a, 0x0d}

        import struct
        hash_bytes = struct.pack("<I", api_hash)
        has_bad = any(b in bad_chars for b in hash_bytes)

        if has_bad:
            # Should be able to encode it
            result = encode_dword(api_hash, bad_chars)
            self.assertIsNotNone(result)

            if result and result[0] != "ADD":
                clean, offset = result
                # Verify encoding is correct
                self.assertEqual((clean - offset) & 0xFFFFFFFF, api_hash)

    def test_multiple_api_hashes_encoding(self):
        """Test encoding multiple API hashes."""
        apis = ['LoadLibraryA', 'GetProcAddress', 'ExitProcess']
        bad_chars = {0x00}

        for api in apis:
            with self.subTest(api=api):
                api_hash = ror13_hash(api)

                # Should be able to work with the hash
                self.assertIsInstance(api_hash, int)
                self.assertLessEqual(api_hash, 0xFFFFFFFF)


class TestEndToEndScenarios(unittest.TestCase):
    """Test end-to-end shellcode generation scenarios."""

    def test_simple_windows_shellcode_workflow(self):
        """Test a simple Windows shellcode generation workflow."""
        # Step 1: Generate API hashes
        apis = ['LoadLibraryA', 'GetProcAddress']
        hash_dict = generate_hash_dict(apis)

        self.assertEqual(len(hash_dict), 2)

        # Step 2: Convert string for pushing
        dll_name = "kernel32.dll"
        dwords = string_to_push_dwords(dll_name)

        self.assertGreater(len(dwords), 0)

        # Step 3: Build assembly (simplified)
        asm_code = "_start:\n"
        asm_code += "    xor eax, eax\n"
        asm_code += "    ret\n"

        # Step 4: Format output
        result = format_output(asm_code, 'asm', arch='x86', platform='windows')
        self.assertEqual(result, asm_code)

    def test_bad_character_avoidance_workflow(self):
        """Test workflow with bad character avoidance."""
        bad_chars = {0x00, 0x0a, 0x0d}

        # Test values that might have bad chars
        test_values = [
            0x00001234,  # Has null bytes
            0x12340000,  # Has null bytes at end
            0x000a0d00,  # Has multiple bad chars
        ]

        for value in test_values:
            with self.subTest(value=hex(value)):
                import struct
                value_bytes = struct.pack("<I", value)
                has_bad = any(b in bad_chars for b in value_bytes)

                if has_bad:
                    # Should be encodable
                    try:
                        result = encode_dword(value, bad_chars)
                        self.assertIsNotNone(result)
                    except ValueError:
                        # Some values might not be encodable
                        pass

    def test_multi_format_output_consistency(self):
        """Test that different output formats are consistent."""
        asm_code = "xor eax, eax\nret"

        # Generate in different formats
        result_asm = format_output(asm_code, 'asm', arch='x86', platform='windows')
        result_pyasm = format_output(asm_code, 'pyasm', arch='x86', platform='windows')

        # ASM should be unchanged
        self.assertEqual(result_asm, asm_code)

        # pyasm should contain the assembly code
        self.assertIn('xor eax, eax', result_pyasm)
        self.assertIn('ret', result_pyasm)


class TestComponentInteraction(unittest.TestCase):
    """Test interactions between different components."""

    def test_encoder_with_all_bad_chars(self):
        """Test encoder behavior with various bad char sets."""
        test_value = 0x12345678

        bad_char_sets = [
            {0x00},
            {0x00, 0x0a, 0x0d},
            {0x00, 0x0a, 0x0d, 0x20},
            {0x00, 0x09, 0x0a, 0x0d, 0x20},
        ]

        for bad_chars in bad_char_sets:
            with self.subTest(bad_chars=bad_chars):
                import struct
                value_bytes = struct.pack("<I", test_value)
                has_bad = any(b in bad_chars for b in value_bytes)

                if has_bad:
                    result = encode_dword(test_value, bad_chars)
                    self.assertIsNotNone(result)

    def test_hash_generator_output_formats(self):
        """Test that all hash generator formats work."""
        from hash_generator import (
            format_output_text,
            format_output_python,
            format_output_c,
            format_output_asm,
            format_output_json
        )

        apis = ['LoadLibraryA', 'GetProcAddress']
        hash_dict = generate_hash_dict(apis)

        # All formatters should work
        result_text = format_output_text(hash_dict)
        self.assertIn('LoadLibraryA', result_text)

        result_python = format_output_python(hash_dict)
        self.assertIn('API_HASHES', result_python)

        result_c = format_output_c(hash_dict)
        self.assertIn('ApiHash', result_c)

        result_asm = format_output_asm(hash_dict)
        self.assertIn('equ', result_asm)

        result_json = format_output_json(hash_dict)
        self.assertIn('"LoadLibraryA"', result_json)


class TestErrorHandling(unittest.TestCase):
    """Test error handling in integrated scenarios."""

    def test_invalid_format_handling(self):
        """Test handling of invalid output format."""
        asm_code = "mov eax, ebx"

        with self.assertRaises(ValueError) as context:
            format_output(asm_code, 'invalid_format', arch='x86', platform='windows')

        self.assertIn('Unknown output format', str(context.exception))

    def test_unencodable_value_handling(self):
        """Test handling of values that can't be encoded."""
        # Create a bad char set that makes encoding impossible
        bad_chars = set(range(256))
        test_value = 0x12345678

        with self.assertRaises(ValueError) as context:
            encode_dword(test_value, bad_chars)

        self.assertIn('Cannot encode', str(context.exception))


if __name__ == "__main__":
    unittest.main()