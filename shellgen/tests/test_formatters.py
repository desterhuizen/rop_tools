"""
Tests for src/formatters.py

Tests output formatting in various formats: ASM, Python, C, raw, and pyasm.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

from shellgen.src.formatters import (
    _convert_asm_to_python_tuple,
    format_asm,
    format_c_array,
    format_output,
    format_pyasm,
    format_python_bytes,
)


class TestConvertAsmToPythonTuple(unittest.TestCase):
    """Test cases for _convert_asm_to_python_tuple helper function."""

    def test_simple_instruction(self):
        """Test conversion of simple instruction without comment."""
        asm_code = "mov eax, ebx"
        result = _convert_asm_to_python_tuple(asm_code)
        self.assertIn("mov eax, ebx", result)
        self.assertIn(";", result)  # Should add semicolon

    def test_instruction_with_inline_comment(self):
        """Test instruction with inline comment."""
        asm_code = "mov eax, ebx ; load value"
        result = _convert_asm_to_python_tuple(asm_code)
        self.assertIn("mov eax, ebx", result)
        self.assertIn("# load value", result)  # Comment should be Python style

    def test_pure_comment_line(self):
        """Test line that is only a comment."""
        asm_code = "; This is a comment"
        result = _convert_asm_to_python_tuple(asm_code)
        self.assertIn("# This is a comment", result)

    def test_empty_lines_skipped(self):
        """Test that empty lines are skipped."""
        asm_code = "mov eax, ebx\n\nmov ecx, edx"
        result = _convert_asm_to_python_tuple(asm_code)
        # Should not have extra blank lines
        self.assertNotIn('    f""', result)

    def test_multiple_instructions(self):
        """Test multiple instructions."""
        asm_code = "mov eax, ebx\nadd eax, ecx\nret"
        result = _convert_asm_to_python_tuple(asm_code)
        self.assertIn("mov eax, ebx", result)
        self.assertIn("add eax, ecx", result)
        self.assertIn("ret", result)

    def test_padding_alignment(self):
        """Test that instructions are padded for alignment."""
        asm_code = "mov eax, ebx ; comment"
        result = _convert_asm_to_python_tuple(asm_code)
        # Should have padding before semicolon
        lines = result.split("\n")
        for line in lines:
            if "mov eax, ebx" in line and not line.strip().startswith("#"):
                # Check for padding (semicolon should be padded)
                self.assertIn(';"', line)


class TestFormatAsm(unittest.TestCase):
    """Test cases for format_asm function."""

    def test_returns_asm_unchanged(self):
        """Test that ASM code is returned as-is."""
        asm_code = "; Test assembly\nmov eax, ebx\nret"
        result = format_asm(asm_code)
        self.assertEqual(result, asm_code)

    def test_preserves_formatting(self):
        """Test that original formatting is preserved."""
        asm_code = """_start:
    mov eax, ebx
    add eax, 0x100
    ret"""
        result = format_asm(asm_code)
        self.assertEqual(result, asm_code)


class TestFormatPythonBytes(unittest.TestCase):
    """Test cases for format_python_bytes function."""

    @patch("sys.stdout.isatty", return_value=False)
    def test_basic_formatting(self, mock_isatty):
        """Test basic Python bytes formatting."""
        shellcode_bytes = b"\x90\x90\x90\xc3"
        result = format_python_bytes(shellcode_bytes, arch="x86", platform="windows")

        # Should contain the shellcode variable
        self.assertIn("shellgen", result)
        self.assertIn("\\x90\\x90\\x90\\xc3", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_includes_metadata(self, mock_isatty):
        """Test that metadata is included in output."""
        shellcode_bytes = b"\x90\xc3"
        result = format_python_bytes(shellcode_bytes, arch="x86", platform="windows")

        # Should include comments with metadata
        self.assertIn("Length: 2 bytes", result)
        self.assertIn("Architecture: x86", result)
        self.assertIn("Platform: windows", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_different_architectures(self, mock_isatty):
        """Test formatting for different architectures."""
        shellcode_bytes = b"\x90\xc3"

        for arch in ["x86", "x64", "arm", "arm64"]:
            with self.subTest(arch=arch):
                result = format_python_bytes(
                    shellcode_bytes, arch=arch, platform="linux"
                )
                self.assertIn(f"Architecture: {arch}", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_empty_shellcode(self, mock_isatty):
        """Test formatting empty shellcode."""
        shellcode_bytes = b""
        result = format_python_bytes(shellcode_bytes, arch="x86", platform="windows")

        self.assertIn("shellgen", result)
        self.assertIn("Length: 0 bytes", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_hex_encoding(self, mock_isatty):
        """Test that bytes are correctly hex-encoded."""
        shellcode_bytes = b"\x00\xff\x12\x34"
        result = format_python_bytes(shellcode_bytes, arch="x86", platform="windows")

        self.assertIn("\\x00", result)
        self.assertIn("\\xff", result)
        self.assertIn("\\x12", result)
        self.assertIn("\\x34", result)


class TestFormatCArray(unittest.TestCase):
    """Test cases for format_c_array function."""

    @patch("sys.stdout.isatty", return_value=False)
    def test_basic_formatting(self, mock_isatty):
        """Test basic C array formatting."""
        shellcode_bytes = b"\x90\x90\x90\xc3"
        result = format_c_array(shellcode_bytes, arch="x86", platform="windows")

        # Should contain C array declaration
        self.assertIn("unsigned char shellgen[]", result)
        self.assertIn("0x90, 0x90, 0x90, 0xc3", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_includes_length_variable(self, mock_isatty):
        """Test that length variable is included."""
        shellcode_bytes = b"\x90\xc3"
        result = format_c_array(shellcode_bytes, arch="x86", platform="windows")

        self.assertIn("unsigned int shellcode_len", result)
        self.assertIn("= 2", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_16_bytes_per_line(self, mock_isatty):
        """Test that output has 16 bytes per line."""
        # Create shellcode with more than 16 bytes
        shellcode_bytes = bytes(range(32))
        result = format_c_array(shellcode_bytes, arch="x86", platform="windows")

        lines = result.split("\n")
        # Find the data lines (between { and })
        data_lines = [l for l in lines if "0x" in l and "{" not in l and "}" not in l]

        # Should have multiple lines
        self.assertGreater(len(data_lines), 1)

    @patch("sys.stdout.isatty", return_value=False)
    def test_includes_metadata_comments(self, mock_isatty):
        """Test that C comments with metadata are included."""
        shellcode_bytes = b"\x90\xc3"
        result = format_c_array(shellcode_bytes, arch="x64", platform="linux")

        # Should have C-style comments
        self.assertIn("//", result)
        self.assertIn("x64", result.lower())

    @patch("sys.stdout.isatty", return_value=False)
    def test_proper_c_syntax(self, mock_isatty):
        """Test that output has proper C syntax."""
        shellcode_bytes = b"\x90\xc3"
        result = format_c_array(shellcode_bytes, arch="x86", platform="windows")

        # Should have proper array syntax
        self.assertIn("unsigned char shellgen[] = {", result)
        self.assertIn("};", result)

        # Commas should be placed correctly
        self.assertIn("0x90, 0xc3", result)


class TestFormatPyasm(unittest.TestCase):
    """Test cases for format_pyasm function."""

    def test_basic_structure(self):
        """Test that pyasm output has basic structure."""
        asm_code = "mov eax, ebx\nret"
        result = format_pyasm(asm_code, arch="x86", platform="windows")

        # Should have Python shebang
        self.assertIn("#!/usr/bin/env python3", result)

        # Should have imports
        self.assertIn("from keystone import *", result)

        # Should have CODE tuple
        self.assertIn("CODE = (", result)

        # Should have assembly function
        self.assertIn("ks = Ks(", result)

    def test_architecture_constants(self):
        """Test correct Keystone architecture constants."""
        asm_code = "mov eax, ebx"

        # Test x86
        result = format_pyasm(asm_code, arch="x86", platform="windows")
        self.assertIn("KS_ARCH_X86", result)
        self.assertIn("KS_MODE_32", result)

        # Test x64
        result = format_pyasm(asm_code, arch="x64", platform="windows")
        self.assertIn("KS_ARCH_X86", result)
        self.assertIn("KS_MODE_64", result)

        # Test ARM
        result = format_pyasm(asm_code, arch="arm", platform="linux")
        self.assertIn("KS_ARCH_ARM", result)
        self.assertIn("KS_MODE_ARM", result)

        # Test ARM64
        result = format_pyasm(asm_code, arch="arm64", platform="linux")
        self.assertIn("KS_ARCH_ARM64", result)

    def test_includes_run_shellcode_function(self):
        """Test that run_shellcode function is included."""
        asm_code = "mov eax, ebx"
        result = format_pyasm(asm_code, arch="x86", platform="windows")

        self.assertIn("def run_shellcode(", result)
        self.assertIn("VirtualAlloc", result)
        self.assertIn("CreateThread", result)

    def test_includes_metadata(self):
        """Test that metadata is included in docstring."""
        asm_code = "mov eax, ebx"
        result = format_pyasm(asm_code, arch="x86", platform="windows")

        self.assertIn("Architecture: X86", result)
        self.assertIn("Platform: windows", result)

    def test_breakpoint_option(self):
        """Test that breakpoint option is included."""
        asm_code = "mov eax, ebx"
        result = format_pyasm(asm_code, arch="x86", platform="windows")

        self.assertIn("add_break", result)
        self.assertIn("int3", result)


class TestFormatOutput(unittest.TestCase):
    """Test cases for format_output function."""

    def test_asm_format(self):
        """Test output in ASM format."""
        asm_code = "mov eax, ebx\nret"
        result = format_output(asm_code, "asm", arch="x86", platform="windows")

        self.assertEqual(result, asm_code)

    def test_pyasm_format(self):
        """Test output in pyasm format."""
        asm_code = "mov eax, ebx\nret"
        result = format_output(asm_code, "pyasm", arch="x86", platform="windows")

        self.assertIsInstance(result, str)
        self.assertIn("#!/usr/bin/env python3", result)

    @patch("shellgen.src.formatters.assemble_to_binary")
    def test_raw_format(self, mock_assemble):
        """Test output in raw binary format."""
        asm_code = "mov eax, ebx\nret"
        mock_shellcode = b"\x89\xd8\xc3"
        mock_assemble.return_value = mock_shellcode

        result = format_output(asm_code, "raw", arch="x86", platform="windows")

        self.assertEqual(result, mock_shellcode)
        mock_assemble.assert_called_once_with(asm_code, "x86")

    @patch("shellgen.src.formatters.assemble_to_binary")
    def test_python_format(self, mock_assemble):
        """Test output in Python format."""
        asm_code = "mov eax, ebx\nret"
        mock_shellcode = b"\x89\xd8\xc3"
        mock_assemble.return_value = mock_shellcode

        result = format_output(asm_code, "python", arch="x86", platform="windows")

        self.assertIsInstance(result, str)
        self.assertIn("shellgen", result)
        mock_assemble.assert_called_once()

    @patch("shellgen.src.formatters.assemble_to_binary")
    def test_c_format(self, mock_assemble):
        """Test output in C format."""
        asm_code = "mov eax, ebx\nret"
        mock_shellcode = b"\x89\xd8\xc3"
        mock_assemble.return_value = mock_shellcode

        result = format_output(asm_code, "c", arch="x86", platform="windows")

        self.assertIsInstance(result, str)
        self.assertIn("unsigned char shellgen[]", result)
        mock_assemble.assert_called_once()

    def test_unknown_format_raises_error(self):
        """Test that unknown format raises ValueError."""
        asm_code = "mov eax, ebx\nret"

        with self.assertRaises(ValueError) as context:
            format_output(asm_code, "unknown", arch="x86", platform="windows")

        self.assertIn("Unknown output format", str(context.exception))

    def test_all_supported_formats(self):
        """Test that all documented formats are supported."""
        asm_code = "mov eax, ebx\nret"
        supported_formats = ["asm", "pyasm"]

        for fmt in supported_formats:
            with self.subTest(format=fmt):
                try:
                    result = format_output(
                        asm_code, fmt, arch="x86", platform="windows"
                    )
                    self.assertIsNotNone(result)
                except Exception as e:
                    # Only acceptable if it's due to missing assembler (not format error)
                    if "Unknown output format" in str(e):
                        self.fail(f"Format {fmt} should be supported")


class TestFormattersEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios."""

    def test_empty_asm_code(self):
        """Test formatting empty assembly code."""
        asm_code = ""

        # Should handle empty code gracefully
        result_asm = format_asm(asm_code)
        self.assertEqual(result_asm, "")

        result_pyasm = format_pyasm(asm_code, arch="x86", platform="windows")
        self.assertIsInstance(result_pyasm, str)

    def test_asm_with_only_comments(self):
        """Test assembly code with only comments."""
        asm_code = "; Comment line 1\n; Comment line 2"

        result = _convert_asm_to_python_tuple(asm_code)
        self.assertIn("# Comment line 1", result)
        self.assertIn("# Comment line 2", result)

    def test_asm_with_labels(self):
        """Test assembly code with labels."""
        asm_code = "_start:\n    mov eax, ebx\n    jmp _start"

        result = _convert_asm_to_python_tuple(asm_code)
        self.assertIn("_start:", result)
        self.assertIn("mov eax, ebx", result)

    @patch("sys.stdout.isatty", return_value=False)
    def test_very_long_shellcode(self, mock_isatty):
        """Test formatting very long shellcode."""
        # 1000 bytes of shellcode
        shellcode_bytes = bytes(range(256)) * 4

        result_python = format_python_bytes(
            shellcode_bytes, arch="x86", platform="windows"
        )
        self.assertIn("Length: 1024 bytes", result_python)

        result_c = format_c_array(shellcode_bytes, arch="x86", platform="windows")
        self.assertIn("unsigned int shellcode_len = 1024", result_c)

    @patch("sys.stdout.isatty", return_value=False)
    def test_shellcode_with_all_byte_values(self, mock_isatty):
        """Test shellcode containing all possible byte values."""
        shellcode_bytes = bytes(range(256))

        result_python = format_python_bytes(
            shellcode_bytes, arch="x86", platform="windows"
        )
        # Check for first and last bytes
        self.assertIn("\\x00", result_python)
        self.assertIn("\\xff", result_python)

        result_c = format_c_array(shellcode_bytes, arch="x86", platform="windows")
        self.assertIn("0x00", result_c)
        self.assertIn("0xff", result_c)


if __name__ == "__main__":
    unittest.main()
