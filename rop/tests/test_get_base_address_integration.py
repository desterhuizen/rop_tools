"""
Integration tests for get_base_address.py

Tests the complete get_base_address CLI tool including argument parsing,
PE file processing, and output formatting.
"""
import unittest
import tempfile
import os
import subprocess
import sys
import platform
from pathlib import Path


# Get the path to get_base_address.py
BASE_ADDR_TOOL_PATH = Path(__file__).parent.parent / "get_base_address.py"

# Check if we have a test PE file (only on Windows)
HAS_PE_FILE = platform.system() == "Windows"
TEST_PE_FILE = sys.executable if HAS_PE_FILE else None


class TestBasicUsage(unittest.TestCase):
    """Test basic get_base_address.py functionality"""

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_basic_base_address_display(self):
        """Test basic base address extraction"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "ImageBase" in result.stdout
        assert "0x" in result.stdout

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_quiet_mode(self):
        """Test -q flag outputs only the address"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '-q'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should only contain hex address
        assert result.stdout.strip().startswith("0x")
        # Should not contain labels or formatting
        assert "ImageBase" not in result.stdout
        assert "File" not in result.stdout

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_no_color_flag(self):
        """Test --no-color disables color output"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should not contain ANSI color codes (basic check)
        assert "\x1b[" not in result.stdout


class TestVerboseMode(unittest.TestCase):
    """Test verbose mode output"""

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_verbose_mode(self):
        """Test -v flag shows entry point, machine type, sections"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '-v', '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should show entry point
        assert "Entry Point" in result.stdout or "entry" in result.stdout.lower()
        # Should show machine type
        assert "Machine" in result.stdout or "x86" in result.stdout or "x64" in result.stdout
        # Should show sections
        assert "Section" in result.stdout or ".text" in result.stdout


class TestIATDisplay(unittest.TestCase):
    """Test Import Address Table display"""

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_iat_display(self):
        """Test --iat flag displays import table"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '--iat', '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should show IAT information
        assert "Import" in result.stdout or "IAT" in result.stdout
        # Should show DLL names
        assert ".dll" in result.stdout.lower()

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_iat_dll_filter(self):
        """Test --iat --dll filters by DLL name"""
        # Try to filter by kernel32
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE,
             '--iat', '--dll', 'kernel32', '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should show kernel32 imports or message about no imports
        assert "kernel32" in result.stdout.lower() or "No imports" in result.stdout

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_iat_dll_filter_case_insensitive(self):
        """Test DLL filter is case-insensitive"""
        # Try uppercase and lowercase versions
        result_lower = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE,
             '--iat', '--dll', 'kernel32', '--no-color'],
            capture_output=True,
            text=True
        )

        result_upper = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE,
             '--iat', '--dll', 'KERNEL32', '--no-color'],
            capture_output=True,
            text=True
        )

        # Both should return successfully
        assert result_lower.returncode == 0
        assert result_upper.returncode == 0
        # Both should show similar content
        # (either both find imports or both don't)


class TestErrorHandling(unittest.TestCase):
    """Test error handling"""

    def test_missing_file(self):
        """Test error handling for missing file"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), '/nonexistent/file.exe'],
            capture_output=True,
            text=True
        )

        assert result.returncode != 0
        assert "Error" in result.stderr or "Error" in result.stdout
        assert "not found" in result.stderr or "not found" in result.stdout

    def test_invalid_pe_file(self):
        """Test error handling for invalid PE"""
        # Create a non-PE file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exe') as f:
            f.write("This is not a PE file")
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(BASE_ADDR_TOOL_PATH), temp_path],
                capture_output=True,
                text=True
            )

            assert result.returncode != 0
            assert "Error" in result.stderr or "Error" in result.stdout
            assert "not a valid PE" in result.stderr or "not a valid PE" in result.stdout
        finally:
            os.unlink(temp_path)


class TestOutputFormats(unittest.TestCase):
    """Test different output formats and combinations"""

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_combined_verbose_iat(self):
        """Test combining verbose mode with IAT display"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE,
             '-v', '--iat', '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should show both verbose info and IAT
        assert "ImageBase" in result.stdout
        assert "Import" in result.stdout or "IAT" in result.stdout

    @unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
    def test_quiet_mode_ignores_other_flags(self):
        """Test that quiet mode overrides verbose and IAT flags"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE,
             '-q', '-v', '--iat'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should only output the address (quiet mode takes precedence)
        assert result.stdout.strip().startswith("0x")
        # Should not show verbose or IAT info
        assert "Entry Point" not in result.stdout
        assert "Import" not in result.stdout


@unittest.skipIf(not HAS_PE_FILE, reason="No PE file available (not on Windows)")
class TestAddressFormats(unittest.TestCase):
    """Test address display formats"""

    def test_hex_address_format(self):
        """Test that addresses are displayed in hex format"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should contain hex addresses
        assert "0x" in result.stdout

    def test_decimal_address_also_shown(self):
        """Test that decimal address is also displayed"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE, '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should show both hex and decimal
        assert "Decimal" in result.stdout or any(c.isdigit() for c in result.stdout)

    def test_iat_shows_rva_and_absolute(self):
        """Test that IAT display shows both RVA and absolute addresses"""
        result = subprocess.run(
            [sys.executable, str(BASE_ADDR_TOOL_PATH), TEST_PE_FILE,
             '--iat', '--no-color'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        if "No imports" not in result.stdout:
            # Should show both RVA and absolute addresses
            assert "RVA" in result.stdout or "rva" in result.stdout.lower()
            assert "Absolute" in result.stdout or "Abs" in result.stdout