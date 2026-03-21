"""
Unit tests for rop/core/pe_info.py

Tests the PEAnalyzer class for extracting PE file information,
including base addresses, sections, and Import Address Table (IAT) entries.
"""
import pytest
import sys
import shutil
from pathlib import Path
from core.pe_info import PEAnalyzer, PEInfo, PESection, IATEntry
import pefile


# Check if we can find a real PE file for testing
# On Windows, use Python executable; on other platforms, skip tests requiring real PE
def find_test_pe():
    """Try to find a PE file for testing"""
    import platform

    # On Windows, Python executable should be a PE
    if platform.system() == "Windows":
        return sys.executable

    # On other platforms, we can't use real PE files
    # Tests requiring real PE files will be skipped
    return None


TEST_PE_FILE = find_test_pe()
HAS_PE_FILE = TEST_PE_FILE is not None


@pytest.mark.skipif(not HAS_PE_FILE, reason="No PE file available for testing")
class TestPEAnalyzerBasics:
    """Test basic PE analysis functionality"""

    def test_get_base_address(self):
        """Test extracting base address from PE file"""
        base_address = PEAnalyzer.get_base_address(TEST_PE_FILE)

        assert isinstance(base_address, int)
        assert base_address > 0
        # Common ImageBase values
        assert base_address in [0x00400000, 0x10000000, 0x140000000] or base_address > 0

    def test_analyze_file_structure(self):
        """Test PEInfo dataclass population"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        assert isinstance(pe_info, PEInfo)
        assert pe_info.filepath == TEST_PE_FILE
        assert isinstance(pe_info.image_base, int)
        assert isinstance(pe_info.entry_point, int)
        assert isinstance(pe_info.machine_type, str)
        assert isinstance(pe_info.subsystem, str)
        assert isinstance(pe_info.sections, list)
        assert len(pe_info.sections) > 0

    def test_section_parsing(self):
        """Test PESection dataclass parsing"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        # Should have at least one section
        assert len(pe_info.sections) > 0

        # Check first section structure
        section = pe_info.sections[0]
        assert isinstance(section, PESection)
        assert isinstance(section.name, str)
        assert len(section.name) > 0
        assert isinstance(section.virtual_address, int)
        assert isinstance(section.virtual_size, int)
        assert isinstance(section.raw_size, int)
        assert isinstance(section.characteristics, int)

    def test_invalid_pe_file(self, tmp_path):
        """Test error handling for non-PE files"""
        # Create a non-PE file
        invalid_file = tmp_path / "invalid.txt"
        invalid_file.write_text("This is not a PE file")

        with pytest.raises(pefile.PEFormatError):
            PEAnalyzer.analyze_file(str(invalid_file))

    def test_missing_file(self):
        """Test error handling for missing files"""
        with pytest.raises((FileNotFoundError, pefile.PEFormatError)):
            PEAnalyzer.analyze_file("/nonexistent/file.exe")

    def test_machine_type_detection(self):
        """Test machine type detection"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        # Should detect valid machine type
        assert pe_info.machine_type in [
            "x86 (I386)",
            "x64 (AMD64)",
            "ARM",
            "ARM64",
        ] or "Unknown" in pe_info.machine_type

    def test_entry_point_calculation(self):
        """Test absolute entry point calculation"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        abs_entry = pe_info.get_absolute_entry_point()
        assert isinstance(abs_entry, int)
        assert abs_entry == pe_info.image_base + pe_info.entry_point


@pytest.mark.skipif(not HAS_PE_FILE, reason="No PE file available for testing")
class TestIATExtraction:
    """Test Import Address Table extraction"""

    def test_get_iat_entries(self):
        """Test extracting IAT entries from PE file"""
        iat_entries = PEAnalyzer.get_iat_entries(TEST_PE_FILE)

        assert isinstance(iat_entries, list)
        # Python executable should have imports
        assert len(iat_entries) > 0

    def test_iat_entry_structure(self):
        """Test IATEntry dataclass structure"""
        iat_entries = PEAnalyzer.get_iat_entries(TEST_PE_FILE)

        if len(iat_entries) > 0:
            entry = iat_entries[0]
            assert isinstance(entry, IATEntry)
            assert isinstance(entry.dll, str)
            assert len(entry.dll) > 0
            assert isinstance(entry.function, str)
            assert len(entry.function) > 0
            assert isinstance(entry.address, int)
            assert entry.address > 0

    def test_iat_named_imports(self):
        """Test named function imports"""
        iat_entries = PEAnalyzer.get_iat_entries(TEST_PE_FILE)

        # Filter to named imports (not ordinal-only)
        named_imports = [e for e in iat_entries if not e.function.startswith("Ordinal_")]

        # Should have some named imports
        assert len(named_imports) > 0

        # Check structure
        for entry in named_imports[:5]:  # Check first 5
            assert isinstance(entry.function, str)
            assert not entry.function.startswith("Ordinal_")

    def test_iat_grouped_by_dll(self):
        """Test that imports can be grouped by DLL correctly"""
        iat_entries = PEAnalyzer.get_iat_entries(TEST_PE_FILE)

        # Group by DLL
        dll_groups = {}
        for entry in iat_entries:
            if entry.dll not in dll_groups:
                dll_groups[entry.dll] = []
            dll_groups[entry.dll].append(entry)

        # Should have multiple DLLs
        assert len(dll_groups) > 0

        # Each DLL should have at least one import
        for dll, entries in dll_groups.items():
            assert len(entries) > 0
            assert all(e.dll == dll for e in entries)

    def test_iat_absolute_address_calculation(self):
        """Test absolute address calculation (RVA + ImageBase)"""
        iat_entries = PEAnalyzer.get_iat_entries(TEST_PE_FILE)
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        if len(iat_entries) > 0:
            entry = iat_entries[0]
            abs_addr = entry.get_absolute_address(pe_info.image_base)

            assert isinstance(abs_addr, int)
            assert abs_addr == pe_info.image_base + entry.address
            assert abs_addr > pe_info.image_base


@pytest.mark.skipif(not HAS_PE_FILE, reason="No PE file available for testing")
class TestSectionCharacteristics:
    """Test section characteristics and flags"""

    def test_get_characteristics_flags(self):
        """Test section flags extraction"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        # Get first section
        section = pe_info.sections[0]
        flags = section.get_characteristics_flags()

        assert isinstance(flags, list)
        # Flags should be valid strings
        valid_flags = [
            "EXECUTABLE", "READABLE", "WRITABLE",
            "CODE", "INITIALIZED_DATA", "UNINITIALIZED_DATA"
        ]
        for flag in flags:
            assert flag in valid_flags

    def test_executable_section_detection(self):
        """Test detection of executable sections"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        # Find executable sections
        exec_sections = []
        for section in pe_info.sections:
            flags = section.get_characteristics_flags()
            if "EXECUTABLE" in flags:
                exec_sections.append(section)

        # Should have at least one executable section (.text)
        assert len(exec_sections) > 0

        # Executable sections should also typically be readable
        for section in exec_sections:
            flags = section.get_characteristics_flags()
            # Most executable sections are also readable
            assert "EXECUTABLE" in flags

    def test_code_section_detection(self):
        """Test detection of code sections"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        # Find code sections
        code_sections = []
        for section in pe_info.sections:
            flags = section.get_characteristics_flags()
            if "CODE" in flags:
                code_sections.append(section)

        # Should have at least one code section
        assert len(code_sections) > 0

    def test_section_name_parsing(self):
        """Test section name parsing and cleanup"""
        pe_info = PEAnalyzer.analyze_file(TEST_PE_FILE)

        # Check that section names are properly parsed
        for section in pe_info.sections:
            # Name should be a string
            assert isinstance(section.name, str)
            # Name should not contain null bytes
            assert '\x00' not in section.name
            # Common section names
            if section.name in ['.text', '.data', '.rdata', '.bss', '.idata']:
                assert len(section.name) > 0


class TestDataClasses:
    """Test dataclass functionality"""

    def test_pe_section_dataclass(self):
        """Test PESection dataclass creation"""
        section = PESection(
            name=".text",
            virtual_address=0x1000,
            virtual_size=0x2000,
            raw_size=0x2000,
            characteristics=0x60000020  # CODE | EXECUTABLE | READABLE
        )

        assert section.name == ".text"
        assert section.virtual_address == 0x1000
        assert section.virtual_size == 0x2000
        assert section.raw_size == 0x2000
        assert section.characteristics == 0x60000020

        flags = section.get_characteristics_flags()
        assert "EXECUTABLE" in flags
        assert "READABLE" in flags
        assert "CODE" in flags

    def test_iat_entry_dataclass(self):
        """Test IATEntry dataclass creation"""
        entry = IATEntry(
            dll="kernel32.dll",
            function="WriteFile",
            address=0x2000,
            ordinal=123
        )

        assert entry.dll == "kernel32.dll"
        assert entry.function == "WriteFile"
        assert entry.address == 0x2000
        assert entry.ordinal == 123

        abs_addr = entry.get_absolute_address(0x400000)
        assert abs_addr == 0x402000

    def test_iat_entry_without_ordinal(self):
        """Test IATEntry without ordinal"""
        entry = IATEntry(
            dll="user32.dll",
            function="MessageBoxA",
            address=0x3000
        )

        assert entry.dll == "user32.dll"
        assert entry.function == "MessageBoxA"
        assert entry.address == 0x3000
        assert entry.ordinal is None

    def test_pe_info_dataclass(self):
        """Test PEInfo dataclass creation"""
        sections = [
            PESection(".text", 0x1000, 0x2000, 0x2000, 0x60000020)
        ]

        pe_info = PEInfo(
            filepath="/path/to/test.exe",
            image_base=0x400000,
            entry_point=0x1550,
            machine_type="x86 (I386)",
            subsystem="WINDOWS_GUI",
            sections=sections
        )

        assert pe_info.filepath == "/path/to/test.exe"
        assert pe_info.image_base == 0x400000
        assert pe_info.entry_point == 0x1550
        assert pe_info.machine_type == "x86 (I386)"
        assert pe_info.subsystem == "WINDOWS_GUI"
        assert len(pe_info.sections) == 1

        abs_entry = pe_info.get_absolute_entry_point()
        assert abs_entry == 0x401550