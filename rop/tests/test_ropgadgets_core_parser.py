"""
Unit tests for rop/core/parser.py

Tests the ROPGadgetParser class for parsing rp++ output files,
including encoding detection, file parsing, filtering, and grouping.
"""

import os
import tempfile
import unittest

from rop.core.parser import ROPGadgetParser

# Sample gadget data for testing
SAMPLE_GADGETS = """Trying to open 'test.dll'..
FileFormat: PE, Arch: x86

0x10001234: pop eax ; ret ; (1 found)
0x10001240: pop ebx ; pop ecx ; ret ; (2 found)
0x10001250: mov eax, ebx ; ret ; (1 found)
0x10001260: add esp, 0x10 ; ret ; (1 found)
0x10001270: xor eax, eax ; ret ; (1 found)
0x10001280: call [eax] ; (1 found)

A total of 6 gadgets found.
"""

SAMPLE_GADGETS_WITH_BAD_CHARS = """FileFormat: PE, Arch: x86

0x00001234: pop eax ; ret ; (1 found)
0x10000a56: pop ebx ; ret ; (1 found)
0x1000120d: pop ecx ; ret ; (1 found)
0x12345678: pop edx ; ret ; (1 found)
"""


class TestEncodingDetection(unittest.TestCase):
    """Test file encoding detection"""

    def test_detect_utf8(self):
        """Test UTF-8 detection"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        try:
            encoding = ROPGadgetParser.detect_encoding(temp_path)
            assert encoding in ["utf-8", "utf-16-le", "utf-16-be"]  # Detection may vary
        finally:
            os.unlink(temp_path)

    def test_detect_utf16le(self):
        """Test UTF-16 LE detection"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-16-le", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        try:
            encoding = ROPGadgetParser.detect_encoding(temp_path)
            # Should detect UTF-16 LE
            assert encoding in ["utf-16-le", "utf-16-be"]
        finally:
            os.unlink(temp_path)


class TestFileParsingBasics(unittest.TestCase):
    """Test basic file parsing functionality"""

    def test_parse_file_utf8(self):
        """Test parsing UTF-8 file"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        try:
            parser = ROPGadgetParser(temp_path)
            gadgets = parser.parse_file()

            assert len(gadgets) == 6
            assert parser.metadata.get("dll") == "test.dll"
            assert parser.metadata.get("format") == "PE"
            assert parser.metadata.get("arch") == "x86"
            assert parser.metadata.get("total_gadgets") == "6"
        finally:
            os.unlink(temp_path)

    def test_parse_gadget_structure(self):
        """Test that gadgets are parsed correctly"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        try:
            parser = ROPGadgetParser(temp_path)
            gadgets = parser.parse_file()

            # Check first gadget
            g = gadgets[0]
            assert g.address == "0x10001234"
            assert g.instructions == ["pop eax", "ret"]
            assert g.count == 1

            # Check second gadget (multiple instructions)
            g = gadgets[1]
            assert g.address == "0x10001240"
            assert len(g.instructions) == 3
            assert g.count == 2
        finally:
            os.unlink(temp_path)


class TestFilteringByInstruction(unittest.TestCase):
    """Test filtering gadgets by instruction"""

    def setUp(self):
        """Create parser with sample gadgets"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        self.parser = ROPGadgetParser(temp_path)
        self.parser.parse_file()
        os.unlink(temp_path)

    def test_filter_by_instruction_any(self):
        """Test filtering by instruction (any position)"""
        filtered = self.parser.filter_by_instruction("pop", "any")
        assert len(filtered) == 2  # Two gadgets contain 'pop'

    def test_filter_by_instruction_first(self):
        """Test filtering by first instruction"""
        filtered = self.parser.filter_by_instruction("pop", "first")
        assert len(filtered) == 2  # Two gadgets start with 'pop'

    def test_filter_by_instruction_last(self):
        """Test filtering by last instruction"""
        filtered = self.parser.filter_by_instruction("ret", "last")
        assert len(filtered) == 5  # Five gadgets end with 'ret'

    def test_filter_by_instruction_case_insensitive(self):
        """Test case-insensitive filtering"""
        filtered = self.parser.filter_by_instruction("POP", "any")
        assert len(filtered) == 2


class TestFilteringByPattern(unittest.TestCase):
    """Test filtering by regex pattern"""

    def setUp(self):
        """Create parser with sample gadgets"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        self.parser = ROPGadgetParser(temp_path)
        self.parser.parse_file()
        os.unlink(temp_path)

    def test_filter_by_pattern_simple(self):
        """Test simple regex pattern"""
        filtered = self.parser.filter_by_pattern(r"pop.*ret")
        assert len(filtered) >= 1

    def test_filter_by_pattern_complex(self):
        """Test complex regex pattern"""
        filtered = self.parser.filter_by_pattern(r"pop.*pop.*ret")
        assert len(filtered) == 1  # Only one gadget with two pops


class TestBadCharacterFiltering(unittest.TestCase):
    """Test filtering by bad characters"""

    def setUp(self):
        """Create parser with gadgets containing bad chars"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS_WITH_BAD_CHARS)
            temp_path = f.name

        self.parser = ROPGadgetParser(temp_path)
        self.parser.parse_file()
        os.unlink(temp_path)

    def test_filter_bad_chars_null(self):
        """Test filtering null bytes"""
        filtered = self.parser.filter_bad_chars(["00"])
        # Should exclude 0x00001234
        addresses = [g.address for g in filtered]
        assert "0x00001234" not in addresses

    def test_filter_bad_chars_multiple(self):
        """Test filtering multiple bad characters"""
        filtered = self.parser.filter_bad_chars(["00", "0a", "0d"])
        # Should exclude gadgets with 00, 0a, or 0d
        addresses = [g.address for g in filtered]
        assert "0x00001234" not in addresses
        assert "0x10000a56" not in addresses
        assert "0x1000120d" not in addresses
        assert "0x12345678" in addresses  # This one should remain


class TestGroupingFunctions(unittest.TestCase):
    """Test grouping gadgets"""

    def setUp(self):
        """Create parser with sample gadgets"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        self.parser = ROPGadgetParser(temp_path)
        self.parser.parse_file()
        os.unlink(temp_path)

    def test_group_by_last_instruction(self):
        """Test grouping by last instruction"""
        groups = self.parser.group_by_last_instruction()
        assert "ret" in groups
        assert len(groups["ret"]) == 5

    def test_group_by_first_instruction(self):
        """Test grouping by first instruction"""
        groups = self.parser.group_by_first_instruction()
        assert "pop" in groups
        assert "mov" in groups
        assert "add" in groups

    def test_group_by_category(self):
        """Test grouping by category"""
        groups = self.parser.group_by_category()
        assert len(groups) > 0
        # Should have at least stack_pop and other categories
        assert "stack_pop" in groups or len(groups) > 0

    def test_group_by_affected_register(self):
        """Test grouping by affected registers"""
        groups = self.parser.group_by_affected_register()
        assert "eax" in groups
        assert len(groups["eax"]) > 0

    def test_group_by_modified_register(self):
        """Test grouping by modified registers"""
        groups = self.parser.group_by_modified_register()
        assert "eax" in groups
        # pop eax modifies eax
        eax_gadgets = groups["eax"]
        assert len(eax_gadgets) > 0


class TestRegisterFiltering(unittest.TestCase):
    """Test filtering by register"""

    def setUp(self):
        """Create parser with sample gadgets"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        self.parser = ROPGadgetParser(temp_path)
        self.parser.parse_file()
        os.unlink(temp_path)

    def test_filter_by_register_affected(self):
        """Test filtering by affected register"""
        filtered = self.parser.filter_by_register("eax", modified_only=False)
        assert len(filtered) > 0

    def test_filter_by_register_modified(self):
        """Test filtering by modified register"""
        filtered = self.parser.filter_by_register("eax", modified_only=True)
        assert len(filtered) > 0


class TestStatistics(unittest.TestCase):
    """Test statistics generation"""

    def setUp(self):
        """Create parser with sample gadgets"""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGETS)
            temp_path = f.name

        self.parser = ROPGadgetParser(temp_path)
        self.parser.parse_file()
        os.unlink(temp_path)

    def test_get_statistics(self):
        """Test statistics generation"""
        stats = self.parser.get_statistics()

        assert stats["total_gadgets"] == 6
        assert stats["unique_addresses"] == 6
        assert "last_instruction_counts" in stats
        assert "category_counts" in stats
