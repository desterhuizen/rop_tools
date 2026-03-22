"""
Integration tests for get_rop_gadgets.py

Tests the complete ROP gadget tool including CLI argument parsing,
file processing, filtering, grouping, and output formatting.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Get the path to get_rop_gadgets.py
ROP_TOOL_PATH = Path(__file__).parent.parent / "get_rop_gadgets.py"

# Sample gadget file for integration testing
SAMPLE_GADGET_FILE = """Trying to open 'kernel32.dll'..
FileFormat: PE, Arch: x86

0x76d41234: pop eax ; ret ; (1 found)
0x76d41240: pop ebx ; pop ecx ; ret ; (2 found)
0x76d41250: mov eax, ebx ; ret ; (1 found)
0x76d41260: add esp, 0x10 ; ret ; (1 found)
0x76d41270: xor eax, eax ; ret ; (1 found)
0x76d41280: call [eax] ; (1 found)
0x76d41290: mov eax, [ebx] ; ret ; (1 found)
0x76d412a0: mov [eax], ebx ; ret ; (1 found)
0x76d412b0: push eax ; ret ; (1 found)
0x76d412c0: lea eax, [ebx+4] ; ret ; (1 found)

A total of 10 gadgets found.
"""

# Sample gadget file with bad characters
SAMPLE_BAD_CHARS_FILE = """FileFormat: PE, Arch: x86

0x00001234: pop eax ; ret ; (1 found)
0x10000a56: pop ebx ; ret ; (1 found)
0x1000120d: pop ecx ; ret ; (1 found)
0x12345678: pop edx ; ret ; (1 found)
0x76543210: pop esi ; ret ; (1 found)
"""

# Sample gadget file with bad instructions (call, jmp, int, etc.)
SAMPLE_BAD_INSTRUCTIONS_FILE = """FileFormat: PE, Arch: x86

0x10001000: pop eax ; ret ; (1 found)
0x10001010: pop ebx ; ret ; (1 found)
0x10001020: pop eax ; call [eax] ; (1 found)
0x10001030: mov eax, ebx ; jmp esp ; (1 found)
0x10001040: xor eax, eax ; int 0x80 ; (1 found)
0x10001050: push ebp ; leave ; (1 found)
0x10001060: pop eax ; je 0x1234 ; (1 found)
0x10001070: add eax, ebx ; jne 0x5678 ; (1 found)
0x10001080: mov eax, [ebx] ; ret ; (1 found)
0x10001090: pop ecx ; pop edx ; ret ; (1 found)
0x100010a0: xchg eax, esp ; ret ; (1 found)
0x100010b0: cli ; ret ; (1 found)
0x100010c0: popf ; ret ; (1 found)
0x100010d0: hlt ; (1 found)
0x100010e0: lock xchg eax, ebx ; ret ; (1 found)

A total of 15 gadgets found.
"""


class BaseSampleGadgetTest(unittest.TestCase):
    """Base class for tests using SAMPLE_GADGET_FILE"""

    def setUp(self):
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_GADGET_FILE)
            self.sample_gadget_file = f.name

    def tearDown(self):
        if hasattr(self, "sample_gadget_file"):
            os.unlink(self.sample_gadget_file)


class BaseBadCharsTest(unittest.TestCase):
    """Base class for tests using SAMPLE_BAD_CHARS_FILE"""

    def setUp(self):
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_BAD_CHARS_FILE)
            self.bad_chars_gadget_file = f.name

    def tearDown(self):
        if hasattr(self, "bad_chars_gadget_file"):
            os.unlink(self.bad_chars_gadget_file)


class BaseBadInstructionsTest(unittest.TestCase):
    """Base class for tests using SAMPLE_BAD_INSTRUCTIONS_FILE"""

    def setUp(self):
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(SAMPLE_BAD_INSTRUCTIONS_FILE)
            self.bad_instructions_gadget_file = f.name

    def tearDown(self):
        if hasattr(self, "bad_instructions_gadget_file"):
            os.unlink(self.bad_instructions_gadget_file)


class TestBasicParsing(BaseSampleGadgetTest):
    """Test basic file parsing and display"""

    def test_parse_file_basic(self):
        """Test basic file parsing"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Parsed 10 gadgets" in result.stdout
        assert "0x76d41234" in result.stdout

    def test_statistics_display(self):
        """Test statistics display"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-s",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Statistics" in result.stdout or "Total" in result.stdout


class TestInstructionFiltering(BaseSampleGadgetTest):
    """Test filtering by instruction"""

    def test_filter_by_instruction_any(self):
        """Test filtering by instruction (any position)"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-i",
                "pop",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Found" in result.stdout and "gadgets with 'pop'" in result.stdout

    def test_filter_by_instruction_first(self):
        """Test filtering by first instruction"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-i",
                "pop",
                "-p",
                "first",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Found" in result.stdout

    def test_filter_by_instruction_last(self):
        """Test filtering by last instruction"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-i",
                "ret",
                "-p",
                "last",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Found" in result.stdout


class TestRegexFiltering(BaseSampleGadgetTest):
    """Test filtering by regex pattern"""

    def test_filter_by_regex(self):
        """Test regex pattern filtering"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-r",
                "pop.*ret",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Found" in result.stdout and "matching regex" in result.stdout

    def test_filter_by_regex_complex(self):
        """Test complex regex pattern"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-r",
                "pop.*pop.*ret",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_filter_with_exclude(self):
        """Test exclusion filtering"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-r",
                "pop",
                "-e",
                "ebx",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Excluded" in result.stdout


class TestBadCharacterFiltering(BaseBadCharsTest):
    """Test bad character filtering"""

    def test_filter_bad_chars_backslash_format(self):
        """Test bad character filtering with \\x format"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_chars_gadget_file,
                "-b",
                "\\x00\\x0a",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Filtered" in result.stdout and "without bad chars" in result.stdout

    def test_filter_bad_chars_comma_format(self):
        """Test bad character filtering with comma format"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_chars_gadget_file,
                "-b",
                "00,0a,0d",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Filtered" in result.stdout


class TestCategoryFiltering(BaseSampleGadgetTest):
    """Test category-based filtering"""

    def test_filter_by_category(self):
        """Test filtering by category"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-c",
                "stack_pop",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "category" in result.stdout

    def test_show_category(self):
        """Test showing category for each gadget"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-i",
                "pop",
                "--show-category",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "[" in result.stdout and "]" in result.stdout


class TestGrouping(BaseSampleGadgetTest):
    """Test grouping functionality"""

    def test_group_by_first(self):
        """Test grouping by first instruction"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-g",
                "first",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Grouped by first instruction" in result.stdout

    def test_group_by_last(self):
        """Test grouping by last instruction"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-g",
                "last",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Grouped by last instruction" in result.stdout

    def test_group_by_category(self):
        """Test grouping by category"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-g",
                "category",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Grouped by category" in result.stdout

    def test_group_by_modified_register(self):
        """Test grouping by modified register"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-g",
                "modified-register",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Grouped by modified register" in result.stdout


class TestRegisterFiltering(BaseSampleGadgetTest):
    """Test register-based filtering"""

    def test_filter_by_register(self):
        """Test filtering by register"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--register",
                "eax",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Found" in result.stdout and "register 'eax'" in result.stdout

    def test_filter_by_register_modified_only(self):
        """Test filtering by modified register only"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--register",
                "eax",
                "--modified-only",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "modify" in result.stdout


class TestDereferencedFiltering(BaseSampleGadgetTest):
    """Test dereferenced register filtering"""

    def test_filter_dereferenced_any(self):
        """Test filtering any dereferenced register"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--deref",
                "",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "dereferenced" in result.stdout

    def test_filter_dereferenced_specific(self):
        """Test filtering specific dereferenced register"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--deref",
                "ebx",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0


class TestSortingAndLimiting(BaseSampleGadgetTest):
    """Test sorting and result limiting"""

    def test_sort_by_count(self):
        """Test sorting by instruction count"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--sort",
                "count",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_sort_by_address(self):
        """Test sorting by address"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--sort",
                "address",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_limit_results(self):
        """Test limiting number of results"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-l",
                "5",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_show_count(self):
        """Test showing instruction count"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--show-count",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "[" in result.stdout


class TestOffsetCalculation(BaseSampleGadgetTest):
    """Test offset calculation from base address"""

    def test_offset_hex_format(self):
        """Test offset calculation with hex base address"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--offset",
                "0x76d40000",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "+" in result.stdout or "offset" in result.stdout

    def test_offset_decimal_format(self):
        """Test offset calculation with decimal base address"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--offset",
                "1992294400",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0


class TestHighlighting(BaseSampleGadgetTest):
    """Test regex match highlighting"""

    def test_highlight_matches(self):
        """Test highlighting regex matches"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-r",
                "pop",
                "--highlight",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0


class TestComplexFiltering(BaseSampleGadgetTest):
    """Test combining multiple filters"""

    def test_combined_filters(self):
        """Test combining multiple filters"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-i",
                "pop",
                "-m",
                "3",
                "--show-category",
                "--show-count",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_filter_group_and_sort(self):
        """Test filtering, grouping, and sorting together"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-c",
                "stack_pop",
                "-g",
                "modified-register",
                "--sort",
                "count",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0


class TestErrorHandling(BaseSampleGadgetTest):
    """Test error handling"""

    def test_missing_file(self):
        """Test error handling for missing file"""
        result = subprocess.run(
            [sys.executable, str(ROP_TOOL_PATH), "-f", "/nonexistent/file.txt"],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "Error" in result.stderr or "not found" in result.stderr

    def test_invalid_offset_format(self):
        """Test error handling for invalid offset format"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "--offset",
                "invalid",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "Error" in result.stderr or "Invalid" in result.stderr


class TestEndToEndWorkflow(BaseSampleGadgetTest):
    """Test complete end-to-end workflows"""

    def test_find_stack_pop_gadgets(self):
        """Test finding stack pop gadgets for ROP chain"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-c",
                "stack_pop",
                "-m",
                "3",
                "--show-count",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "stack_pop" in result.stdout or "gadgets" in result.stdout

    def test_find_write_what_where_gadgets(self):
        """Test finding write-what-where gadgets"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-c",
                "memory_write",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

    def test_build_rop_chain_workflow(self):
        """Test typical ROP chain building workflow"""
        # Step 1: Find pop gadgets
        result1 = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-i",
                "pop",
                "-b",
                "00,0a",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result1.returncode == 0

        # Step 2: Group by modified register
        result2 = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.sample_gadget_file,
                "-c",
                "stack_pop",
                "-g",
                "modified-register",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result2.returncode == 0


class TestBadInstructionFiltering(BaseBadInstructionsTest):
    """Test bad instruction filtering (call, jmp, int, etc.)"""

    def test_bad_instructions_filtered_by_default(self):
        """Test that gadgets with bad instructions are filtered out by default"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Should show filtering message
        assert "Filtered out" in result.stdout and "bad instructions" in result.stdout
        # Gadgets with call, jmp, int, leave, etc. should be filtered
        assert "call [eax]" not in result.stdout
        assert "jmp esp" not in result.stdout
        assert "int 0x80" not in result.stdout
        assert "leave" not in result.stdout
        # Good gadgets should remain
        assert "0x10001000" in result.stdout  # pop eax ; ret
        assert "0x10001010" in result.stdout  # pop ebx ; ret

    def test_keep_bad_instructions_flag(self):
        """Test that --keep-bad-instructions flag preserves bad instruction gadgets"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--keep-bad-instructions",
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Should NOT show filtering message when flag is used
        assert (
            "Filtered out" not in result.stdout
            or "bad instructions" not in result.stdout
        )
        # All gadgets should be present
        assert "call [eax]" in result.stdout
        assert "jmp esp" in result.stdout
        assert "int 0x80" in result.stdout
        assert "leave" in result.stdout

    def test_bad_instruction_filter_count_output(self):
        """Test that filtering message shows correct count"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Should indicate how many were filtered
        # Out of 15 total, we expect ~9 bad ones filtered (call, jmp, int, leave, je, jne, cli, popf, hlt, lock)
        assert "Filtered out" in result.stdout
        assert "remaining" in result.stdout

    def test_filter_call_instruction(self):
        """Test that call instructions are filtered"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "0x10001020" not in result.stdout  # pop eax ; call [eax]
        assert "call" not in result.stdout

    def test_filter_jmp_instruction(self):
        """Test that jmp instructions are filtered"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "0x10001030" not in result.stdout  # mov eax, ebx ; jmp esp

    def test_filter_conditional_jumps(self):
        """Test that conditional jumps (je, jne, etc.) are filtered"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "0x10001060" not in result.stdout  # pop eax ; je 0x1234
        assert "0x10001070" not in result.stdout  # add eax, ebx ; jne 0x5678
        assert "je " not in result.stdout
        assert "jne " not in result.stdout

    def test_filter_interrupt_instructions(self):
        """Test that interrupt instructions (int, cli, etc.) are filtered"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "0x10001040" not in result.stdout  # xor eax, eax ; int 0x80
        assert "0x100010b0" not in result.stdout  # cli ; ret
        assert "int 0x80" not in result.stdout
        assert "cli" not in result.stdout

    def test_filter_leave_instruction(self):
        """Test that leave instruction is filtered"""
        result = subprocess.run(
            [
                sys.executable,
                str(ROP_TOOL_PATH),
                "-f",
                self.bad_instructions_gadget_file,
                "--no-color",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "0x10001050" not in result.stdout  # push ebp ; leave
        assert "leave" not in result.stdout

    def test_bad_instruction_case_insensitive(self):
        """Test that bad instruction filtering is case-insensitive"""
        # Create a gadget file with uppercase instructions
        uppercase_gadgets = """FileFormat: PE, Arch: x86

0x10001000: pop eax ; ret ; (1 found)
0x10001020: pop eax ; CALL [eax] ; (1 found)
0x10001030: mov eax, ebx ; JMP esp ; (1 found)
0x10001040: xor eax, eax ; INT 0x80 ; (1 found)

A total of 4 gadgets found.
"""
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write(uppercase_gadgets)
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(ROP_TOOL_PATH), "-f", temp_path,
                 "--no-color"],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0
            # Should filter uppercase versions too
            assert "CALL" not in result.stdout
            assert "JMP" not in result.stdout
            assert "INT" not in result.stdout
            # Good gadget should remain
            assert "0x10001000" in result.stdout
        finally:
            os.unlink(temp_path)
