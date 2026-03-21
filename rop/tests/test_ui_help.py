"""
Tests for worksheet/ui/help.py

Tests help text constants and help panel generation.
"""

import unittest

from rich.panel import Panel

from rop.worksheet.ui.help import HELP, build_help_panel


class TestHelp(unittest.TestCase):
    """Test cases for help module."""

    def test_help_text_exists(self):
        """Test that HELP constant exists and is not empty."""
        self.assertIsNotNone(HELP)
        self.assertIsInstance(HELP, str)
        self.assertGreater(len(HELP), 0)

    def test_help_contains_asm_operations(self):
        """Test that help text contains ASM operation documentation."""
        self.assertIn("mov", HELP)
        self.assertIn("add", HELP)
        self.assertIn("xor", HELP)
        self.assertIn("xchg", HELP)
        self.assertIn("inc", HELP)
        self.assertIn("dec", HELP)
        self.assertIn("neg", HELP)
        self.assertIn("push", HELP)
        self.assertIn("pop", HELP)

    def test_help_contains_quick_operations(self):
        """Test that help text contains quick operation documentation."""
        self.assertIn("set", HELP)
        self.assertIn("clr", HELP)
        self.assertIn("name", HELP)
        self.assertIn("stack", HELP)

    def test_help_contains_gadget_commands(self):
        """Test that help text contains gadget library documentation."""
        self.assertIn("gadget", HELP)
        self.assertIn("chain", HELP)

    def test_help_contains_import_commands(self):
        """Test that help text contains WinDbg import documentation."""
        self.assertIn("importregs", HELP)
        self.assertIn("importstack", HELP)

    def test_help_contains_file_commands(self):
        """Test that help text contains file operation documentation."""
        self.assertIn("save", HELP)
        self.assertIn("load", HELP)
        self.assertIn("new", HELP)
        self.assertIn("quit", HELP)

    def test_help_contains_display_commands(self):
        """Test that help text contains display commands."""
        self.assertIn("help", HELP)
        # 'v' for view should be documented
        self.assertIn("v", HELP)

    def test_help_contains_examples(self):
        """Test that help text contains usage examples."""
        self.assertIn("EXAMPLES", HELP)
        self.assertIn("0xdeadbeef", HELP)
        self.assertIn("ESP+0x", HELP)

    def test_help_contains_chain_workflow(self):
        """Test that help text contains ROP chain workflow examples."""
        self.assertIn("ROP Chain", HELP)
        self.assertIn("chain add", HELP)
        self.assertIn("chain del", HELP)

    def test_help_contains_execution_log_info(self):
        """Test that help text contains execution log documentation."""
        self.assertIn("EXECUTION LOG", HELP)
        self.assertIn("logmanual", HELP)
        self.assertIn("auto", HELP)

    def test_help_contains_navigation_info(self):
        """Test that help text contains navigation shortcuts."""
        self.assertIn("Navigation", HELP)
        self.assertIn("TAB", HELP)

    def test_help_text_formatting(self):
        """Test that help text uses Rich markup."""
        # Should contain Rich color tags
        self.assertIn("[bold", HELP)
        self.assertIn("[yellow]", HELP)
        self.assertIn("[/yellow]", HELP)
        self.assertIn("[bold cyan]", HELP)

    def test_build_help_panel_returns_panel(self):
        """Test that build_help_panel returns a Rich Panel object."""
        panel = build_help_panel()
        self.assertIsInstance(panel, Panel)

    def test_help_panel_has_title(self):
        """Test that help panel has a title."""
        panel = build_help_panel()
        self.assertIsNotNone(panel.title)
        self.assertIn("QUICK", str(panel.title).upper())

    def test_help_panel_contains_quick_reference(self):
        """Test that help panel contains quick command reference."""
        panel = build_help_panel()
        # Panel should have renderable content
        self.assertIsNotNone(panel.renderable)

        # Convert panel to string to check content
        panel_str = str(panel.renderable)

        # Should contain key command categories
        self.assertIn("ASM", panel_str)
        self.assertIn("mov", panel_str)
        self.assertIn("Quick", panel_str)
        self.assertIn("set", panel_str)
        self.assertIn("Import", panel_str)
        self.assertIn("ROP", panel_str)

    def test_help_panel_contains_shortcuts(self):
        """Test that help panel contains keyboard shortcuts."""
        panel = build_help_panel()
        panel_str = str(panel.renderable)

        # Should mention TAB completion and history
        self.assertIn("TAB", panel_str)

    def test_help_panel_has_border_style(self):
        """Test that help panel has a border style."""
        panel = build_help_panel()
        self.assertIsNotNone(panel.border_style)

    def test_help_panel_is_compact(self):
        """Test that help panel is compact (one line)."""
        panel = build_help_panel()
        panel_str = str(panel.renderable)

        # Should be a single line (no newlines in content)
        # Note: This is a compact reference, not full help
        self.assertLess(panel_str.count("\n"), 3)

    def test_help_text_has_register_examples(self):
        """Test that help text includes register examples."""
        self.assertIn("EAX", HELP)
        self.assertIn("EBX", HELP)

    def test_help_text_has_hex_value_examples(self):
        """Test that help text includes hexadecimal value examples."""
        self.assertIn("0x", HELP)
        self.assertIn("0xdeadbeef", HELP)

    def test_help_text_has_address_examples(self):
        """Test that help text includes memory address examples."""
        self.assertIn("0x10001234", HELP)

    def test_help_text_has_gadget_examples(self):
        """Test that help text includes gadget examples."""
        self.assertIn("pop eax ; ret", HELP)

    def test_help_text_command_aliases(self):
        """Test that help text documents command aliases."""
        self.assertIn("alias", HELP.lower())
        # 's' is alias for 'set'
        self.assertIn("alias: s", HELP)
        # 'clear' is alias for 'clr'
        self.assertIn("alias: clear", HELP)

    def test_help_text_has_auto_gadget_info(self):
        """Test that help text documents auto-gadget feature."""
        self.assertIn("auto", HELP)
        self.assertIn("Auto", HELP)

    def test_help_text_has_gadget_id_info(self):
        """Test that help text documents gadget ID usage (G1, G2, etc)."""
        self.assertIn("G1", HELP)
        self.assertIn("G2", HELP)
        self.assertIn("Gadget ID", HELP)

    def test_help_text_structure(self):
        """Test that help text has proper structure with sections."""
        # Should have command sections
        self.assertIn("COMMANDS", HELP.upper())

        # Should have examples section
        self.assertIn("EXAMPLES", HELP.upper())

        # Should be well-organized with categories
        self.assertIn("ASM Operations", HELP)
        self.assertIn("Quick Operations", HELP)
        self.assertIn("Gadget Library", HELP)
        self.assertIn("ROP Chain", HELP)
        self.assertIn("Import from WinDbg", HELP)
        self.assertIn("Display & File", HELP)


class TestHelpTextCompleteness(unittest.TestCase):
    """Test that help text is complete and comprehensive."""

    def test_all_basic_asm_ops_documented(self):
        """Test that all basic ASM operations are documented."""
        asm_ops = ["mov", "add", "xor", "xchg", "inc", "dec", "neg", "push",
                   "pop"]
        for op in asm_ops:
            with self.subTest(op=op):
                self.assertIn(op, HELP)

    def test_all_quick_ops_documented(self):
        """Test that all quick operations are documented."""
        quick_ops = ["set", "clr", "name", "stack"]
        for op in quick_ops:
            with self.subTest(op=op):
                self.assertIn(op, HELP)

    def test_all_file_ops_documented(self):
        """Test that all file operations are documented."""
        file_ops = ["save", "load", "new", "quit"]
        for op in file_ops:
            with self.subTest(op=op):
                self.assertIn(op, HELP)

    def test_all_import_ops_documented(self):
        """Test that all import operations are documented."""
        import_ops = ["importregs", "importstack"]
        for op in import_ops:
            with self.subTest(op=op):
                self.assertIn(op, HELP)

    def test_gadget_operations_documented(self):
        """Test that gadget operations are documented."""
        gadget_ops = ["gadget", "chain"]
        for op in gadget_ops:
            with self.subTest(op=op):
                self.assertIn(op, HELP)

    def test_chain_subcommands_documented(self):
        """Test that chain subcommands are documented."""
        self.assertIn("chain add", HELP)
        self.assertIn("chain del", HELP)
        self.assertIn("chain clear", HELP)

    def test_gadget_subcommands_documented(self):
        """Test that gadget subcommands are documented."""
        self.assertIn("gadget del", HELP)
        self.assertIn("gadget clear", HELP)


if __name__ == "__main__":
    unittest.main()
