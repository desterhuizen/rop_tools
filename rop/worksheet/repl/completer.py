"""
Tab completion for the ROP worksheet REPL.

This module provides context-aware autocomplete for commands, registers,
stack offsets, named values, and file names.
"""

import os
import readline
from typing import Any, Dict, List, Optional


class WorksheetCompleter:
    """Tab completion for ROP worksheet commands."""

    def __init__(self, ws: Dict[str, Any]):
        """
        Initialize completer with worksheet reference.

        Args:
            ws: Worksheet dictionary
        """
        self.ws = ws
        self.commands = [
            # ASM operations
            "mov",
            "add",
            "xor",
            "xchg",
            "inc",
            "dec",
            "neg",
            "push",
            "pop",
            # Quick ops
            "set",
            "clr",
            "name",
            "stack",
            # Import
            "importregs",
            "importstack",
            # Gadget & Chain
            "gadget",
            "chain",
            "del",
            # File/display
            "save",
            "load",
            "new",
            "notes",
            "v",
            "help",
            "quit",
            "auto",
            "logmanual",
        ]
        self.registers = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]
        self.common_stack_offsets = [
            "ESP+0x00",
            "ESP+0x04",
            "ESP+0x08",
            "ESP+0x0c",
            "ESP+0x10",
            "ESP+0x14",
            "ESP+0x18",
            "ESP+0x1c",
            "ESP+0x20",
            "ESP+0x24",
            "ESP+0x28",
            "ESP+0x2c",
        ]

    def _complete_commands(self, text: str) -> List[str]:
        """
        Complete command names.

        Args:
            text: Text to complete

        Returns:
            List of matching commands
        """
        return [cmd for cmd in self.commands if cmd.startswith(text.lower())]

    def _complete_register_context(self, text: str) -> List[str]:
        """
        Complete in register/value context (after mov, set, etc).

        Args:
            text: Text to complete

        Returns:
            List of matching candidates (registers, offsets, named values)
        """
        candidates = []

        # Add registers
        candidates.extend([r for r in self.registers if r.lower().startswith(text.lower())])

        # Add common stack offsets
        candidates.extend(
            [s for s in self.common_stack_offsets if s.lower().startswith(text.lower())]
        )

        # Add named values from worksheet
        candidates.extend([n for n in self.ws["named"].keys() if n.startswith(text)])

        # Add stack entries from worksheet
        for offset in self.ws["stack"].keys():
            stack_ref = f"ESP{offset}"
            if stack_ref.lower().startswith(text.lower()):
                candidates.append(stack_ref)

        return candidates

    def _complete_chain_indices(self, text: str) -> List[str]:
        """
        Complete chain indices for del command.

        Args:
            text: Text to complete

        Returns:
            List of matching chain indices
        """
        max_idx = len(self.ws["chain"])
        return [str(i) for i in range(1, max_idx + 1) if str(i).startswith(text)]

    def _complete_json_files(self, text: str) -> List[str]:
        """
        Complete JSON filenames for save/load commands.

        Args:
            text: Text to complete

        Returns:
            List of matching JSON files
        """
        try:
            json_files = [f for f in os.listdir(".") if f.endswith(".json")]
            return [f for f in json_files if f.startswith(text)]
        except OSError:
            return []

    def _get_candidates(self, text: str, tokens: List[str], line: str) -> List[str]:
        """
        Get completion candidates based on context.

        Args:
            text: Text to complete
            tokens: Line tokens
            line: Full line buffer

        Returns:
            List of completion candidates
        """
        # First word - complete commands
        if not tokens or (len(tokens) == 1 and not line.endswith(" ")):
            return self._complete_commands(text)

        # Get the command
        command = tokens[0].lower()

        # After register/value commands - complete with registers, offsets, named values
        if command in ["mov", "move", "m", "xchg", "set", "s", "clr", "clear", "stack"]:
            return self._complete_register_context(text)

        # After 'del' - complete with chain indices
        if command in ["del", "delete", "rm"]:
            return self._complete_chain_indices(text)

        # After 'save' or 'load' - complete with .json files
        if command in ["save", "load"]:
            return self._complete_json_files(text)

        return []

    def complete(self, text: str, state: int) -> Optional[str]:
        """
        Readline completion function.

        Args:
            text: Text to complete
            state: Completion state (0-indexed)

        Returns:
            Completion candidate or None
        """
        line = readline.get_line_buffer()
        tokens = line.split()

        candidates = self._get_candidates(text, tokens, line)

        # Return the state-th candidate
        try:
            return candidates[state]
        except IndexError:
            return None
