"""
Tab completion for the ROP worksheet REPL.

This module provides context-aware autocomplete for commands, registers,
stack offsets, named values, and file names.
"""

import os
import readline
from typing import Dict, Any, List, Optional


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
            "mov", "add", "xor", "xchg", "inc", "dec", "neg", "push", "pop",
            # Quick ops
            "set", "clr", "name", "stack",
            # Import
            "importregs", "importstack",
            # Gadget & Chain
            "gadget", "chain", "del",
            # File/display
            "save", "load", "new", "notes", "v", "help", "quit", "auto", "logmanual"
        ]
        self.registers = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]
        self.common_stack_offsets = [
            "ESP+0x00", "ESP+0x04", "ESP+0x08", "ESP+0x0c",
            "ESP+0x10", "ESP+0x14", "ESP+0x18", "ESP+0x1c",
            "ESP+0x20", "ESP+0x24", "ESP+0x28", "ESP+0x2c",
        ]

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

        # First word - complete commands
        if not tokens or (len(tokens) == 1 and not line.endswith(' ')):
            candidates = [cmd for cmd in self.commands if cmd.startswith(text.lower())]

        # After 'mov', 'xchg', 'set', 'clr', 'stack' - complete with registers, stack offsets, named values
        elif len(tokens) >= 1 and tokens[0].lower() in ['mov', 'move', 'm', 'xchg', 'set', 's', 'clr', 'clear', 'stack']:
            candidates = []

            # Add registers
            candidates.extend([r for r in self.registers if r.lower().startswith(text.lower())])

            # Add common stack offsets
            candidates.extend([s for s in self.common_stack_offsets if s.lower().startswith(text.lower())])

            # Add named values from worksheet
            candidates.extend([n for n in self.ws["named"].keys() if n.startswith(text)])

            # Add stack entries from worksheet
            for offset in self.ws["stack"].keys():
                stack_ref = f"ESP{offset}"
                if stack_ref.lower().startswith(text.lower()):
                    candidates.append(stack_ref)

        # After 'del' - complete with chain indices
        elif len(tokens) >= 1 and tokens[0].lower() in ['del', 'delete', 'rm']:
            max_idx = len(self.ws["chain"])
            candidates = [str(i) for i in range(1, max_idx + 1) if str(i).startswith(text)]

        # After 'save' or 'load' - complete with .json files
        elif len(tokens) >= 1 and tokens[0].lower() in ['save', 'load']:
            try:
                json_files = [f for f in os.listdir('.') if f.endswith('.json')]
                candidates = [f for f in json_files if f.startswith(text)]
            except:
                candidates = []

        else:
            candidates = []

        # Return the state-th candidate
        try:
            return candidates[state]
        except IndexError:
            return None