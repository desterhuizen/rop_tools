"""
Worksheet operations - ASM instructions, stack manipulation, and quick operations.
"""

from .asm_ops import cmd_add, cmd_dec, cmd_inc, cmd_move, cmd_neg, cmd_xchg, cmd_xor
from .quick_ops import cmd_clear, cmd_set
from .stack_ops import cmd_pop, cmd_push, cmd_stack

__all__ = [
    # ASM operations
    "cmd_move",
    "cmd_add",
    "cmd_xor",
    "cmd_xchg",
    "cmd_inc",
    "cmd_dec",
    "cmd_neg",
    # Stack operations
    "cmd_push",
    "cmd_pop",
    "cmd_stack",
    # Quick operations
    "cmd_set",
    "cmd_clear",
]
