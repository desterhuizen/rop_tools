"""
Worksheet operations - ASM instructions, stack manipulation, and quick operations.
"""

from .asm_ops import (
    cmd_add,
    cmd_and,
    cmd_cdq,
    cmd_dec,
    cmd_inc,
    cmd_lea,
    cmd_lodsd,
    cmd_move,
    cmd_movsxd,
    cmd_movzx,
    cmd_neg,
    cmd_nop,
    cmd_not,
    cmd_or,
    cmd_rol,
    cmd_ror,
    cmd_shl,
    cmd_shr,
    cmd_stosd,
    cmd_sub,
    cmd_xchg,
    cmd_xor,
)
from .quick_ops import cmd_clear, cmd_set
from .stack_ops import cmd_pop, cmd_push, cmd_stack

__all__ = [
    # ASM operations
    "cmd_move",
    "cmd_add",
    "cmd_sub",
    "cmd_xor",
    "cmd_xchg",
    "cmd_inc",
    "cmd_dec",
    "cmd_neg",
    # Phase 2 - Two-operand
    "cmd_and",
    "cmd_or",
    "cmd_shl",
    "cmd_shr",
    "cmd_ror",
    "cmd_rol",
    # Phase 3 - Single-operand
    "cmd_not",
    # Phase 4 - Zero-operand
    "cmd_cdq",
    "cmd_lodsd",
    "cmd_stosd",
    "cmd_nop",
    # Phase 5 - Data movement
    "cmd_movzx",
    "cmd_movsxd",
    # Phase 6 - LEA
    "cmd_lea",
    # Stack operations
    "cmd_push",
    "cmd_pop",
    "cmd_stack",
    # Quick operations
    "cmd_set",
    "cmd_clear",
]
