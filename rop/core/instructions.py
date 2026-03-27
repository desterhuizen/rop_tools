"""
Shared bad instruction definitions for ROP tools.

Used by both get_rop_gadgets.py (to filter gadgets) and the worksheet
(to warn during auto-execution). Keeping one source of truth avoids
the two tools diverging.
"""

from typing import Dict, List, Optional, Tuple

# Category key → list of opcodes (lowercase).
# Most entries are exact opcode matches.  The "privileged_mov" category
# uses prefix matching ("mov cr", "mov dr", "mov tr") — handled
# specially in classify_bad_instruction().
BAD_INSTRUCTION_CATEGORIES: Dict[str, List[str]] = {
    "privileged": [
        "clts",
        "hlt",
        "lmsw",
        "ltr",
        "lgdt",
        "lidt",
        "lldt",
        "invlpg",
        "invd",
        "swapgs",
        "wbinvd",
    ],
    "privileged_mov": ["mov cr", "mov dr", "mov tr"],
    "io": [
        "in",
        "ins",
        "insb",
        "insw",
        "insd",
        "out",
        "outs",
        "outsb",
        "outsw",
        "outsd",
    ],
    "interrupt": [
        "int",
        "int3",
        "into",
        "iret",
        "iretd",
        "cli",
        "sti",
        "syscall",
        "sysenter",
        "sysret",
        "sysexit",
    ],
    "control_flow": [
        "call",
        "jmp",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "jcxz",
        "jecxz",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
        "loop",
        "loope",
        "loopne",
        "loopnz",
        "loopz",
    ],
    "stack_frame": ["leave", "enter"],
    "flags": ["pushf", "pushfd", "popf", "popfd"],
    "sync": ["lock", "wait", "fwait"],
}

# Human-readable labels shown in warnings and UI.
CATEGORY_LABELS: Dict[str, str] = {
    "privileged": "PRIVILEGED",
    "privileged_mov": "PRIVILEGED",
    "io": "I/O",
    "interrupt": "INTERRUPT",
    "control_flow": "CONTROL FLOW",
    "stack_frame": "STACK FRAME",
    "flags": "FLAGS",
    "sync": "SYNC/PREFIX",
}

# ── Pre-built lookup tables (built once at import time) ──────────────

# opcode → category  (exact match)
_OPCODE_TO_CATEGORY: Dict[str, str] = {}
for _cat, _opcodes in BAD_INSTRUCTION_CATEGORIES.items():
    if _cat == "privileged_mov":
        continue  # handled via prefix matching
    for _op in _opcodes:
        _OPCODE_TO_CATEGORY[_op] = _cat

# prefix strings for the "mov cr/dr/tr" family
_PREFIX_ENTRIES: List[Tuple[str, str]] = [
    (prefix, cat)
    for cat, opcodes in BAD_INSTRUCTION_CATEGORIES.items()
    if cat == "privileged_mov"
    for prefix in opcodes
]


def classify_bad_instruction(
    opcode: str, operands: Optional[List[str]] = None
) -> Optional[str]:
    """
    Check whether *opcode* (+ optional operands) is a bad instruction.

    Args:
        opcode:   Lowercased opcode string (e.g. "hlt", "mov", "jne").
        operands: Optional list of operand strings.  Only needed for
                  detecting "mov cr/dr/tr" variants.

    Returns:
        A human-readable category label (e.g. "PRIVILEGED", "I/O") if
        the instruction is bad, or ``None`` if it is safe.
    """
    # 1. Exact opcode match (covers the vast majority)
    cat = _OPCODE_TO_CATEGORY.get(opcode)
    if cat:
        return CATEGORY_LABELS[cat]

    # 2. Prefix match for "mov cr", "mov dr", "mov tr"
    if opcode == "mov" and operands:
        full = f"mov {operands[0].lower()}"
        for prefix, cat in _PREFIX_ENTRIES:
            if full.startswith(prefix):
                return CATEGORY_LABELS[cat]

    return None


def get_flat_bad_instructions() -> List[str]:
    """
    Return a flat list suitable for substring matching against a full
    instruction chain string.  This preserves backward compatibility
    with the ``_contains_bad_instruction()`` check in
    ``get_rop_gadgets.py``.

    The list uses condensed substring patterns (e.g. ``"in "`` with a
    trailing space, ``"jn"`` to match all jn* jumps) so that a simple
    ``any(bad in chain)`` check works correctly without enumerating
    every conditional jump variant.
    """
    return [
        # privileged
        "clts",
        "hlt",
        "lmsw",
        "ltr",
        "lgdt",
        "lidt",
        "lldt",
        "mov cr",
        "mov dr",
        "mov tr",
        # I/O  ("in " has trailing space to avoid matching "inc")
        "in ",
        "ins",
        "invlpg",
        "invd",
        "out",
        "outs",
        # interrupts / system
        "cli",
        "sti",
        "popf",
        "pushf",
        "int",
        "iret",
        "iretd",
        "swapgs",
        "wbinvd",
        # control flow  (condensed prefixes cover all jn*/jr*/etc.)
        "call",
        "jmp",
        "leave",
        "ja",
        "jb",
        "jc",
        "je",
        "jg",
        "jl",
        "jn",
        "jo",
        "jp",
        "js",
        "jz",
        # stack frame / sync / unknown
        "lock",
        "enter",
        "wait",
        "???",
    ]
