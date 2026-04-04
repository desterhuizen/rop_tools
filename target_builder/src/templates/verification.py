"""Verification checks template.

Generates a C++ verify_input() function with N randomly-selected checks
that the attacker must reverse-engineer before reaching the vulnerable
code path.  Each generated binary has different checks (seeded RNG).

Checks are tiered by difficulty:
  Tier 1 (Basic, checks 1-3): magic byte, forbidden byte, byte equality,
      parity
  Tier 2 (Intermediate, checks 4-6): bitmask, range, modulo, nibble swap
  Tier 3 (Advanced, checks 7+): XOR gate, sum gate, prefix token, checksum
"""

import random
from typing import Dict, List, Tuple

# Short tokens for prefix checks — look like auth tokens / command prefixes
PREFIX_POOL = [
    "AUTH",
    "EXEC",
    "ROOT",
    "PRIV",
    "SUDO",
    "CMD",
    "SYS",
    "KEY",
    "TOK",
    "ACC",
    "SEC",
    "RUN",
    "DBG",
    "SUP",
    "OPS",
    "ADM",
]

# Tier definitions: each tier has a list of check-type names and a range
# of check indices (1-based) that draw from it.
TIER_1_CHECKS = ["magic_byte", "forbidden_byte", "byte_equality", "parity"]
TIER_2_CHECKS = ["bitmask", "range", "modulo", "nibble_swap"]
TIER_3_CHECKS = ["xor_gate", "sum_gate", "prefix", "checksum"]

# Tier boundaries (1-based check number)
TIER_1_MAX = 3  # checks 1-3
TIER_2_MAX = 6  # checks 4-6


def _tier_for_check(check_num: int) -> List[str]:
    """Return the pool of check types available for a given check number."""
    if check_num <= TIER_1_MAX:
        return TIER_1_CHECKS
    elif check_num <= TIER_2_MAX:
        return TIER_2_CHECKS
    else:
        return TIER_3_CHECKS


def generate_verification_function(  # noqa: C901
    level: int,
    seed: int,
) -> Tuple[str, List[Tuple[int, int]]]:
    """Generate a C++ verify_input() function with random checks.

    Args:
        level: Number of verification checks (1-10).
        seed: Random seed for deterministic generation.

    Returns:
        Tuple of (C++ source code, solution) where solution is a list
        of (offset, byte_value) pairs describing one valid input that
        passes all checks.
    """
    if level <= 0:
        return "", []

    rng = random.Random(seed)

    # Available byte offsets in the verification header (first 32 bytes)
    available = list(range(32))

    checks_code: List[str] = []
    solution: Dict[int, int] = {}

    # Track whether prefix has been used (only once allowed)
    prefix_used = False

    for i in range(level):
        check_num = i + 1
        pool = list(_tier_for_check(check_num))

        # Prefix can only appear once and needs offsets 0..N contiguous
        if prefix_used:
            pool = [c for c in pool if c != "prefix"]

        # Two-offset checks need at least 2 available offsets
        multi_offset = {"byte_equality", "xor_gate", "sum_gate"}
        if len(available) < 2:
            pool = [c for c in pool if c not in multi_offset]

        # Checksum needs 3 offsets
        if len(available) < 3:
            pool = [c for c in pool if c != "checksum"]

        # Prefix needs contiguous offsets from 0
        if "prefix" in pool and 0 not in available:
            pool = [c for c in pool if c != "prefix"]

        if not available or not pool:
            break

        check_type = rng.choice(pool)
        if check_type == "prefix":
            prefix_used = True

        code, sol = _generate_check(rng, check_type, available, check_num)
        checks_code.append(code)
        solution.update(sol)

    if not solution:
        return "", []

    # Minimum required data length
    max_offset = max(solution.keys()) + 1

    lines = [
        "// Input verification — reverse this function to find the "
        "required byte pattern",
        "int verify_input(char* data, int data_len) {",
        f"    if (data_len < {max_offset}) return 0;",
        "",
    ]
    for code in checks_code:
        lines.append(code)
    lines.append("    return 1;")
    lines.append("}")

    return "\n".join(lines), sorted(solution.items())


# ---------------------------------------------------------------------------
# Solution formatting helpers
# ---------------------------------------------------------------------------


def format_solution_comment(solution: List[Tuple[int, int]]) -> str:
    """Format the verification solution as a C-style comment block."""
    if not solution:
        return ""

    lines = ["// Verification solution " "(place these bytes at the start of input):"]
    lines.append("// Offset  Value")
    for offset, value in solution:
        char_repr = ""
        if 0x20 <= value <= 0x7E:
            char_repr = f"  ('{chr(value)}')"
        lines.append(f"//   [{offset:2d}]   0x{value:02X}{char_repr}")

    max_offset = max(o for o, _ in solution) + 1
    lines.append(f"// Verification header size: {max_offset} bytes")
    return "\n".join(lines)


def format_solution_python(solution: List[Tuple[int, int]]) -> str:
    """Format the verification solution as Python byte-building code."""
    if not solution:
        return ""

    max_offset = max(o for o, _ in solution) + 1
    lines = [
        f"# Verification header ({max_offset} bytes) — "
        "must precede the overflow payload",
        f"verify_header = bytearray({max_offset})",
    ]
    for offset, value in solution:
        char_repr = ""
        if 0x20 <= value <= 0x7E:
            char_repr = f"  # '{chr(value)}'"
        lines.append(f"verify_header[{offset}] = 0x{value:02X}{char_repr}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Offset helpers
# ---------------------------------------------------------------------------


def _pick_offset(rng: random.Random, available: List[int]) -> int:
    """Pick and remove a single offset from the available pool."""
    idx = rng.randrange(len(available))
    return available.pop(idx)


def _pick_offsets(rng: random.Random, available: List[int], count: int) -> List[int]:
    """Pick and remove *count* offsets from the available pool."""
    result = []
    for _ in range(count):
        idx = rng.randrange(len(available))
        result.append(available.pop(idx))
    return sorted(result)


def _safe_byte(rng: random.Random) -> int:
    """Random byte avoiding 0x00 (null terminator for strcpy)."""
    return rng.randint(0x01, 0xFE)


# ---------------------------------------------------------------------------
# Check generators — each returns (C++ code, solution dict)
# ---------------------------------------------------------------------------


def _generate_check(
    rng: random.Random,
    check_type: str,
    available: List[int],
    check_num: int,
) -> Tuple[str, Dict[int, int]]:
    """Dispatch to the correct check generator."""
    generators = {
        "magic_byte": _gen_magic_byte,
        "forbidden_byte": _gen_forbidden_byte,
        "byte_equality": _gen_byte_equality,
        "parity": _gen_parity,
        "bitmask": _gen_bitmask,
        "range": _gen_range,
        "modulo": _gen_modulo,
        "nibble_swap": _gen_nibble_swap,
        "xor_gate": _gen_xor_gate,
        "sum_gate": _gen_sum_gate,
        "prefix": _gen_prefix,
        "checksum": _gen_checksum,
    }
    return generators[check_type](rng, available, check_num)


# ---- Tier 1: Basic --------------------------------------------------------


def _gen_magic_byte(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[offset] must equal a specific byte."""
    offset = _pick_offset(rng, available)
    value = _safe_byte(rng)
    code = (
        f"    // Check {n}: magic byte\n"
        f"    if ((unsigned char)data[{offset}] != 0x{value:02X})"
        f" return 0;\n"
    )
    return code, {offset: value}


def _gen_forbidden_byte(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[offset] must NOT equal a specific byte."""
    offset = _pick_offset(rng, available)
    # The forbidden value — solution just needs any other non-null byte
    forbidden = _safe_byte(rng)
    # Pick a solution value that differs from the forbidden byte
    value = _safe_byte(rng)
    while value == forbidden:
        value = _safe_byte(rng)
    code = (
        f"    // Check {n}: forbidden byte\n"
        f"    if ((unsigned char)data[{offset}] == 0x{forbidden:02X})"
        f" return 0;\n"
    )
    return code, {offset: value}


def _gen_byte_equality(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[a] must equal data[b]."""
    offsets = _pick_offsets(rng, available, 2)
    a, b = offsets
    value = _safe_byte(rng)
    code = (
        f"    // Check {n}: byte equality\n"
        f"    if ((unsigned char)data[{a}]"
        f" != (unsigned char)data[{b}]) return 0;\n"
    )
    return code, {a: value, b: value}


def _gen_parity(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[offset] must be even or odd."""
    offset = _pick_offset(rng, available)
    want_even = rng.choice([True, False])
    # Pick a solution value matching the parity
    value = _safe_byte(rng)
    if want_even and value % 2 != 0:
        value = (value + 1) & 0xFE or 0x02
    elif not want_even and value % 2 == 0:
        value = value + 1 if value < 0xFE else value - 1
    parity_word = "even" if want_even else "odd"
    expected = 0 if want_even else 1
    code = (
        f"    // Check {n}: parity ({parity_word})\n"
        f"    if (((unsigned char)data[{offset}] & 1)"
        f" != {expected}) return 0;\n"
    )
    return code, {offset: value}


# ---- Tier 2: Intermediate -------------------------------------------------


def _gen_bitmask(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """(data[offset] & mask) must equal expected."""
    offset = _pick_offset(rng, available)
    mask_bits = rng.sample(range(8), rng.randint(3, 6))
    mask = 0
    for bit in mask_bits:
        mask |= 1 << bit
    value = _safe_byte(rng)
    expected = value & mask
    code = (
        f"    // Check {n}: bitmask\n"
        f"    if (((unsigned char)data[{offset}] & 0x{mask:02X})"
        f" != 0x{expected:02X}) return 0;\n"
    )
    return code, {offset: value}


def _gen_range(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[offset] must be within [low, high]."""
    offset = _pick_offset(rng, available)
    low = rng.randint(0x20, 0x60)
    high = rng.randint(low + 0x10, min(low + 0x40, 0xFE))
    value = rng.randint(low, high)
    code = (
        f"    // Check {n}: range\n"
        f"    if ((unsigned char)data[{offset}] < 0x{low:02X} || "
        f"(unsigned char)data[{offset}] > 0x{high:02X}) return 0;\n"
    )
    return code, {offset: value}


def _gen_modulo(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[offset] % divisor must equal remainder."""
    offset = _pick_offset(rng, available)
    divisor = rng.choice([3, 5, 7, 11, 13, 17])
    value = _safe_byte(rng)
    remainder = value % divisor
    code = (
        f"    // Check {n}: modulo\n"
        f"    if ((unsigned char)data[{offset}] % {divisor}"
        f" != {remainder}) return 0;\n"
    )
    return code, {offset: value}


def _gen_nibble_swap(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """Swapping nibbles of data[offset] must equal expected."""
    offset = _pick_offset(rng, available)
    value = _safe_byte(rng)
    swapped = ((value >> 4) & 0x0F) | ((value & 0x0F) << 4)
    code = (
        f"    // Check {n}: nibble swap\n"
        f"    if ((((unsigned char)data[{offset}] >> 4) | "
        f"((unsigned char)data[{offset}] << 4))"
        f" != 0x{swapped:02X}) return 0;\n"
    )
    return code, {offset: value}


# ---- Tier 3: Advanced -----------------------------------------------------


def _gen_xor_gate(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """data[a] XOR data[b] must equal a specific value."""
    offsets = _pick_offsets(rng, available, 2)
    a, b = offsets
    val_a = _safe_byte(rng)
    val_b = _safe_byte(rng)
    expected = val_a ^ val_b
    code = (
        f"    // Check {n}: XOR gate\n"
        f"    if (((unsigned char)data[{a}] ^ "
        f"(unsigned char)data[{b}])"
        f" != 0x{expected:02X}) return 0;\n"
    )
    return code, {a: val_a, b: val_b}


def _gen_sum_gate(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """(data[a] + data[b]) & 0xFF must equal a specific value."""
    offsets = _pick_offsets(rng, available, 2)
    a, b = offsets
    val_a = _safe_byte(rng)
    val_b = _safe_byte(rng)
    expected = (val_a + val_b) & 0xFF
    code = (
        f"    // Check {n}: sum gate\n"
        f"    if ((((unsigned char)data[{a}] + "
        f"(unsigned char)data[{b}]) & 0xFF)"
        f" != 0x{expected:02X}) return 0;\n"
    )
    return code, {a: val_a, b: val_b}


def _gen_prefix(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """First N bytes must match a specific token string."""
    token = rng.choice(PREFIX_POOL)
    sol: Dict[int, int] = {}
    for i, ch in enumerate(token):
        if i in available:
            available.remove(i)
        sol[i] = ord(ch)
    code = (
        f"    // Check {n}: prefix token\n"
        f'    if (strncmp(data, "{token}", {len(token)}) != 0)'
        f" return 0;\n"
    )
    return code, sol


def _gen_checksum(
    rng: random.Random, available: List[int], n: int
) -> Tuple[str, Dict[int, int]]:
    """(data[a] + data[b] + data[c]) & 0xFF must equal expected."""
    offsets = _pick_offsets(rng, available, 3)
    a, b, c = offsets
    val_a = _safe_byte(rng)
    val_b = _safe_byte(rng)
    val_c = _safe_byte(rng)
    expected = (val_a + val_b + val_c) & 0xFF
    code = (
        f"    // Check {n}: checksum\n"
        f"    if ((((unsigned char)data[{a}] + "
        f"(unsigned char)data[{b}] + "
        f"(unsigned char)data[{c}]) & 0xFF)"
        f" != 0x{expected:02X}) return 0;\n"
    )
    return code, {a: val_a, b: val_b, c: val_c}
