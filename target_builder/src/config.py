"""Configuration enums and dataclasses for target_builder.

Defines all configuration types: vulnerability types, architectures,
protocols, mitigations, and the main ServerConfig dataclass.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class VulnType(Enum):
    """Vulnerability type to embed in the generated server."""

    BOF = "bof"
    SEH = "seh"
    EGGHUNTER = "egghunter"
    FMTSTR = "fmtstr"


class Architecture(Enum):
    """Target compilation architecture."""

    X86 = "x86"
    X64 = "x64"


class Compiler(Enum):
    """Target compiler toolchain."""

    MSVC = "msvc"
    MINGW = "mingw"


class Protocol(Enum):
    """Network protocol for the generated server."""

    TCP = "tcp"
    HTTP = "http"
    RPC = "rpc"


class BadCharAction(Enum):
    """How the server handles bad characters in input."""

    DROP = "drop"
    REPLACE = "replace"
    TERMINATE = "terminate"


class Difficulty(Enum):
    """Preset difficulty level for randomized challenges."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class DepBypassApi(Enum):
    """Win32 API imported by the server for DEP bypass ROP chains."""

    VIRTUALPROTECT = "virtualprotect"
    VIRTUALALLOC = "virtualalloc"
    WRITEPROCESSMEMORY = "writeprocessmemory"
    HEAPCREATE = "heapcreate"
    SETPROCESSDEPPOLICY = "setprocessdeppolicy"
    NTALLOCATE = "ntallocate"


class ExploitLevel(Enum):
    """Level of detail in the generated exploit skeleton."""

    CONNECT = "connect"
    INTERACT = "interact"
    CRASH = "crash"


class HintVerbosity(Enum):
    """Level of hint detail in crash-level exploit skeletons."""

    FULL = "full"
    MINIMAL = "minimal"
    NONE = "none"


class GadgetDensity(Enum):
    """ROP gadget density in the companion DLL."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


class PaddingStyle(Enum):
    """Style of stack padding variables generated between buffer and saved EBP."""

    NONE = "none"
    ARRAY = "array"  # Single char array: char pad[N]
    MIXED = "mixed"  # Mix of ints, chars, doubles
    STRUCT = "struct"  # A struct with named fields
    MULTI = "multi"  # Multiple smaller arrays


class DecoyType(Enum):
    """Types of non-exploitable decoy commands."""

    NEAR_MISS_BUFFER = "near_miss_buffer"
    SAFE_FORMAT = "safe_format"
    BOUNDED_COPY = "bounded_copy"
    HEAP_BUFFER = "heap_buffer"


# Architecture constraints for vulnerability types
VULN_ARCH_COMPAT = {
    VulnType.BOF: {Architecture.X86, Architecture.X64},
    VulnType.SEH: {Architecture.X86},
    VulnType.EGGHUNTER: {Architecture.X86},
    VulnType.FMTSTR: {Architecture.X86, Architecture.X64},
}

# Default command names per protocol
DEFAULT_COMMANDS = {
    Protocol.TCP: "TRAD",
    Protocol.HTTP: "/vulnerable",
    Protocol.RPC: "1",
}

# Banner pool for randomization
BANNER_POOL = [
    "FileSync Pro v3.2.1 - Enterprise File Server",
    "DataBridge RPC Service v1.0.4",
    "NetAdmin Console v2.8 - Type HELP for commands",
    "ACME Corp Internal API Gateway v4.1",
    "SecureVault Storage Server v2.0.3",
    "CloudRelay Proxy Service v1.7",
    "TaskMaster Job Scheduler v3.5.0",
    "LogStream Analytics Engine v2.1",
    "PacketForge Network Toolkit v1.3.2",
    "SyncBridge Data Replication v4.0.1",
]

# Decoy command name pool
DECOY_COMMAND_POOL = [
    "PROCESS",
    "QUERY",
    "UPDATE",
    "VALIDATE",
    "MONITOR",
    "ANALYZE",
    "SUBMIT",
    "EXECUTE",
    "TRANSFER",
    "VERIFY",
    "COMPILE",
    "EXPORT",
    "IMPORT",
    "CONFIGURE",
    "OPTIMIZE",
]

# Difficulty preset ranges
DIFFICULTY_PRESETS = {
    Difficulty.EASY: {
        "buffer_size_range": (1024, 2048),
        "bad_char_count_range": (0, 0),
        "decoy_count_range": (0, 0),
        "mitigations": [],
        "vuln_types": [VulnType.BOF],
        "pre_padding_range": (0, 0),
        "landing_pad_range": (0, 0),  # 0 = unlimited
        "padding_styles": [PaddingStyle.NONE],
    },
    Difficulty.MEDIUM: {
        "buffer_size_range": (256, 512),
        "bad_char_count_range": (3, 6),
        "decoy_count_range": (1, 2),
        "mitigations": ["dep"],
        "vuln_types": [VulnType.BOF, VulnType.SEH, VulnType.FMTSTR],
        "pre_padding_range": (32, 128),
        "landing_pad_range": (64, 256),
        "padding_styles": [
            PaddingStyle.NONE,
            PaddingStyle.ARRAY,
            PaddingStyle.MIXED,
        ],
    },
    Difficulty.HARD: {
        "buffer_size_range": (64, 128),
        "bad_char_count_range": (8, 12),
        "decoy_count_range": (3, 5),
        "mitigations": ["dep", "aslr", "stack_canary"],
        "vuln_types": [
            VulnType.BOF,
            VulnType.SEH,
            VulnType.EGGHUNTER,
            VulnType.FMTSTR,
        ],
        "pre_padding_range": (64, 256),
        "landing_pad_range": (8, 32),  # tight — short jump needed
        "padding_styles": [
            PaddingStyle.ARRAY,
            PaddingStyle.MIXED,
            PaddingStyle.STRUCT,
            PaddingStyle.MULTI,
        ],
    },
}


def address_base_bytes(address: int, arch: "Architecture") -> Tuple[int, ...]:
    """Extract the bytes contributed by the base address to code addresses.

    For a 64KB-aligned base, the low 2 bytes are always 0x00 and get
    replaced by the RVA offset in actual code addresses. Only the upper
    non-zero bytes are determined by the base address choice.

    For x86: bytes 2 and 3 (the upper 2 bytes of a 32-bit address).
    For x64: bytes 2-7, but only those that are non-zero. In practice,
    user-mode addresses fit in 32 bits, so this is usually bytes 2 and 3.
    We skip zero bytes in upper positions since they won't appear in the
    actual code addresses (the linker places code in the low RVA range).

    Args:
        address: Base address (must be 0x10000-aligned).
        arch: Target architecture.

    Returns:
        Tuple of byte values contributed by the base address.
    """
    if arch == Architecture.X86:
        return ((address >> 16) & 0xFF, (address >> 24) & 0xFF)
    # x64: check bytes 2 and 3 (same as x86 for sub-4GB addresses)
    # Only include higher bytes if the address actually uses them
    result = [(address >> 16) & 0xFF, (address >> 24) & 0xFF]
    for i in range(4, 8):
        byte_val = (address >> (i * 8)) & 0xFF
        if byte_val != 0:
            result.append(byte_val)
    return tuple(result)


def address_conflicts_with_bad_chars(
    address: int, bad_chars: List[int], arch: "Architecture"
) -> bool:
    """Check if a base address has bytes that conflict with bad characters.

    Only checks the bytes contributed by the base address (upper bytes),
    not the low 2 bytes which come from the RVA offset.

    Args:
        address: Base address to check.
        bad_chars: List of bad character byte values.
        arch: Target architecture.

    Returns:
        True if any base-contributed byte is in bad_chars.
    """
    if not bad_chars:
        return False
    bad_set = set(bad_chars)
    return any(b in bad_set for b in address_base_bytes(address, arch))


def find_safe_base_address(bad_chars: List[int], arch: "Architecture") -> int:
    """Find a base address whose upper bytes avoid all bad characters.

    Searches for a 64KB-aligned address where the bytes contributed by
    the base (upper 2 bytes for x86) don't conflict with bad characters.

    Args:
        bad_chars: List of bad character byte values.
        arch: Target architecture.

    Returns:
        A safe base address.

    Raises:
        ValueError: If no safe address can be found.
    """
    # Preferred candidates — common exploit-friendly addresses
    preferred = [
        0x11110000,
        0x22220000,
        0x33330000,
        0x44440000,
        0x55550000,
        0x66660000,
        0x77770000,
        0x11120000,
        0x11130000,
        0x21210000,
        0x31310000,
        0x41410000,
        0x51510000,
        0x61610000,
        0x71710000,
    ]

    for candidate in preferred:
        if not address_conflicts_with_bad_chars(candidate, bad_chars, arch):
            return candidate

    # Systematic scan: 0x01010000 to 0x7FFE0000 in 0x10000 steps
    for addr in range(0x01010000, 0x7FFE0000, 0x10000):
        if not address_conflicts_with_bad_chars(addr, bad_chars, arch):
            return addr

    raise ValueError(
        "Cannot find a base address whose upper bytes avoid all bad characters"
    )


def find_random_base_address(
    bad_chars: List[int],
    arch: "Architecture",
    rng: object,
) -> int:
    """Pick a random 64KB-aligned base address avoiding bad chars.

    Randomly selects upper two bytes (for x86) that aren't in bad_chars,
    producing addresses like 0x62340000 instead of always 0x11110000.
    Falls back to find_safe_base_address if no random pick works quickly.

    Args:
        bad_chars: Byte values to avoid in upper address bytes.
        arch: Target architecture.
        rng: A random.Random instance for reproducible selection.
    """
    bad_set = set(bad_chars)
    # Valid byte range for upper bytes: 0x01-0x7F (stay in user-space for x86)
    safe_bytes = [b for b in range(0x01, 0x80) if b not in bad_set]
    if not safe_bytes:
        return find_safe_base_address(bad_chars, arch)

    # Try random combinations
    for _ in range(100):
        b3 = rng.choice(safe_bytes)  # byte 3 (highest)
        b2 = rng.choice(safe_bytes)  # byte 2
        addr = (b3 << 24) | (b2 << 16)
        if not address_conflicts_with_bad_chars(addr, bad_chars, arch):
            return addr

    return find_safe_base_address(bad_chars, arch)


@dataclass
class StackLayoutConfig:
    """Configuration for stack layout variation in the vulnerable function.

    Controls padding between the buffer and saved EBP/EIP (affects offset),
    landing pad size after EIP (forces short jumps when tight), and the
    visual style of padding variables on the stack.
    """

    pre_padding_size: int = 0
    """Bytes of local variables declared before the vulnerable buffer.
    These sit between the buffer and saved EBP, increasing the offset
    to EIP that the attacker must calculate."""

    landing_pad_size: int = 0
    """Max bytes of controlled data after EIP overwrite. 0 = unlimited.
    When small (8-32), the attacker must use a short jump backward
    to reach shellcode placed before the return address."""

    padding_style: PaddingStyle = PaddingStyle.NONE
    """Style of padding variables generated in C++ code."""


@dataclass
class EmbeddedGadgetsConfig:
    """Configuration for embedding ROP gadgets directly in the server binary."""

    enabled: bool = False
    gadget_density: GadgetDensity = GadgetDensity.STANDARD
    seed: Optional[int] = None


@dataclass
class RopDllConfig:
    """Configuration for the optional ROP companion DLL."""

    enabled: bool = False
    output_file: str = "rop_helper.cpp"
    gadget_density: GadgetDensity = GadgetDensity.STANDARD
    no_aslr: bool = True
    base_address: int = 0x10000000
    seed: Optional[int] = None


@dataclass
class ExploitConfig:
    """Configuration for the optional exploit skeleton."""

    enabled: bool = False
    level: ExploitLevel = ExploitLevel.CONNECT
    output_file: str = "exploit.py"
    hint_verbosity: HintVerbosity = HintVerbosity.FULL


@dataclass
class ServerConfig:
    """Complete configuration for a generated vulnerable server.

    This is the central data structure passed through the rendering pipeline.
    CLI parsing produces a ServerConfig, which templates consume to generate C++.
    """

    # Required
    vuln_type: VulnType = VulnType.BOF

    # Server settings
    port: int = 9999
    arch: Architecture = Architecture.X86
    buffer_size: int = 2048
    protocol: Protocol = Protocol.TCP
    command: str = ""
    additional_commands: List[str] = field(
        default_factory=lambda: ["HELP", "STATS", "EXIT"]
    )
    banner: str = ""

    # Base address — default 0x11110000 avoids null bytes in code addresses
    base_address: int = 0x11110000

    # Compiler toolchain
    compiler: Compiler = Compiler.MSVC

    # Bad characters
    bad_chars: List[int] = field(default_factory=list)
    bad_char_action: BadCharAction = BadCharAction.DROP

    # Egghunter-specific
    egg_tag: str = "w00t"
    vuln_buffer_size: int = 128

    # SEH-specific
    seh_offset: Optional[int] = None

    # Mitigations
    dep: bool = False
    dep_api: DepBypassApi = DepBypassApi.VIRTUALPROTECT
    aslr: bool = False
    stack_canary: bool = False
    safe_seh: bool = False
    fmtstr_leak: bool = False

    # Decoys
    decoy_count: int = 0
    decoy_types: List[DecoyType] = field(default_factory=list)
    decoy_names: List[str] = field(default_factory=list)

    # Randomization
    random: bool = False
    random_seed: Optional[int] = None
    difficulty: Optional[Difficulty] = None

    # Output
    output_file: str = ""
    build_script: bool = False
    no_color: bool = False
    cheat_sheet: bool = False

    # Sub-configs
    exploit: ExploitConfig = field(default_factory=ExploitConfig)
    rop_dll: RopDllConfig = field(default_factory=RopDllConfig)
    embedded_gadgets: EmbeddedGadgetsConfig = field(
        default_factory=EmbeddedGadgetsConfig
    )
    stack_layout: StackLayoutConfig = field(default_factory=StackLayoutConfig)

    def __post_init__(self):
        """Set defaults that depend on other fields."""
        if not self.command:
            self.command = DEFAULT_COMMANDS.get(self.protocol, "TRAD")

    def validate(self):  # noqa: C901
        """Validate configuration, raising ValueError on invalid combos."""
        # Architecture constraints
        allowed_archs = VULN_ARCH_COMPAT.get(self.vuln_type, set())
        if self.arch not in allowed_archs:
            raise ValueError(
                f"--vuln {self.vuln_type.value} is not supported on "
                f"--arch {self.arch.value}"
            )

        # SafeSEH requires SEH vuln type
        if self.safe_seh and self.vuln_type != VulnType.SEH:
            raise ValueError("--safeSEH requires --vuln seh")

        # Buffer size sanity
        if self.buffer_size < 16:
            raise ValueError("--buffer-size must be at least 16")

        # Egghunter vuln buffer must be smaller than main buffer
        if (
            self.vuln_type == VulnType.EGGHUNTER
            and self.vuln_buffer_size >= self.buffer_size
        ):
            raise ValueError(
                "--vuln-buffer-size must be smaller than --buffer-size for egghunter"
            )

        # Egg tag must be exactly 4 bytes
        if self.vuln_type == VulnType.EGGHUNTER and len(self.egg_tag) != 4:
            raise ValueError("--egg tag must be exactly 4 characters")

        # Base address validation
        self._validate_base_address()

        # ROP DLL base address validation against bad chars
        if (
            self.rop_dll.enabled
            and self.bad_chars
            and address_conflicts_with_bad_chars(
                self.rop_dll.base_address, self.bad_chars, self.arch
            )
        ):
            raise ValueError(
                f"--rop-dll-base 0x{self.rop_dll.base_address:08X} "
                "contains bytes that conflict with --bad-chars"
            )

        # Embedded gadgets constraints
        if self.embedded_gadgets.enabled:
            if self.arch != Architecture.X86:
                raise ValueError(
                    "--embedded-gadgets requires --arch x86 " "(MSVC __asm is x86 only)"
                )
            if self.rop_dll.enabled:
                raise ValueError(
                    "--embedded-gadgets and --rop-dll are mutually exclusive"
                )

        # MinGW constraints — inline asm gadgets are MSVC-only
        if self.compiler == Compiler.MINGW:
            if self.rop_dll.enabled:
                raise ValueError(
                    "--rop-dll requires MSVC inline assembly; "
                    "use --compiler msvc for --rop-dll"
                )
            if self.embedded_gadgets.enabled:
                raise ValueError(
                    "--embedded-gadgets requires MSVC inline assembly; "
                    "use --compiler msvc for --embedded-gadgets"
                )

        # Stack layout validation
        if self.stack_layout.pre_padding_size < 0:
            raise ValueError("--pre-padding must be non-negative")
        if self.stack_layout.landing_pad_size < 0:
            raise ValueError("--landing-pad must be non-negative")

        # Port range
        if not (1 <= self.port <= 65535):
            raise ValueError("--port must be between 1 and 65535")

    def _validate_base_address(self):
        """Validate the base_address field (called when not None)."""
        if self.base_address % 0x10000 != 0:
            raise ValueError("--base-address must be aligned to 0x10000 (64KB)")
        if self.arch == Architecture.X86 and not (
            0x10000 <= self.base_address <= 0x7FFE0000
        ):
            raise ValueError(
                "--base-address must be between 0x00010000 and " "0x7FFE0000 for x86"
            )
        if self.bad_chars and address_conflicts_with_bad_chars(
            self.base_address, self.bad_chars, self.arch
        ):
            raise ValueError(
                f"--base-address 0x{self.base_address:08X} contains bytes "
                "that conflict with --bad-chars"
            )
