"""Configuration enums and dataclasses for target_builder.

Defines all configuration types: vulnerability types, architectures,
protocols, mitigations, and the main ServerConfig dataclass.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


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


class GadgetDensity(Enum):
    """ROP gadget density in the companion DLL."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


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
    },
    Difficulty.MEDIUM: {
        "buffer_size_range": (256, 512),
        "bad_char_count_range": (3, 6),
        "decoy_count_range": (1, 2),
        "mitigations": ["dep"],
        "vuln_types": [VulnType.BOF, VulnType.SEH, VulnType.FMTSTR],
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
    },
}


@dataclass
class RopDllConfig:
    """Configuration for the optional ROP companion DLL."""

    enabled: bool = False
    output_file: str = "rop_helper.cpp"
    gadget_density: GadgetDensity = GadgetDensity.STANDARD
    no_aslr: bool = True
    base_address: int = 0x10000000


@dataclass
class ExploitConfig:
    """Configuration for the optional exploit skeleton."""

    enabled: bool = False
    level: ExploitLevel = ExploitLevel.CONNECT
    output_file: str = "exploit.py"


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

    def __post_init__(self):
        """Set defaults that depend on other fields."""
        if not self.command:
            self.command = DEFAULT_COMMANDS.get(self.protocol, "TRAD")

    def validate(self):
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
        if self.vuln_type == VulnType.EGGHUNTER:
            if self.vuln_buffer_size >= self.buffer_size:
                raise ValueError(
                    "--vuln-buffer-size must be smaller than --buffer-size "
                    "for egghunter"
                )

        # Egg tag must be exactly 4 bytes
        if self.vuln_type == VulnType.EGGHUNTER:
            if len(self.egg_tag) != 4:
                raise ValueError("--egg tag must be exactly 4 characters")

        # Port range
        if not (1 <= self.port <= 65535):
            raise ValueError("--port must be between 1 and 65535")
