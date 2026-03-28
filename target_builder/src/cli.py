"""CLI interface for target_builder.

Argparse definition, validation, randomization logic, and orchestration.
"""

import argparse
import enum
import random
import sys
from typing import FrozenSet, List, Optional, Type

from target_builder.src.build_script import generate as generate_build
from target_builder.src.config import (
    BANNER_POOL,
    DATA_STAGING_CMD_POOL,
    DECOY_COMMAND_POOL,
    DIFFICULTY_PRESETS,
    LEAK_FUNC_POOL,
    VULN_ARCH_COMPAT,
    Architecture,
    BadCharAction,
    Compiler,
    DecoyType,
    DepBypassApi,
    Difficulty,
    EmbeddedGadgetsConfig,
    ExploitConfig,
    ExploitLevel,
    GadgetDensity,
    HintVerbosity,
    PaddingStyle,
    Protocol,
    RopDllConfig,
    ServerConfig,
    StackLayoutConfig,
    VulnType,
    find_random_base_address,
    find_safe_base_address,
)
from target_builder.src.exploit_skeleton import generate as generate_exploit
from target_builder.src.renderer import render
from target_builder.src.templates.rop_dll import generate_rop_dll


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="target_builder",
        description=(
            "Generate compilable C++ Windows servers with configurable "
            "vulnerabilities for authorized security testing."
        ),
    )

    # Required
    parser.add_argument(
        "--vuln",
        type=str,
        default=None,
        help=(
            "Vulnerability type: bof, seh, egghunter, fmtstr. "
            "Comma-separated list with --random to constrain pool "
            "(e.g. --vuln bof,seh)"
        ),
    )

    # Server settings
    server = parser.add_argument_group("Server")
    server.add_argument(
        "--port",
        type=int,
        default=9999,
        help="Listen port (default: 9999)",
    )
    server.add_argument(
        "--arch",
        type=str,
        choices=[a.value for a in Architecture],
        default=None,
        help="Target architecture (default: x86)",
    )
    server.add_argument(
        "--buffer-size",
        type=int,
        default=2048,
        help="Vulnerable buffer size in bytes (default: 2048)",
    )
    server.add_argument(
        "--protocol",
        type=str,
        default=None,
        help=(
            "Network protocol: tcp, http, rpc. "
            "Comma-separated list with --random (e.g. --protocol tcp,http). "
            "Default: tcp"
        ),
    )
    server.add_argument(
        "--command",
        type=str,
        default="",
        help="Command that triggers the vulnerability",
    )
    server.add_argument(
        "--additional-commands",
        type=str,
        default="HELP,STATS,EXIT",
        help="Comma-separated safe commands (default: HELP,STATS,EXIT)",
    )
    server.add_argument(
        "--decoy-commands",
        type=int,
        default=0,
        help="Number of decoy commands (default: 0)",
    )
    server.add_argument(
        "--banner",
        type=str,
        default="",
        help="Custom server banner",
    )
    server.add_argument(
        "--base-address",
        type=str,
        default=None,
        help=(
            'EXE base address: hex address or "auto" to avoid bad chars '
            "(default: 0x11110000)"
        ),
    )

    # Bad characters
    bad = parser.add_argument_group("Bad Characters")
    bad.add_argument(
        "--bad-chars",
        type=str,
        default="",
        help='Hex bytes to filter, e.g. "00,0a,0d,25"',
    )
    bad.add_argument(
        "--bad-char-count",
        type=int,
        default=0,
        help="Generate N random bad chars",
    )
    bad.add_argument(
        "--bad-char-action",
        type=str,
        default=None,
        help=(
            "How server handles bad chars: drop, replace, terminate. "
            "Comma-separated list with --random. Default: drop"
        ),
    )

    # Egghunter
    egg = parser.add_argument_group("Egghunter")
    egg.add_argument(
        "--egg",
        type=str,
        default="w00t",
        help='4-byte egg tag (default: "w00t")',
    )
    egg.add_argument(
        "--vuln-buffer-size",
        type=int,
        default=128,
        help="Small overflow buffer size (default: 128)",
    )

    # SEH
    seh = parser.add_argument_group("SEH")
    seh.add_argument(
        "--seh-offset",
        type=int,
        default=None,
        help="Bytes before SEH handler overwrite (default: auto)",
    )

    # Stack layout
    stk = parser.add_argument_group("Stack Layout")
    stk.add_argument(
        "--pre-padding",
        type=int,
        default=0,
        help="Bytes of padding between buffer and saved EBP (default: 0)",
    )
    stk.add_argument(
        "--landing-pad",
        type=int,
        default=0,
        help=(
            "Max shellcode bytes after EIP overwrite; "
            "0=unlimited (default: 0). Small values force short jumps."
        ),
    )
    stk.add_argument(
        "--padding-style",
        type=str,
        default=None,
        help=(
            "Style of stack padding variables: none, array, mixed, struct, multi. "
            "Comma-separated list with --random. Default: none"
        ),
    )

    # Mitigations
    mit = parser.add_argument_group("Mitigations")
    mit.add_argument(
        "--dep",
        action="store_true",
        help="Enable DEP",
    )
    mit.add_argument(
        "--dep-api",
        type=str,
        choices=[a.value for a in DepBypassApi],
        default=None,
        help="DEP bypass API (default: virtualprotect)",
    )
    mit.add_argument(
        "--aslr",
        action="store_true",
        help="Enable ASLR (adds info leak)",
    )
    mit.add_argument(
        "--stack-canary",
        action="store_true",
        help="Enable /GS stack cookies",
    )
    mit.add_argument(
        "--safeSEH",
        action="store_true",
        help="Enable SafeSEH (--vuln seh only)",
    )
    mit.add_argument(
        "--fmtstr-leak",
        action="store_true",
        help="Add a format string leak command for ASLR bypass practice",
    )
    mit.add_argument(
        "--data-staging",
        action="store_true",
        help="Add a data staging command that stores data on the heap "
        "(for egghunter practice)",
    )

    # Randomization
    rand = parser.add_argument_group("Randomization")
    rand.add_argument(
        "--random",
        action="store_true",
        help="Randomize all challenge aspects",
    )
    rand.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help="Reproducible random challenge seed",
    )
    rand.add_argument(
        "--difficulty",
        type=str,
        choices=[d.value for d in Difficulty],
        default=None,
        help="Preset difficulty level",
    )
    rand.add_argument(
        "--exclude-protection",
        type=str,
        default=None,
        help=(
            "Comma-separated protections to force OFF during --random. "
            "Valid: dep, aslr, canary, safeseh, fmtstr-leak"
        ),
    )

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument(
        "--output",
        type=str,
        default="",
        help="Output .cpp file (default: stdout)",
    )
    out.add_argument(
        "--build-script",
        action="store_true",
        help="Generate build script (build.bat for MSVC, build.sh for MinGW)",
    )
    out.add_argument(
        "--compiler",
        type=str,
        choices=[c.value for c in Compiler],
        default="msvc",
        help="Compiler toolchain: msvc, mingw (default: msvc)",
    )
    out.add_argument(
        "--generate-completion",
        type=str,
        choices=["bash", "zsh"],
        default=None,
        metavar="SHELL",
        help="Print shell completion script to stdout and exit",
    )
    out.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    out.add_argument(
        "--cheat-sheet",
        action="store_true",
        help="Print exploit hints",
    )

    # Exploit skeleton
    exp = parser.add_argument_group("Exploit Skeleton")
    exp.add_argument(
        "--exploit",
        type=str,
        choices=[e.value for e in ExploitLevel],
        default=None,
        help="Generate starter exploit script",
    )
    exp.add_argument(
        "--exploit-output",
        type=str,
        default="exploit.py",
        help="Output file for exploit (default: exploit.py)",
    )
    exp.add_argument(
        "--exploit-hints",
        type=str,
        choices=[h.value for h in HintVerbosity],
        default="full",
        help="Hint verbosity in crash exploits: full, minimal, none (default: full)",
    )

    # ROP DLL
    rop = parser.add_argument_group("ROP DLL")
    rop.add_argument(
        "--rop-dll",
        action="store_true",
        help="Generate companion ROP DLL",
    )
    rop.add_argument(
        "--rop-dll-output",
        type=str,
        default="rop_helper.cpp",
        help="Output file for DLL (default: rop_helper.cpp)",
    )
    rop.add_argument(
        "--rop-dll-gadgets",
        type=str,
        choices=[g.value for g in GadgetDensity],
        default="standard",
        help="Gadget density (default: standard)",
    )
    rop.add_argument(
        "--rop-dll-no-aslr",
        action="store_true",
        default=True,
        help="Compile DLL without ASLR (default: true)",
    )
    rop.add_argument(
        "--rop-dll-base",
        type=str,
        default=None,
        help="Preferred DLL base address (default: 0x10000000)",
    )

    # Embedded Gadgets
    emb = parser.add_argument_group("Embedded Gadgets")
    emb.add_argument(
        "--embedded-gadgets",
        action="store_true",
        help="Embed ROP gadgets directly in the server binary (x86 only)",
    )
    emb.add_argument(
        "--embedded-gadgets-density",
        type=str,
        choices=[g.value for g in GadgetDensity],
        default="standard",
        help="Gadget density (default: standard)",
    )

    return parser


def _validate_parsed_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    is_random: bool,
) -> None:
    """Validate args that lost choices= constraints or are random-only."""
    # Comma-lists and --exclude-protection only valid with --random
    if not is_random:
        for arg_name, arg_val in [
            ("--vuln", args.vuln),
            ("--protocol", args.protocol),
            ("--bad-char-action", args.bad_char_action),
            ("--padding-style", args.padding_style),
        ]:
            if arg_val and "," in arg_val:
                parser.error(f"{arg_name} comma-lists are only valid with --random")
        if args.exclude_protection is not None:
            parser.error("--exclude-protection is only valid with --random")

    # Validate single-value enum args (choices= removed for comma-list support)
    _check_enum_arg(parser, "--vuln", args.vuln, VulnType)
    _check_enum_arg(parser, "--protocol", args.protocol, Protocol)
    _check_enum_arg(parser, "--bad-char-action", args.bad_char_action, BadCharAction)
    _check_enum_arg(parser, "--padding-style", args.padding_style, PaddingStyle)


def _check_enum_arg(
    parser: argparse.ArgumentParser,
    arg_name: str,
    value: Optional[str],
    enum_cls: Type[enum.Enum],
) -> None:
    """Validate a single-value enum arg (skip comma-lists)."""
    if value and "," not in value:
        valid = {e.value for e in enum_cls}
        if value not in valid:
            parser.error(
                f"argument {arg_name}: invalid choice: '{value}' "
                f"(choose from {', '.join(sorted(valid))})"
            )


def parse_args(argv: Optional[List[str]] = None) -> ServerConfig:
    """Parse CLI arguments into a ServerConfig.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Validated ServerConfig.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    is_random = args.random or args.random_seed is not None

    _validate_parsed_args(parser, args, is_random)

    # Handle randomization first
    if is_random:
        return _randomize_config(args)

    # Require --vuln when not randomizing
    if not args.vuln:
        parser.error("--vuln is required (or use --random)")

    config = _args_to_config(args)
    _warn_fmtstr_leak_no_aslr(config)
    config.validate()
    return config


def _args_to_config(args: argparse.Namespace) -> ServerConfig:
    """Convert parsed args to ServerConfig."""
    # Parse bad chars
    bad_chars = _parse_bad_chars(args.bad_chars)

    # Parse additional commands
    add_cmds = [
        c.strip().upper() for c in args.additional_commands.split(",") if c.strip()
    ]

    # Parse DLL base address
    arch = Architecture(args.arch or "x86")
    dll_base = _resolve_base_address_arg(args.rop_dll_base, bad_chars, arch)
    if dll_base is None:
        dll_base = 0x10000000

    # Parse server base address
    base_address = _resolve_base_address_arg(args.base_address, bad_chars, arch)
    if base_address is None:
        base_address = 0x11110000

    config = ServerConfig(
        vuln_type=VulnType(args.vuln),
        port=args.port,
        arch=arch,
        buffer_size=args.buffer_size,
        protocol=Protocol(args.protocol or "tcp"),
        command=args.command,
        additional_commands=add_cmds,
        banner=args.banner if args.banner else _default_banner(),
        base_address=base_address,
        compiler=Compiler(args.compiler),
        bad_chars=bad_chars,
        bad_char_action=BadCharAction(args.bad_char_action or "drop"),
        egg_tag=args.egg,
        vuln_buffer_size=args.vuln_buffer_size,
        seh_offset=args.seh_offset,
        dep=args.dep,
        dep_api=DepBypassApi(args.dep_api or "virtualprotect"),
        aslr=args.aslr,
        stack_canary=args.stack_canary,
        safe_seh=args.safeSEH,
        fmtstr_leak=args.fmtstr_leak,
        data_staging=args.data_staging,
        decoy_count=args.decoy_commands,
        difficulty=(Difficulty(args.difficulty) if args.difficulty else None),
        output_file=args.output,
        build_script=args.build_script,
        no_color=args.no_color,
        cheat_sheet=args.cheat_sheet,
        exploit=ExploitConfig(
            enabled=args.exploit is not None,
            level=(
                ExploitLevel(args.exploit) if args.exploit else ExploitLevel.CONNECT
            ),
            output_file=args.exploit_output,
            hint_verbosity=HintVerbosity(args.exploit_hints),
        ),
        rop_dll=RopDllConfig(
            enabled=args.rop_dll,
            output_file=args.rop_dll_output,
            gadget_density=GadgetDensity(args.rop_dll_gadgets),
            no_aslr=args.rop_dll_no_aslr,
            base_address=dll_base,
        ),
        embedded_gadgets=EmbeddedGadgetsConfig(
            enabled=args.embedded_gadgets,
            gadget_density=GadgetDensity(args.embedded_gadgets_density),
        ),
        stack_layout=StackLayoutConfig(
            pre_padding_size=args.pre_padding,
            landing_pad_size=args.landing_pad,
            padding_style=PaddingStyle(args.padding_style or "none"),
        ),
    )

    return config


# Map from --exclude-protection names to argparse flag attributes
_PROTECTION_FLAG_MAP = {
    "dep": "dep",
    "aslr": "aslr",
    "canary": "stack_canary",
    "safeseh": "safeSEH",
    "fmtstr-leak": "fmtstr_leak",
    "data-staging": "data_staging",
}


def _parse_comma_enum(
    value: Optional[str],
    enum_cls: Type[enum.Enum],
    arg_name: str,
) -> Optional[List[enum.Enum]]:
    """Parse a comma-separated string into a list of enum values.

    Returns None if value is None. Raises ValueError on invalid values.
    """
    if value is None:
        return None
    parts = [v.strip() for v in value.split(",") if v.strip()]
    valid = {e.value for e in enum_cls}
    result = []
    for p in parts:
        if p not in valid:
            raise ValueError(
                f"Invalid {arg_name} value '{p}'. " f"Valid: {', '.join(sorted(valid))}"
            )
        result.append(enum_cls(p))
    return result


def _parse_exclude_protections(value: Optional[str]) -> FrozenSet[str]:
    """Parse --exclude-protection into a frozenset of protection names."""
    if not value:
        return frozenset()
    parts = {p.strip() for p in value.split(",") if p.strip()}
    invalid = parts - _PROTECTION_FLAG_MAP.keys()
    if invalid:
        raise ValueError(
            f"Invalid --exclude-protection value(s): {', '.join(sorted(invalid))}. "
            f"Valid: {', '.join(sorted(_PROTECTION_FLAG_MAP.keys()))}"
        )
    return frozenset(parts)


def _validate_random_constraints(
    args: argparse.Namespace,
    excluded: FrozenSet[str],
) -> None:
    """Validate that --exclude-protection doesn't contradict explicit flags."""
    for prot_name, attr_name in _PROTECTION_FLAG_MAP.items():
        if prot_name in excluded and getattr(args, attr_name, False):
            flag = attr_name.replace("_", "-")
            raise ValueError(f"--exclude-protection {prot_name} contradicts --{flag}")


def _randomize_config(args: argparse.Namespace) -> ServerConfig:  # noqa: C901
    """Build a randomized ServerConfig, respecting explicit overrides."""
    seed = (
        args.random_seed if args.random_seed is not None else random.randint(0, 2**31)
    )
    rng = random.Random(seed)

    # Print seed to stderr for reproducibility
    print(f"[*] Random seed: {seed}", file=sys.stderr)

    # Parse and validate constraints
    excluded = _parse_exclude_protections(args.exclude_protection)
    _validate_random_constraints(args, excluded)

    difficulty = None
    if args.difficulty:
        difficulty = Difficulty(args.difficulty)

    # Architecture — respect explicit --arch
    if args.arch is not None:
        arch = Architecture(args.arch)
    else:
        arch = rng.choice(list(Architecture))

    # Vuln type — support comma-list (e.g. --vuln bof,seh)
    vuln_list = _parse_comma_enum(args.vuln, VulnType, "--vuln")
    if vuln_list is not None:
        # Filter by arch compatibility
        candidates = [v for v in vuln_list if arch in VULN_ARCH_COMPAT[v]]
        if not candidates:
            raise ValueError(
                f"No vuln types from '{args.vuln}' are compatible "
                f"with --arch {arch.value}"
            )
        vuln_type = candidates[0] if len(candidates) == 1 else rng.choice(candidates)
    elif difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        candidates = [v for v in preset["vuln_types"] if arch in VULN_ARCH_COMPAT[v]]
        vuln_type = rng.choice(candidates) if candidates else VulnType.BOF
    else:
        candidates = [v for v in VulnType if arch in VULN_ARCH_COMPAT[v]]
        vuln_type = rng.choice(candidates)

    # Protocol — support comma-list (e.g. --protocol tcp,http)
    proto_list = _parse_comma_enum(args.protocol, Protocol, "--protocol")
    if proto_list is not None:
        protocol = proto_list[0] if len(proto_list) == 1 else rng.choice(proto_list)
    else:
        protocol = rng.choice(list(Protocol))

    # Buffer size
    if difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        lo, hi = preset["buffer_size_range"]
        buffer_size = rng.randint(lo, hi)
    else:
        buffer_size = rng.choice([64, 128, 256, 512, 1024, 2048])

    # Bad chars
    bad_chars = _parse_bad_chars(args.bad_chars)
    if not bad_chars:
        if difficulty:
            preset = DIFFICULTY_PRESETS[difficulty]
            lo, hi = preset["bad_char_count_range"]
            count = rng.randint(lo, hi)
        elif args.bad_char_count > 0:
            count = args.bad_char_count
        else:
            count = rng.randint(0, 8)
        bad_chars = _generate_random_bad_chars(count, rng, vuln_type)

    # Bad char action — support comma-list, respect explicit value
    bca_list = _parse_comma_enum(
        args.bad_char_action, BadCharAction, "--bad-char-action"
    )
    if bca_list is not None:
        bad_char_action = bca_list[0] if len(bca_list) == 1 else rng.choice(bca_list)
    else:
        bad_char_action = rng.choice(list(BadCharAction))

    # Mitigations — respect --exclude-protection
    if difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        dep = "dep" in preset["mitigations"] and "dep" not in excluded
        aslr = "aslr" in preset["mitigations"] and "aslr" not in excluded
        stack_canary = (
            "stack_canary" in preset["mitigations"] and "canary" not in excluded
        )
    else:
        if "dep" in excluded:
            dep = False
        else:
            dep = args.dep or rng.random() > 0.5

        if "aslr" in excluded:
            aslr = False
        else:
            aslr = args.aslr or rng.random() > 0.6

        if "canary" in excluded:
            stack_canary = False
        else:
            stack_canary = args.stack_canary or rng.random() > 0.7

    if "safeseh" in excluded:
        safe_seh = False
    else:
        safe_seh = args.safeSEH or (vuln_type == VulnType.SEH and rng.random() > 0.5)

    # Format string leak
    if "fmtstr-leak" in excluded:
        fmtstr_leak = False
    else:
        fmtstr_leak = args.fmtstr_leak
        if not fmtstr_leak and difficulty == Difficulty.HARD and aslr:
            fmtstr_leak = rng.random() > 0.5

    # Data staging
    if "data-staging" in excluded:
        data_staging = False
    else:
        data_staging = args.data_staging
        if not data_staging:
            if difficulty == Difficulty.HARD:
                data_staging = rng.random() > 0.5
            elif difficulty == Difficulty.MEDIUM:
                data_staging = rng.random() > 0.7

    # DEP API — respect explicit --dep-api
    if args.dep_api is not None:
        dep_api = DepBypassApi(args.dep_api)
    elif dep:
        dep_api = rng.choice(list(DepBypassApi))
    else:
        dep_api = DepBypassApi.VIRTUALPROTECT

    # Decoys
    if difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        lo, hi = preset["decoy_count_range"]
        decoy_count = rng.randint(lo, hi)
    else:
        decoy_count = (
            args.decoy_commands if args.decoy_commands > 0 else rng.randint(0, 4)
        )

    decoy_types = [rng.choice(list(DecoyType)) for _ in range(decoy_count)]
    available_names = list(DECOY_COMMAND_POOL)
    rng.shuffle(available_names)
    decoy_names = available_names[:decoy_count]

    # Stack layout
    if args.pre_padding > 0:
        pre_padding = args.pre_padding
    elif difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        lo, hi = preset["pre_padding_range"]
        pre_padding = rng.randint(lo, hi)
    else:
        pre_padding = rng.choice([0, 0, 32, 64, 96, 128])

    if args.landing_pad > 0:
        landing_pad = args.landing_pad
    elif difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        lo, hi = preset["landing_pad_range"]
        landing_pad = rng.randint(lo, hi)
    else:
        landing_pad = rng.choice([0, 0, 0, 16, 32, 64, 128, 256])

    # Padding style — support comma-list, respect explicit value
    ps_list = _parse_comma_enum(args.padding_style, PaddingStyle, "--padding-style")
    if ps_list is not None:
        padding_style = ps_list[0] if len(ps_list) == 1 else rng.choice(ps_list)
    elif pre_padding > 0:
        if difficulty:
            preset = DIFFICULTY_PRESETS[difficulty]
            padding_style = rng.choice(preset["padding_styles"])
        else:
            padding_style = rng.choice(list(PaddingStyle))
            # Re-roll NONE if we have padding to show
            if padding_style == PaddingStyle.NONE:
                padding_style = rng.choice(
                    [
                        PaddingStyle.ARRAY,
                        PaddingStyle.MIXED,
                        PaddingStyle.STRUCT,
                        PaddingStyle.MULTI,
                    ]
                )
    else:
        padding_style = PaddingStyle.NONE

    # Banner
    banner = args.banner if args.banner else rng.choice(BANNER_POOL)

    # ASLR info leak function name
    leak_func_name = rng.choice(LEAK_FUNC_POOL) if aslr else "get_server_config"

    # Data staging command name
    data_staging_cmd = rng.choice(DATA_STAGING_CMD_POOL) if data_staging else "STORE"

    # Base addresses — randomize upper bytes, avoiding bad chars
    base_address = _resolve_base_address_arg(args.base_address, bad_chars, arch)
    if base_address is None:
        base_address = find_random_base_address(bad_chars, arch, rng)

    dll_base = _resolve_base_address_arg(args.rop_dll_base, bad_chars, arch)
    if dll_base is None:
        if args.rop_dll:
            dll_base = find_random_base_address(bad_chars, arch, rng)
        else:
            dll_base = 0x10000000

    # Build config
    config = ServerConfig(
        vuln_type=vuln_type,
        port=args.port,
        arch=arch,
        buffer_size=buffer_size,
        protocol=protocol,
        command=args.command if args.command else "",
        additional_commands=[
            c.strip().upper() for c in args.additional_commands.split(",") if c.strip()
        ],
        banner=banner,
        base_address=base_address,
        compiler=Compiler(args.compiler),
        bad_chars=bad_chars,
        bad_char_action=bad_char_action,
        egg_tag=args.egg,
        vuln_buffer_size=min(args.vuln_buffer_size, buffer_size - 16),
        dep=dep,
        dep_api=dep_api,
        aslr=aslr,
        stack_canary=stack_canary,
        safe_seh=safe_seh,
        fmtstr_leak=fmtstr_leak,
        leak_func_name=leak_func_name,
        data_staging=data_staging,
        data_staging_cmd=data_staging_cmd,
        decoy_count=decoy_count,
        decoy_types=decoy_types,
        decoy_names=decoy_names,
        random=True,
        random_seed=seed,
        difficulty=difficulty,
        output_file=args.output,
        build_script=args.build_script,
        no_color=args.no_color,
        cheat_sheet=args.cheat_sheet,
        exploit=ExploitConfig(
            enabled=args.exploit is not None,
            level=(
                ExploitLevel(args.exploit) if args.exploit else ExploitLevel.CONNECT
            ),
            output_file=args.exploit_output,
            hint_verbosity=HintVerbosity(args.exploit_hints),
        ),
        rop_dll=RopDllConfig(
            enabled=args.rop_dll,
            output_file=args.rop_dll_output,
            gadget_density=GadgetDensity(args.rop_dll_gadgets),
            no_aslr=args.rop_dll_no_aslr,
            base_address=dll_base,
            seed=seed,
        ),
        embedded_gadgets=EmbeddedGadgetsConfig(
            enabled=args.embedded_gadgets,
            gadget_density=GadgetDensity(args.embedded_gadgets_density),
            seed=seed,
        ),
        stack_layout=StackLayoutConfig(
            pre_padding_size=pre_padding,
            landing_pad_size=landing_pad,
            padding_style=padding_style,
        ),
    )

    # Print challenge summary
    _print_challenge_summary(config)

    _warn_fmtstr_leak_no_aslr(config)
    config.validate()
    return config


def _parse_bad_chars(hex_str: str) -> List[int]:
    """Parse comma-separated hex string into list of byte values."""
    if not hex_str:
        return []
    result = []
    for part in hex_str.split(","):
        part = part.strip().lower()
        if part.startswith("0x"):
            part = part[2:]
        if part:
            result.append(int(part, 16))
    return sorted(set(result))


def _generate_random_bad_chars(
    count: int,
    rng: random.Random,
    vuln_type: Optional[VulnType] = None,
) -> List[int]:
    """Generate a list of random bad character byte values."""
    # Common bad chars that are likely in real scenarios
    common = [0x00, 0x0A, 0x0D, 0x20, 0x25, 0x26, 0x2B, 0x3D]
    # 0x25 ('%') must not be a bad char for format string vulns — it would
    # make the vulnerability unexploitable.
    if vuln_type == VulnType.FMTSTR:
        common = [b for b in common if b != 0x25]
    # All possible (excluding 0x00 which is implicit)
    all_bytes = list(range(1, 256))

    if count <= 0:
        return []

    # Start with some common ones, then add random
    selected = set()
    for b in common[: min(count, len(common))]:
        selected.add(b)
        if len(selected) >= count:
            break

    while len(selected) < count:
        b = rng.choice(all_bytes)
        if vuln_type == VulnType.FMTSTR and b == 0x25:
            continue
        selected.add(b)

    return sorted(selected)


def _resolve_base_address_arg(
    arg_value: Optional[str],
    bad_chars: List[int],
    arch: Architecture,
) -> Optional[int]:
    """Resolve a base address CLI argument.

    Args:
        arg_value: Raw CLI value — None, "auto", or a hex string.
        bad_chars: Configured bad characters.
        arch: Target architecture.

    Returns:
        Resolved address as int, or None if not specified.
    """
    if arg_value is None:
        return None
    if arg_value.lower() == "auto":
        return find_safe_base_address(bad_chars, arch)
    return int(arg_value, 0)


def _warn_fmtstr_leak_no_aslr(config: ServerConfig) -> None:
    """Print a warning if --fmtstr-leak is used without --aslr."""
    if config.fmtstr_leak and not config.aslr:
        print(
            "[!] --fmtstr-leak without --aslr: the format string leak "
            "command will be generated but ASLR is not enabled. "
            "Useful for experimentation, but not needed for exploitation.",
            file=sys.stderr,
        )


def _default_banner() -> str:
    """Return a default banner."""
    return "Target Server v1.0 - Type HELP for commands"


def _print_challenge_summary(config: ServerConfig) -> None:
    """Print randomized challenge parameters to stderr."""
    bad_hex = ", ".join(f"0x{b:02x}" for b in config.bad_chars)

    mitigations = []
    if config.dep:
        mitigations.append(f"DEP ({config.dep_api.value})")
    if config.aslr:
        mitigations.append("ASLR")
    if config.stack_canary:
        mitigations.append("Stack Canary")
    if config.safe_seh:
        mitigations.append("SafeSEH")
    if config.fmtstr_leak:
        mitigations.append("FmtStr Leak")
    if config.data_staging:
        mitigations.append(f"Data Staging ({config.data_staging_cmd})")

    # Stack layout info
    layout = config.stack_layout
    if layout.pre_padding_size > 0 or layout.landing_pad_size > 0:
        stack_info = []
        if layout.pre_padding_size > 0:
            stack_info.append(
                f"padding={layout.pre_padding_size}B " f"({layout.padding_style.value})"
            )
        if layout.landing_pad_size > 0:
            stack_info.append(f"landing_pad={layout.landing_pad_size}B")
            if layout.landing_pad_size <= 32:
                stack_info.append("(short jump likely needed)")
        stack_desc = ", ".join(stack_info)
    else:
        stack_desc = "standard (no extra padding)"

    lines = [
        "",
        "=" * 50,
        "  CHALLENGE PARAMETERS",
        "=" * 50,
        f"  Vulnerability:  {config.vuln_type.value}",
        f"  Architecture:   {config.arch.value}",
        f"  Protocol:       {config.protocol.value}",
        f"  Buffer size:    {config.buffer_size}",
        f"  Stack layout:   {stack_desc}",
        f"  Bad chars:      {bad_hex if bad_hex else 'none (0x00 implicit)'}",
        f"  Bad char mode:  {config.bad_char_action.value}",
        f"  Mitigations:    {', '.join(mitigations) if mitigations else 'none'}",
        f"  Base address:   0x{config.base_address:08X}",
        f"  Decoys:         {config.decoy_count}",
        f"  Seed:           {config.random_seed}",
        "=" * 50,
        "",
    ]
    print("\n".join(lines), file=sys.stderr)


def _handle_completion(argv: List[str]) -> bool:
    """Handle --generate-completion if present. Returns True if handled."""
    if "--generate-completion" not in argv:
        return False
    idx = argv.index("--generate-completion")
    if idx + 1 < len(argv) and argv[idx + 1] in ("bash", "zsh"):
        from target_builder.src.completions import generate_completion

        parser = build_parser()
        print(generate_completion(argv[idx + 1], parser))
        return True
    return False


def run(argv: Optional[List[str]] = None) -> int:  # noqa: C901
    """Main CLI entry point.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success).
    """
    # Handle --generate-completion early (no --vuln required)
    _argv = sys.argv[1:] if argv is None else list(argv)
    if _handle_completion(_argv):
        return 0

    try:
        config = parse_args(argv)
    except SystemExit:
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Render server C++
    cpp_source = render(config)

    # Output server source
    if config.output_file:
        with open(config.output_file, "w") as f:
            f.write(cpp_source)
        print(f"[+] Server source: {config.output_file}", file=sys.stderr)
    else:
        print(cpp_source)

    # Generate build script
    if config.build_script:
        if config.compiler == Compiler.MINGW:
            script_ext = ".sh"
        else:
            script_ext = ".bat"
        script_file = (
            config.output_file.rsplit(".", 1)[0] + script_ext
            if config.output_file
            else "build" + script_ext
        )
        script_content = generate_build(config)
        with open(script_file, "w") as f:
            f.write(script_content)
        print(f"[+] Build script: {script_file}", file=sys.stderr)

    # Generate exploit skeleton
    if config.exploit.enabled:
        exploit_src = generate_exploit(config)
        if exploit_src:
            with open(config.exploit.output_file, "w") as f:
                f.write(exploit_src)
            print(
                f"[+] Exploit skeleton: {config.exploit.output_file}",
                file=sys.stderr,
            )

    # Generate ROP DLL
    if config.rop_dll.enabled:
        dll_src = generate_rop_dll(config.rop_dll)
        with open(config.rop_dll.output_file, "w") as f:
            f.write(dll_src)
        print(
            f"[+] ROP DLL source: {config.rop_dll.output_file}",
            file=sys.stderr,
        )

    return 0
