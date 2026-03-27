"""CLI interface for target_builder.

Argparse definition, validation, randomization logic, and orchestration.
"""

import argparse
import random
import sys
from typing import List, Optional

from target_builder.src.build_script import generate as generate_build
from target_builder.src.config import (
    BANNER_POOL,
    DECOY_COMMAND_POOL,
    DIFFICULTY_PRESETS,
    VULN_ARCH_COMPAT,
    Architecture,
    BadCharAction,
    DecoyType,
    DepBypassApi,
    Difficulty,
    EmbeddedGadgetsConfig,
    ExploitConfig,
    ExploitLevel,
    GadgetDensity,
    PaddingStyle,
    Protocol,
    RopDllConfig,
    ServerConfig,
    StackLayoutConfig,
    VulnType,
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
        choices=[v.value for v in VulnType],
        help="Vulnerability type to embed",
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
        default="x86",
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
        choices=[p.value for p in Protocol],
        default="tcp",
        help="Network protocol (default: tcp)",
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
        default="0x11110000",
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
        choices=[a.value for a in BadCharAction],
        default="drop",
        help="How server handles bad chars (default: drop)",
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
        choices=[s.value for s in PaddingStyle],
        default="none",
        help="Style of stack padding variables (default: none)",
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
        default="virtualprotect",
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
        help="Generate build.bat",
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
        default="0x10000000",
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


def parse_args(argv: Optional[List[str]] = None) -> ServerConfig:
    """Parse CLI arguments into a ServerConfig.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Validated ServerConfig.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle randomization first
    if args.random or args.random_seed is not None:
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
    arch = Architecture(args.arch)
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
        protocol=Protocol(args.protocol),
        command=args.command,
        additional_commands=add_cmds,
        banner=args.banner if args.banner else _default_banner(),
        base_address=base_address,
        bad_chars=bad_chars,
        bad_char_action=BadCharAction(args.bad_char_action),
        egg_tag=args.egg,
        vuln_buffer_size=args.vuln_buffer_size,
        seh_offset=args.seh_offset,
        dep=args.dep,
        dep_api=DepBypassApi(args.dep_api),
        aslr=args.aslr,
        stack_canary=args.stack_canary,
        safe_seh=args.safeSEH,
        fmtstr_leak=args.fmtstr_leak,
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
            padding_style=PaddingStyle(args.padding_style),
        ),
    )

    return config


def _randomize_config(args: argparse.Namespace) -> ServerConfig:  # noqa: C901
    """Build a randomized ServerConfig."""
    seed = (
        args.random_seed if args.random_seed is not None else random.randint(0, 2**31)
    )
    rng = random.Random(seed)

    # Print seed to stderr for reproducibility
    print(f"[*] Random seed: {seed}", file=sys.stderr)

    difficulty = None
    if args.difficulty:
        difficulty = Difficulty(args.difficulty)

    # Architecture
    arch = (
        Architecture(args.arch)
        if args.arch != "x86"
        else rng.choice(list(Architecture))
    )

    # Vuln type (respecting arch constraints)
    if args.vuln:
        vuln_type = VulnType(args.vuln)
    elif difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        candidates = [v for v in preset["vuln_types"] if arch in VULN_ARCH_COMPAT[v]]
        vuln_type = rng.choice(candidates) if candidates else VulnType.BOF
    else:
        candidates = [v for v in VulnType if arch in VULN_ARCH_COMPAT[v]]
        vuln_type = rng.choice(candidates)

    # Protocol
    protocol = (
        Protocol(args.protocol)
        if args.protocol != "tcp"
        else rng.choice(list(Protocol))
    )

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
        bad_chars = _generate_random_bad_chars(count, rng)

    bad_char_action = rng.choice(list(BadCharAction))

    # Mitigations
    if difficulty:
        preset = DIFFICULTY_PRESETS[difficulty]
        dep = "dep" in preset["mitigations"]
        aslr = "aslr" in preset["mitigations"]
        stack_canary = "stack_canary" in preset["mitigations"]
    else:
        dep = args.dep or rng.random() > 0.5
        aslr = args.aslr or rng.random() > 0.6
        stack_canary = args.stack_canary or rng.random() > 0.7

    safe_seh = args.safeSEH or (vuln_type == VulnType.SEH and rng.random() > 0.5)

    # Format string leak — only for hard difficulty
    fmtstr_leak = args.fmtstr_leak
    if not fmtstr_leak and difficulty == Difficulty.HARD and aslr:
        fmtstr_leak = rng.random() > 0.5

    # DEP API
    dep_api = rng.choice(list(DepBypassApi)) if dep else DepBypassApi.VIRTUALPROTECT

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

    if args.padding_style != "none":
        padding_style = PaddingStyle(args.padding_style)
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

    # Base addresses — auto-select safe addresses avoiding bad chars
    base_address = _resolve_base_address_arg(args.base_address, bad_chars, arch)
    if base_address is None:
        if bad_chars:
            base_address = find_safe_base_address(bad_chars, arch)
        else:
            base_address = 0x11110000

    dll_base = _resolve_base_address_arg(args.rop_dll_base, bad_chars, arch)
    if dll_base is None:
        if args.rop_dll and bad_chars:
            dll_base = find_safe_base_address(bad_chars, arch)
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


def _generate_random_bad_chars(count: int, rng: random.Random) -> List[int]:
    """Generate a list of random bad character byte values."""
    # Common bad chars that are likely in real scenarios
    common = [0x00, 0x0A, 0x0D, 0x20, 0x25, 0x26, 0x2B, 0x3D]
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


def run(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success).
    """
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
        bat_file = (
            config.output_file.rsplit(".", 1)[0] + ".bat"
            if config.output_file
            else "build.bat"
        )
        bat_content = generate_build(config)
        with open(bat_file, "w") as f:
            f.write(bat_content)
        print(f"[+] Build script: {bat_file}", file=sys.stderr)

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
