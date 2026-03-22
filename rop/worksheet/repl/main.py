"""
Main REPL loop for the ROP worksheet.

This module contains the interactive command-line interface that handles
user input, command parsing, and display updates.
"""

import json
import os
import re
import readline
from contextlib import suppress
from typing import Any, Callable, Dict, Optional, Tuple

try:
    from rich.console import Console
    from rich.prompt import Confirm, Prompt
except ImportError:
    import sys

    sys.exit("[!] Install rich first:  pip install rich")

from ..chain.manager import cmd_chain_add, cmd_chain_clear, cmd_chain_del
from ..core.data import blank_worksheet
from ..gadgets.library import cmd_gadget_add, cmd_gadget_clear, cmd_gadget_del
from ..io.windbg import cmd_import_regs, cmd_import_stack
from ..operations.asm_ops import (
    cmd_add,
    cmd_dec,
    cmd_inc,
    cmd_move,
    cmd_neg,
    cmd_xchg,
    cmd_xor,
)
from ..operations.quick_ops import cmd_clear, cmd_set
from ..operations.stack_ops import cmd_pop, cmd_push, cmd_stack
from ..ui.display import build_worksheet_view
from ..ui.help import HELP, build_help_panel
from .completer import WorksheetCompleter

console = Console()


# ============================================================================
# Helper Functions
# ============================================================================


def parse_two_args(args: str, strip_commas: bool = True) -> Optional[Tuple[str, str]]:
    """
    Parse command arguments into two parts.

    Args:
        args: Raw argument string
        strip_commas: Whether to remove commas from args

    Returns:
        Tuple of (arg1, arg2) or None if parsing fails
    """
    if strip_commas:
        args = args.replace(",", " ")
    args_list = args.split(None, 1)
    if len(args_list) == 2:
        return args_list[0].strip(), args_list[1].strip()
    return None


def display_worksheet(ws: Dict[str, Any]) -> None:
    """Display the worksheet and help panel."""
    console.clear()
    console.print(build_worksheet_view(ws))
    console.print(build_help_panel())


def show_success(message: str) -> None:
    """Show success message."""
    console.print(f"[green]✓ {message}[/green]")


def show_error(message: str) -> None:
    """Show error message."""
    console.print(f"[red]{message}[/red]")


def show_usage(usage: str) -> None:
    """Show command usage."""
    console.print(f"[red]Usage: {usage}[/red]")


def read_multiline_input(prompt: str) -> str:
    """
    Read multiple lines of input until an empty line.

    Args:
        prompt: Prompt to display

    Returns:
        Combined input as single string
    """
    console.print(f"[cyan]{prompt}[/cyan]")
    lines = []
    while True:
        try:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines)


# ============================================================================
# Command Handlers
# ============================================================================


def handle_view(ws: Dict[str, Any], args: str) -> None:
    """Handle view/refresh commands."""
    display_worksheet(ws)


def handle_asm_two_operand(
    ws: Dict[str, Any],
    args: str,
    cmd_func: Callable,
    cmd_name: str,
    display_success_msg: bool = False,
) -> None:
    """
    Handle ASM operations with two operands (mov, add, xor, xchg).

    Args:
        ws: Worksheet dictionary
        args: Command arguments
        cmd_func: Command function to call
        cmd_name: Command name for usage message
        display_success_msg: Whether to display success message from cmd_func
    """
    parsed = parse_two_args(args, strip_commas=True)
    if parsed:
        success, msg = cmd_func(ws, parsed[0], parsed[1])
        if success:
            if display_success_msg and msg:
                show_success(msg)
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        show_usage(f"{cmd_name} <dst>, <src>")


def handle_asm_single_operand(
    ws: Dict[str, Any], args: str, cmd_func: Callable, cmd_name: str
) -> None:
    """
    Handle ASM operations with single operand (inc, dec, neg).

    Args:
        ws: Worksheet dictionary
        args: Command arguments
        cmd_func: Command function to call
        cmd_name: Command name for usage message
    """
    if args:
        success, msg = cmd_func(ws, args)
        if success:
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        show_usage(f"{cmd_name} <dst>")


def handle_pop(ws: Dict[str, Any], args: str) -> None:
    """Handle pop command."""
    if args:
        success, msg = cmd_pop(ws, args)
        if success:
            if msg:
                show_success(msg)
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        show_usage("pop <dst>")


def handle_push(ws: Dict[str, Any], args: str) -> None:
    """Handle push command."""
    if args:
        success, msg = cmd_push(ws, args)
        if success:
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        show_usage("push <src>")


def handle_stack(ws: Dict[str, Any], args: str) -> None:
    """Handle stack command."""
    parsed = parse_two_args(args, strip_commas=True)
    if parsed:
        success, msg = cmd_stack(ws, parsed[0], parsed[1])
        if success:
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        show_usage("stack <offset> <value>")


def handle_set(ws: Dict[str, Any], args: str) -> None:
    """Handle set command."""
    parsed = parse_two_args(args, strip_commas=True)
    if parsed:
        target, value = parsed

        # Auto-convert plain hex numbers to 0x format
        if not value.startswith("0x") and not value.startswith("0X"):
            try:
                num = int(value, 16)
                value = f"0x{num:08x}"
            except ValueError:
                pass

        cmd_set(ws, target, value)
        display_worksheet(ws)
    else:
        show_usage("set <target>, <value>")


def handle_clear(ws: Dict[str, Any], args: str) -> None:
    """Handle clear command."""
    if args:
        cmd_clear(ws, args)
        display_worksheet(ws)
    else:
        show_usage("clr <target>")


def handle_name(ws: Dict[str, Any], args: str) -> None:
    """Handle name/named command."""
    args_list = args.split(None, 1)
    if len(args_list) == 2:
        ws["named"][args_list[0]] = args_list[1]
        display_worksheet(ws)
    else:
        show_usage("name <name> <value>")


def handle_gadget(ws: Dict[str, Any], args: str) -> None:
    """Handle gadget command with subcommands."""
    subargs = args.split(None, 1)
    if not subargs:
        show_usage(
            'gadget <address> "<instructions>" OR gadget del <address> OR gadget clear'
        )
        return

    subcommand = subargs[0].lower()

    if subcommand == "del":
        if len(subargs) > 1:
            address = subargs[1].strip()
            success, msg = cmd_gadget_del(ws, address)
            if success:
                display_worksheet(ws)
            else:
                show_error(msg)
        else:
            show_usage("gadget del <address>")

    elif subcommand == "clear":
        if Confirm.ask("Clear all gadgets from library?"):
            cmd_gadget_clear(ws)
            display_worksheet(ws)

    else:
        # Add gadget: gadget <address> "<instructions>"
        match = re.match(r'(\S+)\s+"([^"]+)"', args)
        if match:
            address, instructions = match.groups()
            cmd_gadget_add(ws, address, instructions)
            display_worksheet(ws)
        else:
            show_usage('gadget <address> "<instructions>"')


def handle_chain(ws: Dict[str, Any], args: str) -> None:
    """Handle chain command with subcommands."""
    subargs = args.split(None, 1)
    if not subargs:
        show_usage("chain add <value> OR chain del <index> OR chain clear")
        return

    subcommand = subargs[0].lower()

    if subcommand == "add":
        if len(subargs) > 1:
            value = subargs[1].strip()
            success, msg = cmd_chain_add(ws, value)
            if success:
                display_worksheet(ws)
            else:
                show_error(msg)
        else:
            show_usage("chain add <value>")

    elif subcommand == "del":
        if len(subargs) > 1:
            index = subargs[1].strip()
            success, msg = cmd_chain_del(ws, index)
            if success:
                display_worksheet(ws)
            else:
                show_error(msg)
        else:
            show_usage("chain del <index>")

    elif subcommand == "clear":
        if Confirm.ask("Clear entire ROP chain?"):
            cmd_chain_clear(ws)
            display_worksheet(ws)
    else:
        show_usage("chain add <value> OR chain del <index> OR chain clear")


def handle_delete(ws: Dict[str, Any], args: str) -> None:
    """Handle delete command (backward compatibility for chain delete)."""
    if args:
        success, msg = cmd_chain_del(ws, args)
        if success:
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        show_usage("del <index>")


def handle_import_regs(ws: Dict[str, Any], args: str) -> None:
    """Handle importregs command."""
    text = read_multiline_input("Paste WinDbg register output (end with empty line):")
    if text:
        success, msg = cmd_import_regs(ws, text)
        if success:
            show_success(msg)
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        console.print("[yellow]No input provided[/yellow]")


def handle_import_stack(ws: Dict[str, Any], args: str) -> None:
    """Handle importstack command."""
    text = read_multiline_input("Paste WinDbg stack dump (end with empty line):")
    if text:
        success, msg = cmd_import_stack(ws, text)
        if success:
            show_success(msg)
            display_worksheet(ws)
        else:
            show_error(msg)
    else:
        console.print("[yellow]No input provided[/yellow]")


def handle_notes(ws: Dict[str, Any], args: str) -> None:
    """Handle notes command."""
    ws["notes"] = Prompt.ask("Notes", default=ws["notes"])
    display_worksheet(ws)


def handle_save(ws: Dict[str, Any], args: str) -> None:
    """Handle save command."""
    filename = args.strip() or "rop.json"
    with open(filename, "w") as f:
        json.dump(ws, f, indent=2)
    show_success(f"Saved to {filename}")


def handle_load(ws: Dict[str, Any], args: str) -> Dict[str, Any]:
    """
    Handle load command.

    Args:
        ws: Current worksheet dictionary
        args: Command arguments

    Returns:
        Updated worksheet dictionary
    """
    filename = args.strip() or "rop.json"
    if os.path.exists(filename):
        with open(filename) as f:
            ws = json.load(f)
        display_worksheet(ws)
        return ws
    else:
        show_error(f"File not found: {filename}")
        return ws


def handle_new(ws: Dict[str, Any], args: str) -> Dict[str, Any]:
    """
    Handle new command.

    Args:
        ws: Current worksheet dictionary
        args: Command arguments

    Returns:
        New blank worksheet or existing worksheet
    """
    if Confirm.ask("Start new worksheet? (unsaved changes will be lost)"):
        ws = blank_worksheet()
        display_worksheet(ws)
    return ws


def handle_auto(ws: Dict[str, Any], args: str) -> None:
    """Handle auto-gadget toggle command."""
    ws["auto_gadget"] = not ws.get("auto_gadget", True)
    status = "[green]ON[/green]" if ws["auto_gadget"] else "[red]OFF[/red]"
    console.print(f"Auto-gadget processing: {status}")
    display_worksheet(ws)


def handle_logmanual(ws: Dict[str, Any], args: str) -> None:
    """Handle log-manual toggle command."""
    ws["log_manual"] = not ws.get("log_manual", True)
    status = "[green]ON[/green]" if ws["log_manual"] else "[red]OFF[/red]"
    console.print(f"Manual operation logging: {status}")
    display_worksheet(ws)


def handle_help(ws: Dict[str, Any], args: str) -> None:
    """Handle help command."""
    console.print(HELP)


def handle_quit(ws: Dict[str, Any], args: str) -> bool:
    """
    Handle quit command.

    Returns:
        True if should quit, False otherwise
    """
    return Confirm.ask("Quit?")


# ============================================================================
# Command Dispatch
# ============================================================================


def dispatch_asm_command(ws: Dict[str, Any], action: str, args: str) -> bool:
    """
    Dispatch ASM operation commands.

    Args:
        ws: Worksheet dictionary
        action: Command action
        args: Command arguments

    Returns:
        True if command was handled, False otherwise
    """
    # Map ASM commands to (handler, cmd_func, cmd_name, display_success)
    asm_two_operand = {
        "mov": (handle_asm_two_operand, cmd_move, "mov", True),
        "move": (handle_asm_two_operand, cmd_move, "mov", True),
        "m": (handle_asm_two_operand, cmd_move, "mov", True),
        "add": (handle_asm_two_operand, cmd_add, "add", False),
        "xor": (handle_asm_two_operand, cmd_xor, "xor", False),
        "xchg": (handle_asm_two_operand, cmd_xchg, "xchg", False),
    }

    asm_single_operand = {
        "inc": (handle_asm_single_operand, cmd_inc, "inc"),
        "dec": (handle_asm_single_operand, cmd_dec, "dec"),
        "neg": (handle_asm_single_operand, cmd_neg, "neg"),
    }

    if action in asm_two_operand:
        handler, cmd_func, cmd_name, show_msg = asm_two_operand[action]
        handler(ws, args, cmd_func, cmd_name, display_success_msg=show_msg)
        return True
    elif action in asm_single_operand:
        handler, cmd_func, cmd_name = asm_single_operand[action]
        handler(ws, args, cmd_func, cmd_name)
        return True
    return False


def dispatch_registry_command(
    ws: Dict[str, Any], action: str, args: str
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Dispatch commands from the registry.

    Args:
        ws: Worksheet dictionary
        action: Command action
        args: Command arguments

    Returns:
        Tuple of (updated_worksheet, should_quit)
    """
    if action not in COMMAND_REGISTRY:
        return None, False

    handler = COMMAND_REGISTRY[action]
    result = handler(ws, args)

    # Handle commands that return updated worksheet
    if action in ["load", "new"] and result is not None:
        return result, False

    # Handle quit command
    if action in ["quit", "q", "exit"] and result:
        return None, True

    return None, False


# ============================================================================
# Command Registry
# ============================================================================


# Map command names to handler functions
# Format: {command_name: handler_function}
COMMAND_REGISTRY: Dict[str, Callable] = {
    # View commands
    "v": handle_view,
    "view": handle_view,
    "show": handle_view,
    "r": handle_view,
    "refresh": handle_view,
    # ASM operations - handled specially due to cmd_func parameter
    # Stack operations
    "pop": handle_pop,
    "push": handle_push,
    "stack": handle_stack,
    # Quick operations
    "set": handle_set,
    "s": handle_set,
    "clr": handle_clear,
    "clear": handle_clear,
    # Named values
    "name": handle_name,
    "named": handle_name,
    # Complex commands
    "gadget": handle_gadget,
    "chain": handle_chain,
    "del": handle_delete,
    "delete": handle_delete,
    "rm": handle_delete,
    # Import commands
    "importregs": handle_import_regs,
    "importreg": handle_import_regs,
    "impreg": handle_import_regs,
    "importstack": handle_import_stack,
    "impstack": handle_import_stack,
    "impst": handle_import_stack,
    # File operations
    "save": handle_save,
    "load": handle_load,
    "new": handle_new,
    # Settings
    "auto": handle_auto,
    "logmanual": handle_logmanual,
    "notes": handle_notes,
    "note": handle_notes,
    # Meta commands
    "help": handle_help,
    "h": handle_help,
    "?": handle_help,
    "quit": handle_quit,
    "q": handle_quit,
    "exit": handle_quit,
}


# ============================================================================
# Main REPL Loop
# ============================================================================


def main():
    """Main REPL loop for the ROP worksheet."""
    ws = blank_worksheet()

    # Setup tab completion
    completer = WorksheetCompleter(ws)
    readline.set_completer(completer.complete)
    readline.set_completer_delims(" \t\n")

    # Configure readline - only complete on TAB
    readline.parse_and_bind("tab: complete")
    with suppress(Exception):
        readline.parse_and_bind("set completion-display-width 0")

    # Initial display
    display_worksheet(ws)

    while True:
        try:
            cmd = input("\n\033[1;36m>\033[0m ").strip()

            if not cmd:
                continue

            parts = cmd.split(None, 1)
            action = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            # Try ASM operations first
            if dispatch_asm_command(ws, action, args):
                continue

            # Try registry commands
            updated_ws, should_quit = dispatch_registry_command(ws, action, args)
            if updated_ws is not None:
                ws = updated_ws
            if should_quit:
                break

            # Unknown command
            if not updated_ws and not should_quit and action not in COMMAND_REGISTRY:
                show_error(f"Unknown command: {action}")
                console.print("Type [yellow]help[/yellow] for commands")

        except KeyboardInterrupt:
            console.print("\n[dim]Use 'quit' to exit[/dim]")
        except Exception as e:
            show_error(f"Error: {e}")
