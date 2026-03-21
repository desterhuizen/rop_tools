"""
Main REPL loop for the ROP worksheet.

This module contains the interactive command-line interface that handles
user input, command parsing, and display updates.
"""

import json
import os
import readline
from typing import Any, Dict

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


def main():
    """Main REPL loop for the ROP worksheet."""
    ws = blank_worksheet()

    # Setup tab completion
    completer = WorksheetCompleter(ws)
    readline.set_completer(completer.complete)
    readline.set_completer_delims(" \t\n")

    # Configure readline - only complete on TAB, don't show lists
    readline.parse_and_bind("tab: complete")
    # Disable automatic display of completion alternatives
    try:
        # This should prevent the completion list from showing
        readline.parse_and_bind("set completion-display-width 0")
    except:
        pass

    # Simple display function - just print worksheet and help
    def display():
        console.clear()
        console.print(build_worksheet_view(ws))
        console.print(build_help_panel())

    # Initial display
    display()

    while True:
        try:
            # Use raw input for better readline/autocomplete support
            # Pass prompt directly to input() so readline knows the prompt boundary
            cmd = input("\n\033[1;36m>\033[0m ").strip()

            if not cmd:
                continue

            parts = cmd.split(None, 1)
            action = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            # View - refresh display
            if action in ["v", "view", "show", "r", "refresh"]:
                display()

            # ASM Operations
            elif action in ["mov", "move", "m"]:
                # Strip commas to support: mov EAX, 0x123 or mov EAX 0x123
                args_clean = args.replace(",", " ")
                args_list = args_clean.split(None, 1)
                if len(args_list) == 2:
                    success, msg = cmd_move(ws, args_list[0], args_list[1])
                    if msg:
                        console.print(f"[green]✓ {msg}[/green]")
                    display()
                else:
                    console.print("[red]Usage: mov <dst>, <src>[/red]")

            elif action == "add":
                # Strip commas to support: add EAX, 0x100 or add EAX 0x100
                args_clean = args.replace(",", " ")
                args_list = args_clean.split(None, 1)
                if len(args_list) == 2:
                    success, msg = cmd_add(ws, args_list[0], args_list[1])
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: add <dst>, <src>[/red]")

            elif action == "xor":
                # Strip commas to support: xor EAX, EBX or xor EAX EBX
                args_clean = args.replace(",", " ")
                args_list = args_clean.split(None, 1)
                if len(args_list) == 2:
                    success, msg = cmd_xor(ws, args_list[0], args_list[1])
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: xor <dst>, <src>[/red]")

            elif action == "xchg":
                # Strip commas to support: xchg EAX, EBX or xchg EAX EBX
                args_clean = args.replace(",", " ")
                args_list = args_clean.split(None, 1)
                if len(args_list) == 2:
                    success, msg = cmd_xchg(ws, args_list[0], args_list[1])
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: xchg <dst>, <src>[/red]")

            elif action == "inc":
                if args:
                    success, msg = cmd_inc(ws, args)
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: inc <dst>[/red]")

            elif action == "dec":
                if args:
                    success, msg = cmd_dec(ws, args)
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: dec <dst>[/red]")

            elif action == "neg":
                if args:
                    success, msg = cmd_neg(ws, args)
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: neg <dst>[/red]")

            elif action == "pop":
                if args:
                    success, msg = cmd_pop(ws, args)
                    if success:
                        if msg:
                            console.print(f"[green]✓ {msg}[/green]")
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: pop <dst>[/red]")

            elif action == "push":
                if args:
                    success, msg = cmd_push(ws, args)
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: push <src>[/red]")

            # Stack manipulation
            elif action == "stack":
                # Strip commas to support: stack ECX, EAX or stack ECX EAX
                args_clean = args.replace(",", " ")
                args_list = args_clean.split(None, 1)
                if len(args_list) == 2:
                    success, msg = cmd_stack(ws, args_list[0], args_list[1])
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: stack <offset> <value>[/red]")

            # Set
            elif action in ["set", "s"]:
                # Strip commas to support: set EAX, 1234 or set EAX 1234
                args_clean = args.replace(",", " ")
                args_list = args_clean.split(None, 1)
                if len(args_list) == 2:
                    target = args_list[0].strip()
                    value = args_list[1].strip()

                    # Auto-convert plain hex numbers to 0x format
                    # Check if value looks like hex (no 0x prefix but valid hex chars)
                    if not value.startswith("0x") and not value.startswith(
                            "0X"):
                        try:
                            # Try to parse as hex and convert to proper format
                            num = int(value, 16)
                            value = f"0x{num:08x}"
                        except ValueError:
                            # Not a valid hex number, keep as-is (could be a named value)
                            pass

                    cmd_set(ws, target, value)
                    display()
                else:
                    console.print("[red]Usage: set <target>, <value>[/red]")

            # Clear
            elif action in ["clr", "clear"]:
                if args:
                    cmd_clear(ws, args)
                    display()
                else:
                    console.print("[red]Usage: clr <target>[/red]")

            # Named value
            elif action in ["name", "named"]:
                args_list = args.split(None, 1)
                if len(args_list) == 2:
                    ws["named"][args_list[0]] = args_list[1]
                    display()
                else:
                    console.print("[red]Usage: name <name> <value>[/red]")

            # Gadget management
            elif action == "gadget":
                # Parse subcommand: gadget add <addr> "<instructions>" OR gadget del <addr> OR gadget clear
                subargs = args.split(None, 1)
                if not subargs:
                    console.print(
                        '[red]Usage: gadget <address> "<instructions>" OR gadget del <address> OR gadget clear[/red]'
                    )
                    continue

                subcommand = subargs[0].lower()

                if subcommand == "del":
                    # Delete gadget: gadget del <address>
                    if len(subargs) > 1:
                        address = subargs[1].strip()
                        success, msg = cmd_gadget_del(ws, address)
                        if success:
                            display()
                        else:
                            console.print(f"[red]{msg}[/red]")
                    else:
                        console.print("[red]Usage: gadget del <address>[/red]")

                elif subcommand == "clear":
                    # Clear all gadgets
                    if Confirm.ask("Clear all gadgets from library?"):
                        cmd_gadget_clear(ws)
                        display()

                else:
                    # Add gadget: gadget <address> "<instructions>"
                    # subcommand is actually the address
                    address = subcommand
                    # Parse for quoted instructions
                    import re

                    match = re.match(r'(\S+)\s+"([^"]+)"', args)
                    if match:
                        address, instructions = match.groups()
                        cmd_gadget_add(ws, address, instructions)
                        display()
                    else:
                        console.print(
                            '[red]Usage: gadget <address> "<instructions>"[/red]'
                        )

            # Chain commands
            elif action == "chain":
                # Parse subcommand: chain add <value> OR chain del <index> OR chain clear
                subargs = args.split(None, 1)
                if not subargs:
                    console.print(
                        "[red]Usage: chain add <value> OR chain del <index> OR chain clear[/red]"
                    )
                    continue

                subcommand = subargs[0].lower()

                if subcommand == "add":
                    # Add to chain: chain add <value>
                    if len(subargs) > 1:
                        value = subargs[1].strip()
                        success, msg = cmd_chain_add(ws, value)
                        if success:
                            display()
                        else:
                            console.print(f"[red]{msg}[/red]")
                    else:
                        console.print("[red]Usage: chain add <value>[/red]")

                elif subcommand == "del":
                    # Delete from chain: chain del <index>
                    if len(subargs) > 1:
                        index = subargs[1].strip()
                        success, msg = cmd_chain_del(ws, index)
                        if success:
                            display()
                        else:
                            console.print(f"[red]{msg}[/red]")
                    else:
                        console.print("[red]Usage: chain del <index>[/red]")

                elif subcommand == "clear":
                    # Clear chain
                    if Confirm.ask("Clear entire ROP chain?"):
                        cmd_chain_clear(ws)
                        display()

                else:
                    console.print(
                        "[red]Usage: chain add <value> OR chain del <index> OR chain clear[/red]"
                    )

            # Delete (backward compatibility for chain delete)
            elif action in ["del", "delete", "rm"]:
                if args:
                    success, msg = cmd_chain_del(ws, args)
                    if success:
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[red]Usage: del <index>[/red]")

            # Import registers
            elif action in ["importregs", "importreg", "impreg"]:
                console.print(
                    "[cyan]Paste WinDbg register output (end with empty line):[/cyan]"
                )
                lines = []
                while True:
                    try:
                        line = input()
                        if not line.strip():
                            break
                        lines.append(line)
                    except EOFError:
                        break

                if lines:
                    text = "\n".join(lines)
                    success, msg = cmd_import_regs(ws, text)
                    if success:
                        console.print(f"[green]✓ {msg}[/green]")
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[yellow]No input provided[/yellow]")

            # Import stack
            elif action in ["importstack", "impstack", "impst"]:
                console.print(
                    "[cyan]Paste WinDbg stack dump (end with empty line):[/cyan]"
                )
                lines = []
                while True:
                    try:
                        line = input()
                        if not line.strip():
                            break
                        lines.append(line)
                    except EOFError:
                        break

                if lines:
                    text = "\n".join(lines)
                    success, msg = cmd_import_stack(ws, text)
                    if success:
                        console.print(f"[green]✓ {msg}[/green]")
                        display()
                    else:
                        console.print(f"[red]{msg}[/red]")
                else:
                    console.print("[yellow]No input provided[/yellow]")

            # Notes
            elif action in ["notes", "note"]:
                ws["notes"] = Prompt.ask("Notes", default=ws["notes"])
                display()

            # Save
            elif action == "save":
                filename = args.strip() or "rop.json"
                with open(filename, "w") as f:
                    json.dump(ws, f, indent=2)
                console.print(f"[green]✓ Saved to {filename}[/green]")

            # Load
            elif action == "load":
                filename = args.strip() or "rop.json"
                if os.path.exists(filename):
                    with open(filename) as f:
                        ws = json.load(f)
                    display()
                else:
                    console.print(f"[red]File not found: {filename}[/red]")

            # New
            elif action == "new":
                if Confirm.ask(
                        "Start new worksheet? (unsaved changes will be lost)"):
                    ws = blank_worksheet()
                    display()

            # Auto-gadget toggle
            elif action == "auto":
                ws["auto_gadget"] = not ws.get("auto_gadget", True)
                status = "[green]ON[/green]" if ws[
                    "auto_gadget"] else "[red]OFF[/red]"
                console.print(f"Auto-gadget processing: {status}")
                display()

            # Log-manual toggle
            elif action == "logmanual":
                ws["log_manual"] = not ws.get("log_manual", True)
                status = "[green]ON[/green]" if ws[
                    "log_manual"] else "[red]OFF[/red]"
                console.print(f"Manual operation logging: {status}")
                display()

            # Help
            elif action in ["help", "h", "?"]:
                console.print(HELP)

            # Quit
            elif action in ["quit", "q", "exit"]:
                if Confirm.ask("Quit?"):
                    break

            else:
                console.print(f"[red]Unknown command: {action}[/red]")
                console.print("Type [yellow]help[/yellow] for commands")

        except KeyboardInterrupt:
            console.print("\n[dim]Use 'quit' to exit[/dim]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
