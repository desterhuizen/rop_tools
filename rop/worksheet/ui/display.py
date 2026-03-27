"""
Display functions for worksheet visualization.

This module contains all the Rich-based UI rendering logic for displaying
registers, stack, named values, gadgets, chains, and execution logs.
"""

from typing import Any, Dict, List

from rich import box
from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table


def _build_value_to_names_lookup(ws: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Build reverse lookup mapping values to their named identifiers.

    Args:
        ws: Worksheet dictionary

    Returns:
        Dictionary mapping values to list of names
    """
    value_to_names = {}
    for name, val in ws["named"].items():
        if val not in value_to_names:
            value_to_names[val] = []
        value_to_names[val].append(name)
    return value_to_names


def _build_header_panel(ws: Dict[str, Any]) -> Panel:
    """
    Build the header panel with status information.

    Args:
        ws: Worksheet dictionary

    Returns:
        Rich Panel with header
    """
    auto_status = (
        "[green]ON[/green]" if ws.get("auto_gadget", True) else "[red]OFF[/red]"
    )
    log_manual_status = (
        "[green]ON[/green]" if ws.get("log_manual", True) else "[red]OFF[/red]"
    )
    return Panel(
        f"[bold yellow]ROP Chain Worksheet[/bold yellow] — Quick register & stack tracking  |  Auto-gadget: {auto_status}  |  Log-manual: {log_manual_status}",
        border_style="cyan",
    )


def _build_registers_table(
    ws: Dict[str, Any], value_to_names: Dict[str, List[str]]
) -> Table:
    """
    Build the registers display table.

    Args:
        ws: Worksheet dictionary
        value_to_names: Reverse lookup of values to names

    Returns:
        Rich Table with register contents
    """
    reg_table = Table(
        title="REGISTERS", box=box.SIMPLE, show_header=True, header_style="bold magenta"
    )
    reg_table.add_column("REG", style="cyan", width=6)
    reg_table.add_column("VALUE", style="white", width=24)
    reg_table.add_column("NAME", style="dim green", width=15)

    # Display general-purpose registers first (not EIP)
    gp_regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"]
    for reg in gp_regs:
        val = ws["registers"].get(reg, "0x00000000")
        display_val = f"[yellow]{val}[/yellow]" if val else "[dim]—[/dim]"

        # Check if this value matches any named value
        name_match = ""
        if val in value_to_names:
            name_match = f"[dim green]{', '.join(value_to_names[val])}[/dim green]"

        reg_table.add_row(reg, display_val, name_match)

    # Separator before EIP
    reg_table.add_row(
        "─────", "────────────────────────", "───────────────", style="dim"
    )

    # Display EIP separately with highlighting
    eip_val = ws["registers"].get("EIP", "0x00000000")
    eip_display = (
        f"[bold green]{eip_val}[/bold green]"
        if eip_val and eip_val != "0x00000000"
        else f"[dim]{eip_val}[/dim]"
    )

    # Check if EIP matches any named value
    eip_name_match = ""
    if eip_val in value_to_names:
        eip_name_match = f"[dim green]{', '.join(value_to_names[eip_val])}[/dim green]"

    reg_table.add_row("EIP", eip_display, eip_name_match)

    return reg_table


def _build_stack_table(
    ws: Dict[str, Any], value_to_names: Dict[str, List[str]]
) -> Table:
    """
    Build the stack display table.

    Shows at most 10 items before ESP+0x00 and 10 items after (inclusive).
    When items are hidden, a "..." indicator row is shown.

    Args:
        ws: Worksheet dictionary
        value_to_names: Reverse lookup of values to names

    Returns:
        Rich Table with stack contents
    """
    stack_table = Table(
        title="STACK", box=box.SIMPLE, show_header=True, header_style="bold magenta"
    )
    stack_table.add_column("ADDRESS", style="dim cyan", width=12)
    stack_table.add_column("OFFSET", style="cyan", width=10)
    stack_table.add_column("VALUE", style="white", width=24)
    stack_table.add_column("NAME", style="dim green", width=15)

    if ws["stack"]:
        # Get current ESP value for address calculation
        esp_str = ws["registers"].get("ESP", "0x00000000")
        esp_val = int(esp_str, 16) if esp_str else 0

        # Sort stack by offset
        sorted_stack = sorted(
            ws["stack"].items(),
            key=lambda x: int(x[0], 16),
        )

        # Apply scroll offset: shift the visible window
        # stack_view_offset is in number of slots (each slot = 1 sorted entry)
        view_offset = ws.get("stack_view_offset", 0)

        # Find the index of ESP+0x00 (first non-negative offset) as the center
        center_idx = 0
        for i, (o, _) in enumerate(sorted_stack):
            if int(o, 16) >= 0:
                center_idx = i
                break
        else:
            # All negative — center at end
            center_idx = len(sorted_stack)

        # Window: 10 items above center, 10 items at/below center
        max_visible = 10
        window_start = max(0, center_idx - max_visible + view_offset)
        window_end = min(len(sorted_stack), center_idx + max_visible + view_offset)

        hidden_above = window_start
        hidden_below = len(sorted_stack) - window_end

        # Show "..." if items hidden above
        if hidden_above > 0:
            stack_table.add_row(
                "[dim]...[/dim]",
                f"[dim]({hidden_above} more)[/dim]",
                "",
                "",
            )

        # Render visible rows
        for offset, val in sorted_stack[window_start:window_end]:
            offset_val = int(offset, 16)
            actual_addr = (esp_val + offset_val) & 0xFFFFFFFF
            addr_str = f"0x{actual_addr:08x}"

            display_val = f"[yellow]{val}[/yellow]" if val else "[dim]—[/dim]"

            name_match = ""
            if val in value_to_names:
                name_match = f"[dim green]{', '.join(value_to_names[val])}[/dim green]"

            stack_table.add_row(addr_str, f"ESP{offset}", display_val, name_match)

        # Show "..." if items hidden below
        if hidden_below > 0:
            stack_table.add_row(
                "[dim]...[/dim]",
                f"[dim]({hidden_below} more)[/dim]",
                "",
                "",
            )
    else:
        stack_table.add_row("[dim]—[/dim]", "[dim]empty[/dim]", "", "")

    return stack_table


def _build_named_values_table(ws: Dict[str, Any]) -> Table:
    """
    Build the named values display table.

    Args:
        ws: Worksheet dictionary

    Returns:
        Rich Table with named values
    """
    named_table = Table(
        title="NAMED VALUES",
        box=box.SIMPLE,
        show_header=True,
        header_style="bold magenta",
    )
    named_table.add_column("NAME", style="green", width=20)
    named_table.add_column("VALUE", style="yellow", width=24)

    for name, val in ws["named"].items():
        named_table.add_row(name, val)

    return named_table


def _build_gadgets_table(ws: Dict[str, Any]) -> Table:
    """
    Build the gadget library display table.

    Args:
        ws: Worksheet dictionary

    Returns:
        Rich Table with gadget library
    """
    gadgets_table = Table(
        title="GADGET LIBRARY",
        box=box.SIMPLE,
        show_header=True,
        header_style="bold magenta",
    )
    gadgets_table.add_column("ID", style="dim", width=4)
    gadgets_table.add_column("ADDRESS", style="cyan", width=12)
    gadgets_table.add_column("INSTRUCTIONS", style="white", width=50)

    # Sort gadgets by address for consistent ID assignment
    sorted_gadgets = sorted(
        ws["gadgets"].items(),
        key=lambda x: int(x[0], 16) if x[0].startswith("0x") else 0,
    )
    for i, (addr, instructions) in enumerate(sorted_gadgets, 1):
        # Escape brackets for Rich markup
        instructions_escaped = instructions.replace("[", r"\[")
        gadgets_table.add_row(str(i), addr, instructions_escaped)

    return gadgets_table


def _build_chain_table(ws: Dict[str, Any]) -> Table:
    """
    Build the ROP chain display table.

    Args:
        ws: Worksheet dictionary

    Returns:
        Rich Table with ROP chain
    """
    chain_table = Table(
        title="ROP CHAIN",
        box=box.SIMPLE,
        show_header=True,
        header_style="bold magenta",
    )
    chain_table.add_column("#", style="dim", width=4)
    chain_table.add_column("TYPE", style="yellow", width=8)
    chain_table.add_column("VALUE", style="cyan", width=12)
    chain_table.add_column("GADGET", style="dim white", width=6)

    # Build address to gadget ID lookup
    sorted_gadgets = sorted(
        ws["gadgets"].items(),
        key=lambda x: int(x[0], 16) if x[0].startswith("0x") else 0,
    )
    addr_to_id = {addr: str(i) for i, (addr, _) in enumerate(sorted_gadgets, 1)}

    for i, entry in enumerate(ws["chain"], 1):
        entry_type = entry.get("type", "unknown")
        entry_value = entry.get("value", "")

        # Check if this address matches a gadget
        gadget_id = ""
        if entry_type == "address" and entry_value in addr_to_id:
            gadget_id = f"G{addr_to_id[entry_value]}"

        chain_table.add_row(str(i), entry_type, entry_value, gadget_id)

    return chain_table


def _build_execution_log_table(ws: Dict[str, Any]) -> Table:
    """
    Build the execution log display table.

    Args:
        ws: Worksheet dictionary

    Returns:
        Rich Table with execution log
    """
    log_table = Table(
        title="EXECUTION LOG (Last 10)",
        box=box.SIMPLE,
        show_header=True,
        header_style="bold magenta",
    )
    log_table.add_column("#", style="dim", width=4)
    log_table.add_column("TYPE", style="yellow", width=8)
    log_table.add_column("SOURCE", style="cyan", width=12)
    log_table.add_column("OPERATION", style="white", width=50)

    for i, entry in enumerate(ws["execution_log"], 1):
        entry_type = entry.get("type", "unknown")
        entry_source = entry.get("source", "")
        entry_operation = entry.get("operation", "")

        # Color code by type
        if entry_type == "manual":
            type_display = "[white]Manual[/white]"
        else:  # auto
            type_display = "[dim green]Auto[/dim green]"

        # Escape brackets for Rich markup
        operation_escaped = entry_operation.replace("[", r"\[")

        log_table.add_row(str(i), type_display, entry_source, operation_escaped)

    return log_table


def build_worksheet_view(ws: Dict[str, Any]) -> Group:
    """
    Build the worksheet view as a renderable object.

    Args:
        ws: Worksheet dictionary

    Returns:
        Rich Group containing all display elements
    """
    elements = []

    # Build reverse lookup for named values (used by multiple tables)
    value_to_names = _build_value_to_names_lookup(ws)

    # Header with status
    elements.append(_build_header_panel(ws))

    # Registers and Stack side-by-side
    reg_table = _build_registers_table(ws, value_to_names)
    stack_table = _build_stack_table(ws, value_to_names)
    elements.append(Columns([reg_table, stack_table]))

    # Named Values
    if ws["named"]:
        elements.append(_build_named_values_table(ws))

    # Gadget Library
    if ws["gadgets"]:
        elements.append(_build_gadgets_table(ws))

    # ROP Chain
    if ws["chain"]:
        elements.append(_build_chain_table(ws))

    # Execution Log (last 10 operations)
    if ws["execution_log"]:
        elements.append(_build_execution_log_table(ws))

    # Notes
    if ws["notes"]:
        elements.append(Panel(ws["notes"], title="NOTES", border_style="dim white"))

    return Group(*elements)
