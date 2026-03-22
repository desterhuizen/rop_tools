"""
Display formatters for ROP gadgets.

Provides functions for printing gadgets with color and formatting.
"""

from typing import List, Optional

try:
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Text = None

from lib.color_printer import printer
from rop.core import Gadget, ROPGadgetParser, get_category_style


def _print_gadget_plain(
        gadget: Gadget,
        parser: ROPGadgetParser,
        show_category: bool = False,
        show_count: bool = False,
        base_address: Optional[int] = None,
):
    """Print a single gadget without colors."""
    prefix = ""
    if show_category:
        category = parser.categorize_gadget(gadget)
        prefix += f"[{category}] "
    if show_count:
        inst_count = len(gadget.instructions)
        prefix += f"[{inst_count}] "

    offset_str = ""
    if base_address is not None:
        gadget_addr = int(gadget.address, 16)
        offset = gadget_addr - base_address
        offset_str = f" (offset: +0x{offset:x})"

    print(f"{prefix}{gadget}{offset_str}")


def _build_rich_output(
        gadget: Gadget,
        parser: ROPGadgetParser,
        address: str,
        rest,
        show_category: bool = False,
        show_count: bool = False,
        base_address: Optional[int] = None,
):
    """Build Rich Text output for a colored gadget display."""
    output = Text()

    if show_count:
        inst_count = len(gadget.instructions)
        output.append(f"[{inst_count:2d}] ", style="yellow")

    if show_category:
        category = parser.categorize_gadget(gadget)
        category_style = get_category_style(category)
        output.append(f"[{category}] ", style=category_style)

    output.append(address, style="cyan")

    if base_address is not None:
        gadget_addr = int(gadget.address, 16)
        offset = gadget_addr - base_address
        output.append(f" (+0x{offset:x})", style="#ff8800")

    output.append(":")
    output.append(rest)
    return output


def print_gadget_colored(
        gadget: Gadget,
        parser: ROPGadgetParser,
        show_category: bool = False,
        show_count: bool = False,
        highlight_pattern: Optional[str] = None,
        base_address: Optional[int] = None,
):
    """Print a single gadget with colors using ColorPrinter"""
    if not printer.enabled:
        _print_gadget_plain(gadget, parser, show_category, show_count,
                            base_address)
        return

    parts = gadget.raw_line.split(":", 1)
    if len(parts) != 2:
        print(gadget)
        return

    address = parts[0]
    rest = parts[1]

    if highlight_pattern:
        rest = printer.stylize_regex(rest, highlight_pattern)

    output = _build_rich_output(
        gadget, parser, address, rest,
        show_category, show_count, base_address,
    )
    printer.console.print(output)


def print_gadgets(
        gadgets: List[Gadget],
        limit: Optional[int] = None,
        parser: Optional[ROPGadgetParser] = None,
        show_category: bool = False,
        show_count: bool = False,
        highlight_pattern: Optional[str] = None,
        base_address: Optional[int] = None,
):
    """Pretty print gadgets with optional color using ColorPrinter"""
    for count, gadget in enumerate(gadgets, 1):
        if parser and printer.enabled:
            print_gadget_colored(
                gadget,
                parser,
                show_category,
                show_count,
                highlight_pattern,
                base_address,
            )
        else:
            print(gadget)
        if limit and count >= limit:
            remaining = len(gadgets) - limit
            if remaining > 0:
                if printer.enabled:
                    printer.print_text(f"\n... and {remaining} more gadgets",
                                       "yellow")
                else:
                    print(f"\n... and {remaining} more gadgets")
            break


def print_statistics(parser: ROPGadgetParser):
    """Print statistics about the gadgets with colors using ColorPrinter"""
    stats = parser.get_statistics()

    printer.print_header("=== Gadget Statistics ===", "bold green")
    printer.print_labeled("Total gadgets", stats["total_gadgets"])
    printer.print_labeled("Unique addresses", stats["unique_addresses"])

    if parser.metadata:
        printer.print_header("=== File Metadata ===", "bold green")
        for key, value in parser.metadata.items():
            printer.print_labeled(key, value)

    printer.print_header("=== Top 10 Last Instructions ===", "bold green")
    for inst, count in stats["last_instruction_counts"].items():
        printer.print_labeled(
            inst, f"{count} gadgets", label_style="yellow", value_style="white"
        )

    if "category_counts" in stats:
        printer.print_header("=== Gadget Categories ===", "bold green")
        for category, count in stats["category_counts"].items():
            category_style = get_category_style(category)
            printer.print_labeled(
                category,
                f"{count} gadgets",
                label_style=category_style,
                value_style="white",
            )
