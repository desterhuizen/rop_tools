#!/usr/bin/env python3
"""
ROP Gadget Parser and Analyzer

A command-line tool for parsing, filtering, and analyzing ROP (Return-Oriented Programming)
gadgets from rp++ (rp_win_x86) output files.

Features:
  - Parse rp++ output with automatic UTF-8/UTF-16 encoding detection
  - Filter gadgets by instruction, register, category, or regex pattern
  - Automatically filter out bad instructions that break ROP chains
  - Group gadgets by instruction, category, or register
  - Display with colored output and syntax highlighting
  - Calculate offsets from module base addresses
  - Exclude bad characters from gadget addresses
  - Sort by instruction count or address

Architecture:
  This CLI orchestrates modular components:
  - core.parser: ROPGadgetParser for file parsing
  - core.gadget: Gadget dataclass and analysis methods
  - core.categories: Gadget categorization logic
  - display.formatters: Output formatting and display
  - lib.color_printer: Terminal color abstraction (shared library)

Usage:
  python3 get_rop_gadgets.py -f gadgets.txt -c stack_pop
  python3 get_rop_gadgets.py -f gadgets.txt -r "pop.*ret" --highlight
  python3 get_rop_gadgets.py -f gadgets.txt -g category --show-category

For detailed examples, run: python3 get_rop_gadgets.py --help
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# Add repo root to Python path to access shared lib/
# Use .resolve() to handle symlinks correctly
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Import core classes and functions
from rop.core import ROPGadgetParser, get_category_style  # noqa: E402

# Import display functions
from rop.display import print_gadgets, print_statistics, printer  # noqa: E402

# List of instructions that make gadgets useless for ROP chains
# These instructions can cause crashes, unpredictable behavior, or break exploit chains
BAD_INSTRUCTIONS = [
    "clts",
    "hlt",
    "lmsw",
    "ltr",
    "lgdt",
    "lidt",
    "lldt",
    "mov cr",
    "mov dr",
    "mov tr",
    "in ",
    "ins",
    "invlpg",
    "invd",
    "out",
    "outs",
    "cli",
    "sti",
    "popf",
    "pushf",
    "int",
    "iret",
    "iretd",
    "swapgs",
    "wbinvd",
    "call",
    "jmp",
    "leave",
    "ja",
    "jb",
    "jc",
    "je",
    "jr",
    "jg",
    "jl",
    "jn",
    "jo",
    "jp",
    "js",
    "jz",
    "lock",
    "enter",
    "wait",
    "???",
]


def _contains_bad_instruction(gadget):
    """Check if gadget contains any bad instructions."""
    instruction_chain = gadget.get_instruction_chain().lower()
    return any(bad_inst in instruction_chain for bad_inst in BAD_INSTRUCTIONS)


def _apply_pattern_filters(args, rop_parser, filtered_gadgets):
    """Apply category, instruction, regex, and exclusion filters."""
    if args.category:
        before = len(filtered_gadgets)
        filtered_gadgets = [
            g
            for g in filtered_gadgets
            if rop_parser.categorize_gadget(g) == args.category
        ]
        print(
            f"[*] Found {len(filtered_gadgets)} gadgets in category '{args.category}' "
            f"(removed {before - len(filtered_gadgets)})\n"
        )

    if args.instruction:
        filtered_gadgets = rop_parser.filter_by_instruction(
            args.instruction, args.position
        )
        print(
            f"[*] Found {len(filtered_gadgets)} gadgets with '{args.instruction}' "
            f"({args.position} position)\n"
        )

    if args.regex:
        filtered_gadgets = [
            g
            for g in filtered_gadgets
            if re.search(args.regex, g.get_instruction_chain(), re.IGNORECASE)
        ]
        print(
            f"[*] Found {len(filtered_gadgets)} gadgets matching regex '{args.regex}'\n"
        )

    if args.exclude:
        before = len(filtered_gadgets)
        filtered_gadgets = [
            g
            for g in filtered_gadgets
            if not re.search(args.exclude, g.get_instruction_chain(), re.IGNORECASE)
        ]
        print(
            f"[*] Excluded {before - len(filtered_gadgets)} gadgets matching pattern '{args.exclude}' "
            f"({len(filtered_gadgets)} remaining)\n"
        )

    return filtered_gadgets


def _apply_constraint_filters(args, rop_parser, filtered_gadgets):
    """Apply max-instructions, bad chars, register, deref, and bad instruction filters."""
    if args.max_instructions:
        before = len(filtered_gadgets)
        filtered_gadgets = [
            g for g in filtered_gadgets if len(g.instructions) <= args.max_instructions
        ]
        print(
            f"[*] Filtered to {len(filtered_gadgets)} gadgets with "
            f"<= {args.max_instructions} instructions "
            f"(removed {before - len(filtered_gadgets)})\n"
        )

    if args.bad_chars:
        before = len(filtered_gadgets)
        bad_chars_str = (
            args.bad_chars.replace("\\x", " ").replace(",", " ").strip().split()
        )
        bad_char_set = {c.lower() for c in bad_chars_str}
        filtered_gadgets = [
            g for g in filtered_gadgets if not g.contains_bad_chars(bad_char_set)
        ]
        print(
            f"[*] Filtered to {len(filtered_gadgets)} gadgets without bad chars "
            f"(removed {before - len(filtered_gadgets)})\n"
        )

    if args.register:
        before = len(filtered_gadgets)
        rop_parser.gadgets = filtered_gadgets
        filtered_gadgets = rop_parser.filter_by_register(
            args.register, args.modified_only
        )
        rop_parser.gadgets = rop_parser.gadgets
        mod_str = "modify" if args.modified_only else "affect"
        print(
            f"[*] Found {len(filtered_gadgets)} gadgets that {mod_str} register '{args.register}' "
            f"(removed {before - len(filtered_gadgets)})\n"
        )

    if args.deref is not None:
        before = len(filtered_gadgets)
        deref_reg = args.deref if args.deref else None
        rop_parser.gadgets = filtered_gadgets
        filtered_gadgets = rop_parser.filter_dereferenced_registers(deref_reg)
        rop_parser.gadgets = rop_parser.gadgets

        if deref_reg:
            print(
                f"[*] Found {len(filtered_gadgets)} gadgets with dereferenced register '[{deref_reg}]' "
                f"(removed {before - len(filtered_gadgets)})\n"
            )
        else:
            print(
                f"[*] Found {len(filtered_gadgets)} gadgets with dereferenced registers "
                f"(removed {before - len(filtered_gadgets)})\n"
            )

    if not args.keep_bad_instructions:
        before = len(filtered_gadgets)
        filtered_gadgets = [
            g for g in filtered_gadgets if not _contains_bad_instruction(g)
        ]
        print(
            f"[*] Filtered out {before - len(filtered_gadgets)} gadgets with bad instructions "
            f"({len(filtered_gadgets)} remaining)\n"
        )

    return filtered_gadgets


def apply_filters(args, rop_parser, filtered_gadgets):
    """Apply all user-specified filters to the gadget list."""
    filtered_gadgets = _apply_pattern_filters(args, rop_parser, filtered_gadgets)
    filtered_gadgets = _apply_constraint_filters(args, rop_parser, filtered_gadgets)
    return filtered_gadgets


def parse_base_address(offset_str):
    """Parse a base address string (hex or decimal) and return the integer value."""
    try:
        if offset_str.startswith("0x"):
            return int(offset_str, 16)
        return int(offset_str, 10)
    except ValueError:
        print(
            f"[!] Error: Invalid base address format '{offset_str}'. "
            f"Use hex (e.g., 0x10000000) or decimal format.",
            file=sys.stderr,
        )
        sys.exit(1)


def _display_simple_groups(groups, label, style, display_kwargs):
    """Display gadgets grouped by a single key (register, instruction, etc.)."""
    printer.print_section(f"=== Grouped by {label} ===\n", "bold green")

    for key, gadgets in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
        printer.print_section(f"\n--- {key} ({len(gadgets)} gadgets) ---", style)
        print_gadgets(gadgets, **display_kwargs)


def _display_category_register_groups(nested_groups, display_kwargs):
    """Display gadgets grouped by category, then by modified register."""
    printer.print_section(
        "=== Grouped by category, then by modified register ===\n", "bold green"
    )

    category_totals = {
        cat: sum(len(gads) for gads in regs.values())
        for cat, regs in nested_groups.items()
    }

    for category in sorted(
        category_totals.keys(), key=lambda x: category_totals[x], reverse=True
    ):
        reg_groups = nested_groups[category]
        total_in_cat = category_totals[category]

        category_style = get_category_style(category)
        printer.print_section(f"\n{'=' * 70}", category_style)
        printer.print_section(
            f"  {category.upper()} ({total_in_cat} total gadgets)",
            category_style,
        )
        printer.print_section(f"{'=' * 70}\n", category_style)

        for reg, gadgets in sorted(
            reg_groups.items(), key=lambda x: len(x[1]), reverse=True
        ):
            printer.print_section(f"  --- {reg} ({len(gadgets)} gadgets) ---", "cyan")
            print_gadgets(gadgets, **display_kwargs)
            print()


def _display_category_groups(rop_parser, filtered_gadgets, display_kwargs):
    """Display gadgets grouped by category with per-category styling."""
    groups = defaultdict(list)
    for g in filtered_gadgets:
        category = rop_parser.categorize_gadget(g)
        groups[category].append(g)

    printer.print_section("=== Grouped by category ===\n", "bold green")
    for category, gadgets in sorted(
        groups.items(), key=lambda x: len(x[1]), reverse=True
    ):
        category_style = get_category_style(category)
        printer.print_section(
            f"\n--- {category} ({len(gadgets)} gadgets) ---", category_style
        )
        print_gadgets(gadgets, **display_kwargs)


def _get_grouped_gadgets(group_type, rop_parser, filtered_gadgets):
    """Build groups and return (groups, label, style) for the given group type."""
    if group_type == "register":
        return (
            rop_parser.group_by_affected_register(filtered_gadgets),
            "affected register",
            "yellow",
        )

    if group_type == "modified-register":
        return (
            rop_parser.group_by_modified_register(filtered_gadgets),
            "modified register",
            "cyan",
        )

    if group_type == "dereferenced-register":
        groups = rop_parser.group_by_dereferenced_register(filtered_gadgets)
        formatted = {f"[{k}]": v for k, v in groups.items()}
        return formatted, "dereferenced register", "magenta"

    # "last" or "first" instruction grouping
    groups = defaultdict(list)
    if group_type == "last":
        for g in filtered_gadgets:
            groups[g.get_last_instruction().split()[0]].append(g)
        return groups, "last instruction", "white"

    # default: first
    for g in filtered_gadgets:
        groups[g.get_first_instruction().split()[0]].append(g)
    return groups, "first instruction", "white"


def display_grouped_results(args, rop_parser, filtered_gadgets, display_kwargs):
    """Display gadgets grouped by the user's chosen grouping method."""
    if args.group == "category":
        _display_category_groups(rop_parser, filtered_gadgets, display_kwargs)
    elif args.group == "category-register":
        nested_groups = rop_parser.group_by_category_and_register(filtered_gadgets)
        _display_category_register_groups(nested_groups, display_kwargs)
    else:
        groups, label, style = _get_grouped_gadgets(
            args.group, rop_parser, filtered_gadgets
        )
        _display_simple_groups(groups, label, style, display_kwargs)


def build_arg_parser():
    """Build and return the argument parser."""
    arg_parser = argparse.ArgumentParser(
        description="Parse and analyze ROP gadgets from rp++ output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse and show all gadgets
  %(prog)s -f gadgets.txt

  # Find all 'pop' instructions with categories shown
  %(prog)s -f gadgets.txt -i pop --show-category

  # Find gadgets ending with 'ret'
  %(prog)s -f gadgets.txt -i ret -p last

  # Filter out bad characters and limit to 3 instructions
  %(prog)s -f gadgets.txt -b "\\x00\\x0a" -m 3

  # Filter bad chars using comma-separated format
  %(prog)s -f gadgets.txt -b "00,0a,0d" -m 3

  # Group by last instruction
  %(prog)s -f gadgets.txt -g last

  # Group by category
  %(prog)s -f gadgets.txt -g category

  # Group by modified register
  %(prog)s -f gadgets.txt -g modified-register

  # Group by category, then by modified register (drill-down)
  %(prog)s -f gadgets.txt -g category-register -l 5

  # Filter by category (stack manipulation)
  %(prog)s -f gadgets.txt -c stack_pop

  # Filter gadgets that affect eax register
  %(prog)s -f gadgets.txt --register eax

  # Filter gadgets that modify (not just use) esp register
  %(prog)s -f gadgets.txt --register esp --modified-only

  # Find stack_pop gadgets that modify ebx, grouped by register
  %(prog)s -f gadgets.txt -c stack_pop -g modified-register

  # Filter gadgets with any dereferenced register
  %(prog)s -f gadgets.txt --deref ""

  # Filter gadgets with dereferenced eax register (e.g., [eax], [eax+4])
  %(prog)s -f gadgets.txt --deref eax

  # Group by dereferenced register
  %(prog)s -f gadgets.txt -g dereferenced-register

  # Show statistics
  %(prog)s -f gadgets.txt -s

  # Search with regex pattern
  %(prog)s -f gadgets.txt -r "pop.*pop.*ret"

  # Exclude gadgets with specific patterns (esp/ebp registers)
  %(prog)s -f gadgets.txt -r "pop" -e "esp|ebp"

  # Find mov gadgets but exclude any with eax or ebx
  %(prog)s -f gadgets.txt -r "mov" -e "eax|ebx"

  # Show gadgets with offset from base address
  %(prog)s -f gadgets.txt -i pop --offset 0x10000000

  # Filter out bad instructions (default behavior)
  %(prog)s -f gadgets.txt -i pop

  # Keep all gadgets, including those with bad instructions
  %(prog)s -f gadgets.txt -i pop --keep-bad-instructions

Categories:
  stack_pivot, stack_pop, stack_push, load_register, move_register,
  xchg_register, memory_read, memory_write, arithmetic, logic,
  call, jmp, ret, conditional, syscall, interrupt, string_ops, other
        """,
    )

    arg_parser.add_argument(
        "-f", "--file", required=True, help="Path to rp++ output file"
    )
    arg_parser.add_argument("-i", "--instruction", help="Filter by instruction name")
    arg_parser.add_argument(
        "-p",
        "--position",
        choices=["any", "first", "last"],
        default="any",
        help="Position of instruction to match",
    )
    arg_parser.add_argument(
        "-b",
        "--bad-chars",
        help='Bad characters to filter (e.g., "\\x00\\x0a" or "00,0a,0d")',
    )
    arg_parser.add_argument(
        "-m",
        "--max-instructions",
        type=int,
        help="Maximum number of instructions in gadget",
    )
    arg_parser.add_argument(
        "-g",
        "--group",
        choices=[
            "first",
            "last",
            "category",
            "register",
            "modified-register",
            "dereferenced-register",
            "category-register",
        ],
        help="Group gadgets by first/last instruction, category, affected/modified/dereferenced registers, or category+register",
    )
    arg_parser.add_argument(
        "-c",
        "--category",
        help="Filter by gadget category (e.g., stack_pop, memory_write)",
    )
    arg_parser.add_argument(
        "-r", "--regex", help="Filter by regex pattern in instruction chain"
    )
    arg_parser.add_argument(
        "-e",
        "--exclude",
        help='Exclude gadgets matching this regex pattern (e.g., "esp|ebp" to exclude stack pointer operations)',
    )
    arg_parser.add_argument("--register", help="Filter by register (e.g., eax, rsp)")
    arg_parser.add_argument(
        "--modified-only",
        action="store_true",
        help="With --register, only show gadgets that modify the register (not just use it)",
    )
    arg_parser.add_argument(
        "--deref",
        "--dereferenced",
        help="Filter gadgets with dereferenced registers (e.g., [eax], [rsp+8]). Optionally specify a register.",
    )
    arg_parser.add_argument(
        "-l", "--limit", type=int, help="Limit number of results displayed"
    )
    arg_parser.add_argument(
        "-s", "--stats", action="store_true", help="Show statistics about gadgets"
    )
    arg_parser.add_argument(
        "--show-category", action="store_true", help="Display category for each gadget"
    )
    arg_parser.add_argument(
        "--show-count",
        action="store_true",
        help="Display instruction count for each gadget",
    )
    arg_parser.add_argument(
        "--highlight",
        action="store_true",
        help="Highlight regex matches in output (requires -r/--regex)",
    )
    arg_parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    arg_parser.add_argument(
        "--sort",
        choices=["count", "address"],
        default="count",
        help="Sort gadgets by count (default) or address",
    )
    arg_parser.add_argument(
        "--offset",
        type=str,
        help="Calculate offset from base address (e.g., 0x10000000). Displays offset to the right of address in magenta.",
    )
    arg_parser.add_argument(
        "--keep-bad-instructions",
        action="store_true",
        help="Keep gadgets with bad instructions (call, jmp, int, etc.). By default, these are filtered out.",
    )

    return arg_parser


def main():
    args = build_arg_parser().parse_args()

    # Disable colors if requested
    if args.no_color:
        printer.disable()

    # Parse the file
    print(f"[*] Parsing file: {args.file}")
    rop_parser = ROPGadgetParser(args.file)
    rop_parser.parse_file()
    print(f"[*] Parsed {len(rop_parser.gadgets)} gadgets\n")

    # Apply filters
    filtered_gadgets = apply_filters(args, rop_parser, rop_parser.gadgets)

    # Sort the gadgets
    if args.sort == "count":
        filtered_gadgets = sorted(filtered_gadgets, key=lambda g: len(g.instructions))
    elif args.sort == "address":
        filtered_gadgets = sorted(filtered_gadgets, key=lambda g: int(g.address, 16))

    # Determine highlight pattern and base address
    highlight_pattern = args.regex if (args.highlight and args.regex) else None
    base_address = parse_base_address(args.offset) if args.offset else None

    # Common display kwargs
    display_kwargs = {
        "limit": args.limit,
        "parser": rop_parser,
        "show_category": args.show_category,
        "show_count": args.show_count,
        "highlight_pattern": highlight_pattern,
        "base_address": base_address,
    }

    # Display results
    if args.stats:
        print_statistics(rop_parser)
    elif args.group:
        display_grouped_results(args, rop_parser, filtered_gadgets, display_kwargs)
    else:
        printer.print_section(
            f"=== Results ({len(filtered_gadgets)} gadgets) ===\n", "bold green"
        )
        print_gadgets(filtered_gadgets, **display_kwargs)


if __name__ == "__main__":
    main()
