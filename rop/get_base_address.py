#!/usr/bin/env python3
"""
Get the base address (ImageBase) and other information from a PE file (DLL/EXE).

This tool extracts PE file metadata including ImageBase, entry point, machine type,
and section information using the same display libraries as get_rop_gadgets.py.
"""

import argparse
import sys
from pathlib import Path

import pefile

# Add repo root to path for lib imports
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from lib.color_printer import printer  # noqa: E402
from rop.core import PEAnalyzer, PEInfo  # noqa: E402


def print_pe_info(pe_info: PEInfo, verbose: bool = False):
    """
    Print PE file information using ColorPrinter for consistent formatting.

    Args:
        pe_info: PEInfo object containing PE metadata
        verbose: If True, print detailed section information
    """
    # Print main header
    printer.print_header("=== PE File Information ===", "bold green")

    # Print basic info
    printer.print_labeled(
        "File", pe_info.filepath, label_style="cyan", value_style="white"
    )
    printer.print_labeled(
        "ImageBase",
        f"0x{pe_info.image_base:x}",
        label_style="cyan",
        value_style="yellow",
    )
    printer.print_labeled(
        "Decimal", str(pe_info.image_base), label_style="cyan",
        value_style="yellow"
    )

    if verbose:
        printer.print_labeled(
            "Entry Point (RVA)",
            f"0x{pe_info.entry_point:x}",
            label_style="cyan",
            value_style="yellow",
        )
        abs_entry = pe_info.get_absolute_entry_point()
        printer.print_labeled(
            "Entry Point (Absolute)",
            f"0x{abs_entry:x}",
            label_style="cyan",
            value_style="yellow",
        )
        printer.print_labeled(
            "Machine Type",
            pe_info.machine_type,
            label_style="cyan",
            value_style="white",
        )
        printer.print_labeled(
            "Subsystem", pe_info.subsystem, label_style="cyan",
            value_style="white"
        )

        # Print section information
        if pe_info.sections:
            printer.print_header("\n=== Sections ===", "bold green")

            if printer.enabled:
                # Use Rich table for colored output
                from rich.table import Table

                table = Table(show_header=True, header_style="bold yellow")
                table.add_column("Name", style="cyan", width=12)
                table.add_column("Virtual Addr", style="yellow", width=14)
                table.add_column("Virtual Size", style="white", width=14)
                table.add_column("Raw Size", style="white", width=14)
                table.add_column("Flags", style="green", width=30)

                for section in pe_info.sections:
                    flags = ", ".join(section.get_characteristics_flags())
                    table.add_row(
                        section.name,
                        f"0x{section.virtual_address:08x}",
                        f"0x{section.virtual_size:08x}",
                        f"0x{section.raw_size:08x}",
                        flags,
                    )

                printer.console.print(table)
            else:
                # Fallback to plain text
                for section in pe_info.sections:
                    flags = ", ".join(section.get_characteristics_flags())
                    print(f"\n{section.name}:")
                    print(f"  Virtual Address: 0x{section.virtual_address:08x}")
                    print(f"  Virtual Size:    0x{section.virtual_size:08x}")
                    print(f"  Raw Size:        0x{section.raw_size:08x}")
                    print(f"  Flags:           {flags}")


def _get_func_display(entry):
    """Format function name with ordinal if applicable."""
    if entry.ordinal and not entry.function.startswith("Ordinal_"):
        return f"{entry.function} (#{entry.ordinal})"
    return entry.function


def _print_iat_colored(dll_groups, image_base):
    """Print IAT entries using Rich tables."""
    from rich.table import Table

    for dll, entries in sorted(dll_groups.items()):
        printer.print_text(f"\n[{dll}] - {len(entries)} imports",
                           "bold cyan")

        table = Table(
            show_header=True, header_style="bold yellow", box=None,
            padding=(0, 1)
        )
        table.add_column("Function", style="white", overflow="fold")
        table.add_column("RVA", style="yellow", width=12, justify="right")
        table.add_column("Absolute", style="green", width=12,
                         justify="right")

        for entry in entries:
            abs_addr = entry.get_absolute_address(image_base)
            table.add_row(
                _get_func_display(entry),
                f"0x{entry.address:08x}",
                f"0x{abs_addr:08x}",
            )

        printer.console.print(table)


def _print_iat_plain(dll_groups, image_base):
    """Print IAT entries as plain text."""
    for dll, entries in sorted(dll_groups.items()):
        print(f"\n[{dll}] - {len(entries)} imports")
        for entry in entries:
            abs_addr = entry.get_absolute_address(image_base)
            func_display = _get_func_display(entry)
            print(
                f"  {func_display:<40} RVA: 0x{entry.address:08x}  Abs: 0x{abs_addr:08x}"
            )


def print_iat_info(filepath: str, image_base: int, filter_dll: str = None):
    """
    Print Import Address Table (IAT) information.

    Args:
        filepath: Path to the PE file
        image_base: ImageBase address for calculating absolute addresses
        filter_dll: Optional DLL name to filter by (case-insensitive)
    """
    iat_entries = PEAnalyzer.get_iat_entries(filepath)

    if not iat_entries:
        printer.print_text("\n[!] No imports found in this file", "yellow")
        return

    # Filter by DLL if requested
    if filter_dll:
        filter_dll_lower = filter_dll.lower()
        iat_entries = [e for e in iat_entries if
                       filter_dll_lower in e.dll.lower()]
        if not iat_entries:
            printer.print_text(
                f"\n[!] No imports found for DLL: {filter_dll}", "yellow"
            )
            return

    # Print header
    printer.print_header("\n=== Import Address Table (IAT) ===", "bold green")
    printer.print_labeled(
        "Total Imports", str(len(iat_entries)), label_style="cyan",
        value_style="white"
    )

    # Group by DLL
    dll_groups = {}
    for entry in iat_entries:
        if entry.dll not in dll_groups:
            dll_groups[entry.dll] = []
        dll_groups[entry.dll].append(entry)

    if printer.enabled:
        _print_iat_colored(dll_groups, image_base)
    else:
        _print_iat_plain(dll_groups, image_base)


def main():
    """Main entry point for get_base_address tool"""
    parser = argparse.ArgumentParser(
        description="Extract PE file information including ImageBase address",
        epilog="Example: %(prog)s kernel32.dll -v",
    )
    parser.add_argument("file", help="PE file to analyze (DLL or EXE)")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed PE information including sections",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only print the ImageBase address (for scripting)",
    )
    parser.add_argument(
        "--iat",
        action="store_true",
        help="Display Import Address Table (IAT) information",
    )
    parser.add_argument(
        "--dll",
        metavar="NAME",
        help="Filter IAT to show only imports from specified DLL (case-insensitive)",
    )

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        printer.disable()

    try:
        if args.quiet:
            # Quiet mode: just print the hex address
            base_address = PEAnalyzer.get_base_address(args.file)
            print(f"0x{base_address:x}")
        else:
            # Normal mode: print formatted information
            pe_info = PEAnalyzer.analyze_file(args.file)
            print_pe_info(pe_info, verbose=args.verbose)

            # Print IAT if requested
            if args.iat:
                print_iat_info(args.file, pe_info.image_base,
                               filter_dll=args.dll)

    except FileNotFoundError:
        printer.print_text(f"[!] Error: File '{args.file}' not found",
                           "bold red")
        sys.exit(1)
    except pefile.PEFormatError:
        printer.print_text(
            f"[!] Error: '{args.file}' is not a valid PE file", "bold red"
        )
        sys.exit(1)
    except Exception as e:
        printer.print_text(f"[!] Error: {e}", "bold red")
        sys.exit(1)


if __name__ == "__main__":
    main()
