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
        "Decimal", str(pe_info.image_base), label_style="cyan", value_style="yellow"
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
            "Subsystem", pe_info.subsystem, label_style="cyan", value_style="white"
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
        printer.print_text(f"\n[{dll}] - {len(entries)} imports", "bold cyan")

        table = Table(
            show_header=True, header_style="bold yellow", box=None, padding=(0, 1)
        )
        table.add_column("Function", style="white", overflow="fold")
        table.add_column("RVA", style="yellow", width=12, justify="right")
        table.add_column("Absolute", style="green", width=12, justify="right")

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
        iat_entries = [e for e in iat_entries if filter_dll_lower in e.dll.lower()]
        if not iat_entries:
            printer.print_text(
                f"\n[!] No imports found for DLL: {filter_dll}", "yellow"
            )
            return

    # Print header
    printer.print_header("\n=== Import Address Table (IAT) ===", "bold green")
    printer.print_labeled(
        "Total Imports", str(len(iat_entries)), label_style="cyan", value_style="white"
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


# DEP bypass APIs grouped by technique
DEP_BYPASS_APIS = {
    "VirtualProtect": {
        "dll": "kernel32.dll",
        "technique": "Mark stack as executable (RWX)",
        "args": "lpAddress, dwSize, flNewProtect (0x40=RWX), lpflOldProtect",
    },
    "VirtualAlloc": {
        "dll": "kernel32.dll",
        "technique": "Allocate executable memory",
        "args": "lpAddress, dwSize, flAllocationType (0x1000), flProtect (0x40=RWX)",
    },
    "WriteProcessMemory": {
        "dll": "kernel32.dll",
        "technique": "Copy shellcode to executable region",
        "args": "hProcess (-1), lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten",
    },
    "HeapCreate": {
        "dll": "kernel32.dll",
        "technique": "Create executable heap (HEAP_CREATE_ENABLE_EXECUTE)",
        "args": "flOptions (0x00040000), dwInitialSize, dwMaximumSize",
    },
    "SetProcessDEPPolicy": {
        "dll": "kernel32.dll",
        "technique": "Disable DEP for the process (Vista/XP)",
        "args": "dwFlags (0 = disable)",
    },
    "NtAllocateVirtualMemory": {
        "dll": "ntdll.dll",
        "technique": "Low-level executable allocation",
        "args": "ProcessHandle (-1), BaseAddress, ZeroBits, RegionSize, AllocType, Protect (0x40)",
    },
    "VirtualProtectEx": {
        "dll": "kernel32.dll",
        "technique": "Mark memory RWX in remote/current process",
        "args": "hProcess (-1), lpAddress, dwSize, flNewProtect (0x40), lpflOldProtect",
    },
    "NtProtectVirtualMemory": {
        "dll": "ntdll.dll",
        "technique": "Low-level memory protection change",
        "args": "ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect",
    },
}


def print_dep_bypass_info(filepath: str, image_base: int):
    """
    Scan IAT for DEP bypass candidate functions and print a summary.

    Args:
        filepath: Path to the PE file
        image_base: ImageBase address for calculating absolute addresses
    """
    iat_entries = PEAnalyzer.get_iat_entries(filepath)
    if not iat_entries:
        return

    # Find matches
    found = []
    for entry in iat_entries:
        if entry.function in DEP_BYPASS_APIS:
            info = DEP_BYPASS_APIS[entry.function]
            abs_addr = entry.get_absolute_address(image_base)
            found.append((entry, info, abs_addr))

    if not found:
        return

    printer.print_header("\n=== DEP Bypass Candidates ===", "bold green")
    printer.print_labeled(
        "Found",
        f"{len(found)} usable API(s) in IAT",
        label_style="cyan",
        value_style="white",
    )

    if printer.enabled:
        from rich.table import Table

        table = Table(
            show_header=True,
            header_style="bold yellow",
            box=None,
            padding=(0, 1),
        )
        table.add_column("API", style="bold white", overflow="fold")
        table.add_column("DLL", style="cyan", width=16)
        table.add_column("RVA", style="yellow", width=12, justify="right")
        table.add_column("IAT Address", style="green", width=12, justify="right")
        table.add_column("Technique", style="yellow", overflow="fold")

        for entry, info, abs_addr in found:
            table.add_row(
                entry.function,
                entry.dll,
                f"0x{entry.address:08x}",
                f"0x{abs_addr:08x}",
                info["technique"],
            )

        printer.console.print(table)

        # Print argument reference
        printer.print_text("\nArgument Reference:", "bold cyan")
        for entry, info, _abs_addr in found:
            printer.print_text(
                f"  {entry.function}({info['args']})",
                "dim white",
            )
    else:
        for entry, info, abs_addr in found:
            print(
                f"  {entry.function:<30} "
                f"[{entry.dll}]  "
                f"RVA: 0x{entry.address:08x}  "
                f"IAT: 0x{abs_addr:08x}  "
                f"- {info['technique']}"
            )
        print("\nArgument Reference:")
        for entry, info, _abs_addr in found:
            print(f"  {entry.function}({info['args']})")


def _build_parser():
    """Build and return the argument parser."""
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
    parser.add_argument(
        "--generate-completion",
        choices=["bash", "zsh"],
        metavar="SHELL",
        help="Print shell completion script and exit",
    )

    return parser


def main():
    """Main entry point for get_base_address tool"""
    from lib.completions import handle_completion

    if handle_completion(
        sys.argv[1:],
        _build_parser,
        ["get_base_address", "get_base_address.py"],
    ):
        return

    parser = _build_parser()
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
                # Show DEP bypass candidates (only when showing full IAT)
                if not args.dll:
                    print_dep_bypass_info(args.file, pe_info.image_base)
                print_iat_info(args.file, pe_info.image_base, filter_dll=args.dll)

    except FileNotFoundError:
        printer.print_text(f"[!] Error: File '{args.file}' not found", "bold red")
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
