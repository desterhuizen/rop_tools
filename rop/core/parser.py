"""
ROPGadgetParser class for parsing rp++ output files.

Provides file parsing, filtering, and grouping functionality for ROP gadgets.
"""

import re
import sys
from collections import defaultdict
from typing import List, Dict, Optional, Set

from .gadget import Gadget
from .categories import categorize_gadget


class ROPGadgetParser:
    """Parser for rp++ output files"""

    # Regex pattern to match gadget lines
    GADGET_PATTERN = re.compile(r'^(0x[0-9a-fA-F]+):\s+(.+?)\s+;\s+\((\d+)\s+found\)$')

    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath
        self.gadgets: List[Gadget] = []
        self.metadata: Dict[str, str] = {}

    @staticmethod
    def detect_encoding(filepath: str) -> str:
        """
        Detect file encoding by checking for BOM (Byte Order Mark) and content patterns.
        Returns the detected encoding: 'utf-8', 'utf-16-le', 'utf-16-be', or 'utf-8' as fallback.
        """
        try:
            with open(filepath, 'rb') as f:
                # Read first few bytes to check for BOM
                raw_bytes = f.read(4)

                # Check for UTF-16 BOM
                if raw_bytes.startswith(b'\xff\xfe'):
                    return 'utf-16-le'  # UTF-16 Little Endian
                elif raw_bytes.startswith(b'\xfe\xff'):
                    return 'utf-16-be'  # UTF-16 Big Endian

                # Check for UTF-8 BOM
                if raw_bytes.startswith(b'\xef\xbb\xbf'):
                    return 'utf-8'

                # Read more bytes for heuristic detection
                f.seek(0)
                sample = f.read(1024)

                # Heuristic: UTF-16 files have lots of null bytes
                # Count null bytes in sample
                null_count = sample.count(b'\x00')

                # If more than 30% null bytes, likely UTF-16
                if null_count > len(sample) * 0.3:
                    # Check byte pattern to determine endianness
                    # UTF-16-LE has pattern: char, 0x00
                    # UTF-16-BE has pattern: 0x00, char
                    if len(sample) >= 2:
                        # Count positions of null bytes
                        even_nulls = sum(1 for i in range(0, len(sample)-1, 2) if sample[i] == 0)
                        odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)

                        if odd_nulls > even_nulls:
                            return 'utf-16-le'
                        elif even_nulls > odd_nulls:
                            return 'utf-16-be'

                # Default to UTF-8
                return 'utf-8'

        except Exception:
            # If detection fails, default to UTF-8
            return 'utf-8'

    def parse_file(self, filepath: Optional[str] = None) -> List[Gadget]:
        """Parse the rp++ output file with automatic encoding detection"""
        if filepath:
            self.filepath = filepath

        if not self.filepath:
            raise ValueError("No filepath provided")

        self.gadgets = []
        self.metadata = {}

        # Detect file encoding
        detected_encoding = self.detect_encoding(self.filepath)

        try:
            with open(self.filepath, 'r', encoding=detected_encoding, errors='replace') as f:
                for line in f:
                    line = line.rstrip()

                    # Skip empty lines
                    if not line:
                        continue

                    # Parse metadata lines
                    if line.startswith("Trying to open"):
                        self.metadata['dll'] = line.split("'")[1]
                    elif line.startswith("FileFormat:"):
                        parts = line.split(',')
                        self.metadata['format'] = parts[0].split(':')[1].strip()
                        self.metadata['arch'] = parts[1].split(':')[1].strip()
                    elif "total of" in line and "gadgets found" in line:
                        match = re.search(r'(\d+)\s+gadgets', line)
                        if match:
                            self.metadata['total_gadgets'] = match.group(1)

                    # Parse gadget lines
                    match = self.GADGET_PATTERN.match(line)
                    if match:
                        address = match.group(1)
                        instructions_str = match.group(2)
                        count = int(match.group(3))

                        # Split instructions by ';' and clean them
                        instructions = [inst.strip() for inst in instructions_str.split(';')]

                        gadget = Gadget(
                            address=address,
                            instructions=instructions,
                            raw_line=line,
                            count=count
                        )
                        self.gadgets.append(gadget)

        except FileNotFoundError:
            print(f"[!] Error: File '{self.filepath}' not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error parsing file: {e}", file=sys.stderr)
            sys.exit(1)

        return self.gadgets

    def filter_by_instruction(self, instruction: str, position: str = "any") -> List[Gadget]:
        """
        Filter gadgets by instruction
        position: 'any', 'first', 'last'
        """
        filtered = []
        instruction_lower = instruction.lower()

        for gadget in self.gadgets:
            if position == "first":
                if gadget.get_first_instruction().lower().startswith(instruction_lower):
                    filtered.append(gadget)
            elif position == "last":
                if gadget.get_last_instruction().lower().startswith(instruction_lower):
                    filtered.append(gadget)
            else:  # any
                if any(instruction_lower in inst.lower() for inst in gadget.instructions):
                    filtered.append(gadget)

        return filtered

    def filter_by_pattern(self, pattern: str) -> List[Gadget]:
        """Filter gadgets by regex pattern in instruction chain"""
        filtered = []
        regex = re.compile(pattern, re.IGNORECASE)

        for gadget in self.gadgets:
            if regex.search(gadget.get_instruction_chain()):
                filtered.append(gadget)

        return filtered

    def filter_bad_chars(self, bad_chars: List[str]) -> List[Gadget]:
        """Filter out gadgets containing bad characters in their addresses"""
        # Convert bad chars to set of hex strings (without 0x prefix)
        bad_char_set = {f"{ord(c):02x}" if len(c) == 1 else c.replace('0x', '').lower()
                        for c in bad_chars}

        return [g for g in self.gadgets if not g.contains_bad_chars(bad_char_set)]

    def filter_by_max_instructions(self, max_count: int) -> List[Gadget]:
        """Filter gadgets with at most max_count instructions"""
        return [g for g in self.gadgets if len(g.instructions) <= max_count]

    def group_by_last_instruction(self) -> Dict[str, List[Gadget]]:
        """Group gadgets by their last instruction"""
        groups = defaultdict(list)

        for gadget in self.gadgets:
            last_inst = gadget.get_last_instruction()
            # Normalize the instruction (remove operands for grouping)
            inst_name = last_inst.split()[0] if last_inst else "unknown"
            groups[inst_name].append(gadget)

        return dict(groups)

    def group_by_first_instruction(self) -> Dict[str, List[Gadget]]:
        """Group gadgets by their first instruction"""
        groups = defaultdict(list)

        for gadget in self.gadgets:
            first_inst = gadget.get_first_instruction()
            # Normalize the instruction (remove operands for grouping)
            inst_name = first_inst.split()[0] if first_inst else "unknown"
            groups[inst_name].append(gadget)

        return dict(groups)

    def find_rop_chains(self, chain_pattern: List[str]) -> List[List[Gadget]]:
        """
        Find potential ROP chains matching a pattern
        chain_pattern: list of instruction names to match in sequence
        """
        # This is a simple implementation - could be enhanced
        # to actually chain gadgets that work together
        results = []

        for pattern in chain_pattern:
            matches = self.filter_by_instruction(pattern, "first")
            if matches:
                results.append(matches)

        return results

    def categorize_gadget(self, gadget: Gadget) -> str:
        """Categorize a gadget based on its instructions (wrapper for core.categorize_gadget)"""
        return categorize_gadget(gadget)

    def group_by_category(self) -> Dict[str, List[Gadget]]:
        """Group gadgets by their functional category"""
        groups = defaultdict(list)

        for gadget in self.gadgets:
            category = self.categorize_gadget(gadget)
            groups[category].append(gadget)

        return dict(groups)

    def group_by_affected_register(self, gadgets: Optional[List[Gadget]] = None) -> Dict[str, List[Gadget]]:
        """Group gadgets by registers they affect"""
        groups = defaultdict(list)
        source = gadgets if gadgets is not None else self.gadgets

        for gadget in source:
            registers = gadget.get_affected_registers()
            if not registers:
                groups['none'].append(gadget)
            else:
                for reg in registers:
                    groups[reg].append(gadget)

        return dict(groups)

    def group_by_modified_register(self, gadgets: Optional[List[Gadget]] = None) -> Dict[str, List[Gadget]]:
        """Group gadgets by registers they modify"""
        groups = defaultdict(list)
        source = gadgets if gadgets is not None else self.gadgets

        for gadget in source:
            registers = gadget.get_modified_registers()
            if not registers:
                groups['none'].append(gadget)
            else:
                for reg in registers:
                    groups[reg].append(gadget)

        return dict(groups)

    def filter_by_register(self, register: str, modified_only: bool = False) -> List[Gadget]:
        """Filter gadgets that affect or modify a specific register"""
        register_lower = register.lower()
        filtered = []

        for gadget in self.gadgets:
            if modified_only:
                regs = gadget.get_modified_registers()
            else:
                regs = gadget.get_affected_registers()

            if register_lower in regs:
                filtered.append(gadget)

        return filtered

    def filter_dereferenced_registers(self, register: Optional[str] = None) -> List[Gadget]:
        """Filter gadgets that use dereferenced registers (e.g., [eax], [rsp+8])"""
        filtered = []

        for gadget in self.gadgets:
            if register:
                # Filter for specific dereferenced register
                if gadget.has_dereferenced_register(register):
                    filtered.append(gadget)
            else:
                # Filter for any dereferenced register
                if gadget.has_dereferenced_register():
                    filtered.append(gadget)

        return filtered

    def group_by_dereferenced_register(self, gadgets: Optional[List[Gadget]] = None) -> Dict[str, List[Gadget]]:
        """Group gadgets by dereferenced registers"""
        groups = defaultdict(list)
        source = gadgets if gadgets is not None else self.gadgets

        for gadget in source:
            derefs = gadget.get_dereferenced_registers()
            if not derefs:
                groups['none'].append(gadget)
            else:
                for reg in derefs:
                    groups[reg].append(gadget)

        return dict(groups)

    def group_by_category_and_register(self, gadgets: Optional[List[Gadget]] = None) -> Dict[str, Dict[str, List[Gadget]]]:
        """Group gadgets by category, then by modified registers within each category"""
        nested_groups = defaultdict(lambda: defaultdict(list))
        source = gadgets if gadgets is not None else self.gadgets

        for gadget in source:
            category = self.categorize_gadget(gadget)
            registers = gadget.get_modified_registers()

            if not registers:
                nested_groups[category]['none'].append(gadget)
            else:
                for reg in registers:
                    nested_groups[category][reg].append(gadget)

        return {k: dict(v) for k, v in nested_groups.items()}

    def get_statistics(self) -> Dict:
        """Get statistics about parsed gadgets"""
        stats = {
            'total_gadgets': len(self.gadgets),
            'unique_addresses': len(set(g.address for g in self.gadgets)),
        }

        # Count instructions
        last_inst_groups = self.group_by_last_instruction()
        sorted_groups = sorted(last_inst_groups.items(),
                              key=lambda x: len(x[1]),
                              reverse=True)[:10]
        stats['last_instruction_counts'] = {k: len(v) for k, v in sorted_groups}

        # Count categories
        category_groups = self.group_by_category()
        stats['category_counts'] = {k: len(v) for k, v in sorted(category_groups.items(),
                                                                  key=lambda x: len(x[1]),
                                                                  reverse=True)}

        return stats