"""
Gadget data structure for ROP analysis.

Defines the Gadget class which represents a single ROP gadget with
methods for analyzing instructions, registers, and bad characters.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class Gadget:
    """Represents a single ROP gadget"""

    address: str
    instructions: List[str]
    raw_line: str
    count: int

    def __str__(self):
        return self.raw_line

    def get_instruction_chain(self) -> str:
        """Returns the full instruction chain as a string"""
        return " ; ".join(self.instructions)

    def get_last_instruction(self) -> str:
        """Returns the last instruction in the gadget"""
        return self.instructions[-1] if self.instructions else ""

    def get_first_instruction(self) -> str:
        """Returns the first instruction in the gadget"""
        return self.instructions[0] if self.instructions else ""

    def contains_bad_chars(self, bad_chars: Set[str]) -> bool:
        """Check if the gadget address contains any bad characters"""
        # Remove '0x' prefix and convert to bytes
        addr_hex = self.address[2:]
        # Check each byte pair
        for i in range(0, len(addr_hex), 2):
            byte = addr_hex[i: i + 2]
            if byte in bad_chars:
                return True
        return False

    def get_affected_registers(self) -> Set[str]:
        """Extract all registers affected by this gadget"""
        registers = set()
        # Common x86/x64 registers
        reg_patterns = [
            r"\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b",  # 32-bit
            r"\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)\b",
            # 64-bit
            r"\b(ax|bx|cx|dx|si|di|sp|bp)\b",  # 16-bit
            r"\b(al|ah|bl|bh|cl|ch|dl|dh)\b",  # 8-bit
        ]

        for inst in self.instructions:
            inst_lower = inst.lower()
            for pattern in reg_patterns:
                matches = re.findall(pattern, inst_lower)
                registers.update(matches)

        return registers

    def get_modified_registers(self) -> Set[str]:
        """Extract registers that are modified (destination operands)"""
        modified = set()
        reg_pattern = r"\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15|ax|bx|cx|dx|si|di|sp|bp|al|ah|bl|bh|cl|ch|dl|dh)\b"

        for inst in self.instructions:
            inst_lower = inst.lower().strip()

            # For most instructions, first operand is destination
            if inst_lower.startswith((
                "mov",
                "lea",
                "add",
                "sub",
                "xor",
                "and",
                "or",
                "inc",
                "dec",
                "neg",
                "not",
                "shl",
                "shr",
                "sal",
                "sar",
                "rol",
                "ror",
                "mul",
                "imul",
                "div",
                "idiv",
            )):
                parts = inst_lower.split(None, 1)
                if len(parts) > 1:
                    operands = parts[1]
                    # Get first operand (destination)
                    dest = operands.split(",")[0].strip()
                    matches = re.findall(reg_pattern, dest)
                    modified.update(matches)

            # Pop and XCHG modify the register(s)
            elif inst_lower.startswith(("pop", "xchg")):
                matches = re.findall(reg_pattern, inst_lower)
                modified.update(matches)

        return modified

    def get_dereferenced_registers(self) -> Set[str]:
        """Extract registers that are dereferenced (used in brackets like [eax], [rsp+8], etc)"""
        dereferenced = set()
        # Pattern to match register dereferences: [reg], [reg+offset], [reg-offset], [reg*scale], etc
        deref_pattern = r"\[([^\]]*?)\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15|ax|bx|cx|dx|si|di|sp|bp)\b[^\]]*?\]"

        for inst in self.instructions:
            inst_lower = inst.lower()
            matches = re.findall(deref_pattern, inst_lower)
            # matches is a list of tuples, extract the register (second element)
            for match in matches:
                dereferenced.add(match[1])

        return dereferenced

    def has_dereferenced_register(self, register: Optional[str] = None) -> bool:
        """Check if gadget has any dereferenced register, or optionally a specific one"""
        derefs = self.get_dereferenced_registers()
        if register:
            return register.lower() in derefs
        return len(derefs) > 0
