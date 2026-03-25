"""
Core module for ROP Gadget Parser.

Provides core data structures and parsing functionality.
"""

from .categories import GadgetCategory, categorize_gadget, get_category_style
from .gadget import Gadget
from .instructions import classify_bad_instruction, get_flat_bad_instructions
from .parser import ROPGadgetParser
from .pe_info import IATEntry, PEAnalyzer, PEInfo, PESection

__all__ = [
    "Gadget",
    "GadgetCategory",
    "categorize_gadget",
    "get_category_style",
    "classify_bad_instruction",
    "get_flat_bad_instructions",
    "ROPGadgetParser",
    "PEInfo",
    "PESection",
    "IATEntry",
    "PEAnalyzer",
]
