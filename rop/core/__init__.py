"""
Core module for ROP Gadget Parser.

Provides core data structures and parsing functionality.
"""

from .gadget import Gadget
from .categories import GadgetCategory, categorize_gadget, get_category_style
from .parser import ROPGadgetParser
from .pe_info import PEInfo, PESection, IATEntry, PEAnalyzer

__all__ = [
    'Gadget',
    'GadgetCategory',
    'categorize_gadget',
    'get_category_style',
    'ROPGadgetParser',
    'PEInfo',
    'PESection',
    'IATEntry',
    'PEAnalyzer'
]