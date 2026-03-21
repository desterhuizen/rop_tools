"""
Display module for ROP Gadget Parser.

Provides colored terminal output and formatting utilities.
"""

from lib.color_printer import ColorPrinter, printer

from .formatters import print_gadget_colored, print_gadgets, print_statistics

__all__ = [
    "printer",
    "ColorPrinter",
    "print_gadget_colored",
    "print_gadgets",
    "print_statistics",
]
