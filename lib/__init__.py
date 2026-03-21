"""
Shared library for pentest-scripts tools.

This package contains reusable utilities that can be used across multiple tools
in the pentest-scripts repository.

Modules:
    color_printer: Terminal color output abstraction using Rich library
"""

__version__ = "1.0.0"

from .color_printer import ColorPrinter, printer

__all__ = ['ColorPrinter', 'printer']
