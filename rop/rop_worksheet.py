#!/usr/bin/env python3
"""
ROP Chain Worksheet — Interactive Terminal UI
Main entry point for the ROP worksheet tool.

This refactored version uses a modular architecture:
- worksheet.core: Data structures and value resolution
- worksheet.operations: ASM and stack operations
- worksheet.gadgets: Gadget processing and library management
- worksheet.chain: ROP chain building
- worksheet.io: Import/export functionality
- worksheet.repl: Interactive command-line interface
- worksheet.ui: Display and visualization
"""

__version__ = "2.0.0"

from worksheet.repl.main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        raise
