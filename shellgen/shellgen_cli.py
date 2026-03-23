#!/usr/bin/env python3
"""
Shellcode Generator CLI Entry Point
Multi-architecture shellgen generation with bad character avoidance

This is the main entry point for the modular shellgen generator.
"""

import sys
from pathlib import Path

# Add repo root to Python path to access shared lib/
# Use .resolve() to handle symlinks correctly — must be before src imports
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.cli import run_cli  # noqa: E402

if __name__ == "__main__":
    try:
        run_cli()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
