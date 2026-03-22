#!/usr/bin/env python3
"""target_builder — Vulnerable server generator for security training.

Generates compilable C++ Windows servers with configurable vulnerabilities,
mitigations, and protocols for authorized security testing and exploit
development practice.

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import os
import sys

# Add repo root to path for cross-tool imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from target_builder.src.cli import run  # noqa: E402

if __name__ == "__main__":
    sys.exit(run())
