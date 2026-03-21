#!/usr/bin/env bash
# Wrapper script for hash generator
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/hash_generator.py" "$@"
