#!/usr/bin/env bash
# Wrapper script that automatically uses venv without activation
# Resolve symlinks to get the actual script location
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

"$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/hash_generator.py" "$@"
