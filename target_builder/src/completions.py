"""Shell completion script generator for target_builder.

Thin wrapper around lib.completions with target_builder-specific tool names.
"""

import argparse

from lib.completions import generate_completion as _generate

_TOOL_NAMES = ["target_builder", "target_builder_cli.py"]


def generate_completion(shell: str, parser: argparse.ArgumentParser) -> str:
    """Generate a completion script for the given shell.

    Args:
        shell: "bash" or "zsh".
        parser: Configured ArgumentParser to introspect.

    Returns:
        Complete shell completion script as a string.

    Raises:
        ValueError: If shell type is not supported.
    """
    return _generate(shell, parser, _TOOL_NAMES)
