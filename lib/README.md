# Shared Library for Pentest Scripts

This directory contains reusable utilities shared across multiple tools in the
pentest-scripts repository.

## Overview

The `lib/` directory provides common functionality that multiple tools can
leverage, promoting code reuse, consistency, and maintainability across the
entire toolkit.

## Modules

### color_printer.py

**Description**: Terminal color output abstraction using the Rich library.

**Purpose**: Provides a library-independent interface for colored terminal
output, making it easy to swap color libraries in the future without changing
tool code.

**Key Features**:

- Rich library integration with fallback to plain text
- Simple API for colored text output
- Regex pattern highlighting
- Section headers and labeled output
- Enable/disable color mode

**Usage Example**:

```python
from lib.color_printer import printer

# Print colored text
printer.print_text("Hello, world!", style="bold green")

# Print section header
printer.print_header("=== Results ===", style="bold cyan")

# Print labeled output
printer.print_labeled("Total", "100", label_style="yellow", value_style="white")

# Highlight regex matches
highlighted = printer.stylize_regex("pop eax ; ret", r"pop",
                                    match_style="bold red")

# Disable colors for plain output
printer.disable()
```

**Class: ColorPrinter**

Methods:

- `print_text(text, style=None, end="\n")` - Print styled text
- `print_header(text, style="bold green")` - Print section header
- `print_labeled(label, value, label_style="cyan", value_style="yellow")` -
  Print label:value pairs
- `style_text(text, style)` - Return styled Text object
- `stylize_regex(text, pattern, match_style="bold red")` - Highlight regex
  matches
- `disable()` - Disable colored output
- `print(*args, **kwargs)` - Wrapper for console.print
- `print_section(text, style=None)` - Print section divider

**Global Instance**:

```python
from lib.color_printer import printer  # Pre-initialized instance
```

**Supported Styles** (Rich library):

- Colors: `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`
- Modifiers: `bold`, `dim`, `italic`, `underline`
- Hex colors: `#ff8800`, `#00ff00`, etc.
- Combined: `bold red`, `dim yellow`, `bold cyan`

## Design Philosophy

1. **Library Independence**: Abstract external dependencies (Rich, colorama,
   etc.) to allow easy swapping
2. **Fallback Support**: Gracefully degrade when libraries aren't available
3. **Simple API**: Provide intuitive, easy-to-use interfaces
4. **Consistency**: Ensure all tools use the same color schemes and output
   formats
5. **Testability**: Design for easy unit testing without terminal dependencies

## Adding the Library to New Tools

### Step 1: Add sys.path Setup

Add this to the top of your tool (after imports):

```python
import sys
from pathlib import Path

# Add repo root to Python path to access shared lib/
REPO_ROOT = Path(__file__).parent.parent  # Adjust based on tool location
sys.path.insert(0, str(REPO_ROOT))
```

### Step 2: Import and Use

```python
from lib.color_printer import printer

# Use in your tool
printer.print_text("Tool started", style="green")
```

### Step 3: Test

Ensure your tool works from:

- The tool's directory
- A symlink in another location
- Any arbitrary directory

## Dependencies

- **Rich** (optional, recommended): Terminal color and formatting
  ```bash
  pip install rich
  ```

If Rich is not installed, the library falls back to plain text output.

## Future Additions

Planned additions to the shared library:

- **Logging utilities**: Structured logging with color support
- **Argument parsing**: Common argparse patterns and helpers
- **File utilities**: Encoding detection, file parsing helpers
- **Data structures**: Shared data models for common concepts
- **Network utilities**: Common network operations for pentest tools

## Compatibility

- **Python Version**: 3.6+
- **Operating Systems**: Linux, macOS, Windows
- **Terminals**: Any terminal supporting ANSI colors

## Development Guidelines

When adding new modules to `lib/`:

1. **Abstract external dependencies**: Use wrapper classes/functions
2. **Provide fallbacks**: Handle missing dependencies gracefully
3. **Document thoroughly**: Add comprehensive docstrings and examples
4. **Write tests**: Create unit tests in `lib/tests/`
5. **Update this README**: Document new modules and their usage
6. **Version carefully**: Use semantic versioning for breaking changes

## Testing

To test shared library components:

```bash
# From repo root
python3 -m pytest lib/tests/

# Test with a specific tool
cd rop
./get_rop_gadgets.py -f test_gadgets.txt
```

## Migration Checklist

When migrating a tool to use the shared library:

- [ ] Add sys.path setup to tool's main file
- [ ] Update imports to use `lib.module_name`
- [ ] Remove duplicated code from tool
- [ ] Test all tool functionality
- [ ] Update tool's documentation
- [ ] Commit changes with clear message

## License

Part of the pentest-scripts collection. Intended for authorized security testing
and research only.

## Contributing

When contributing to the shared library:

1. Ensure backward compatibility when possible
2. Update all affected tools when making breaking changes
3. Add comprehensive tests
4. Update documentation
5. Follow existing code style and conventions

---

**Version**: 1.0.0
**Last Updated**: March 12, 2026
