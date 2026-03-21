"""
ColorPrinter abstraction for colored terminal output.

Provides a simple abstraction layer for color libraries, making it easy
to swap implementations without changing the entire codebase.
"""

import re

# Color support with Rich
try:
    from rich.console import Console
    from rich.text import Text
    COLORS_AVAILABLE = True
except ImportError:
    # Fallback if rich not installed
    COLORS_AVAILABLE = False
    Console = None
    Text = None


class ColorPrinter:
    """
    Abstraction layer for colored terminal output.
    Makes it easy to swap color libraries without changing the entire codebase.
    """

    def __init__(self, enabled=True):
        """Initialize the color printer with Rich or fallback to plain text"""
        self.enabled = enabled and COLORS_AVAILABLE
        self.console = Console() if self.enabled else None

    def print_text(self, text, style=None, end="\n"):
        """Print styled text. Falls back to plain text if colors disabled."""
        if self.enabled and style:
            styled_text = Text(str(text), style=style)
            self.console.print(styled_text, end=end)
        else:
            print(text, end=end)

    def print_header(self, text, style="bold green"):
        """Print a section header with styling"""
        if self.enabled:
            self.console.print(f"\n{text}", style=style)
        else:
            print(f"\n{text}")

    def print_labeled(self, label, value, label_style="cyan", value_style="yellow"):
        """Print a 'Label: Value' pair with different styles"""
        if self.enabled:
            output = Text()
            output.append(label, style=label_style)
            output.append(": ", style="white")
            output.append(str(value), style=value_style)
            self.console.print(output)
        else:
            print(f"{label}: {value}")

    def style_text(self, text, style):
        """Return a styled Text object or plain string if colors disabled"""
        if self.enabled:
            return Text(str(text), style=style)
        return str(text)

    def stylize_regex(self, text, pattern, match_style="bold red"):
        """Highlight regex matches in text"""
        if not self.enabled:
            return text

        try:
            regex = re.compile(pattern, re.IGNORECASE)
            rich_text = Text(text)

            # Find all matches and stylize them
            for match in regex.finditer(text):
                rich_text.stylize(match_style, match.start(), match.end())

            return rich_text
        except re.error:
            # Invalid regex, return text as-is
            return Text(text) if self.enabled else text

    def disable(self):
        """Disable colored output"""
        self.enabled = False

    def print(self, *args, **kwargs):
        """Wrapper for standard print or rich console.print"""
        if self.enabled:
            self.console.print(*args, **kwargs)
        else:
            print(*args, **kwargs)

    def print_section(self, text, style=None):
        """Print a section divider with optional styling"""
        if self.enabled and style:
            styled_text = Text(str(text), style=style)
            self.console.print(styled_text)
        else:
            print(text)

    def colorize(self, text, style):
        """Return text with ANSI color codes (for building strings)"""
        if self.enabled and style:
            styled_text = Text(str(text), style=style)
            # Use console to render to string with ANSI codes
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, force_terminal=True, width=200)
            temp_console.print(styled_text, end='')
            return buffer.getvalue()
        return str(text)

    def print_panel(self, content, title="", style="cyan", border_style="cyan"):
        """
        Print content in a bordered panel box using Rich.

        Args:
            content: Text content to display in the panel
            title: Optional title for the panel
            style: Text style for content (default: cyan)
            border_style: Border color style (default: cyan)
        """
        if self.enabled:
            from rich.panel import Panel
            styled_content = Text(str(content), style=style)
            panel = Panel(styled_content, title=title, border_style=border_style, expand=False)
            self.console.print(panel)
        else:
            # Fallback to simple bordered output
            width = 72
            border = "=" * width
            print(border)
            if title:
                print(f"{title}")
                print("-" * width)
            print(content)
            print(border)

    def print_hex_preview(self, data, max_bytes=16, title="Shellcode Preview"):
        """
        Print a hex preview of binary data with ASCII representation.

        Args:
            data: Bytes to preview
            max_bytes: Maximum number of bytes to display (default: 16)
            title: Title for the preview section

        Format:
            89 e5 81 c4 f0 f9 ff ff  31 c9 64 8b 41 30 8b 40
            ˙åü˙˙˙1Édü A0ü@
        """
        if len(data) == 0:
            return

        preview_bytes = data[:max_bytes]

        # Build hex string (split into two groups of 8 for readability)
        hex_parts = []
        for i in range(0, len(preview_bytes), 8):
            chunk = preview_bytes[i:i+8]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            hex_parts.append(hex_str)
        hex_line = '  '.join(hex_parts)

        # Build ASCII representation
        ascii_chars = []
        for b in preview_bytes:
            if 32 <= b <= 126:  # Printable ASCII range
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append('·')  # Middle dot for non-printable
        ascii_line = ''.join(ascii_chars)

        # Print with color
        if self.enabled:
            self.print_text(f"\n{title}:\n", "bold cyan")
            self.print_text(f"  {hex_line}\n", "yellow")
            self.print_text(f"  {ascii_line}\n", "dim white")
        else:
            print(f"\n{title}:")
            print(f"  {hex_line}")
            print(f"  {ascii_line}")

    def print_table(self, columns, rows, title="", title_style="bold cyan"):
        """
        Print a formatted table using Rich Table.

        Args:
            columns: List of column names
            rows: List of lists containing row data
            title: Optional table title
            title_style: Style for the title

        Example:
            printer.print_table(
                columns=["Payload", "x86", "x64"],
                rows=[
                    ["messagebox", "✓", "✓"],
                    ["winexec", "✓", "✓"]
                ],
                title="Architecture Support"
            )
        """
        if self.enabled:
            from rich.table import Table

            table = Table(title=title, title_style=title_style, show_header=True, header_style="bold yellow")

            # Add columns
            for col in columns:
                table.add_column(col, style="cyan")

            # Add rows
            for row in rows:
                # Convert row items to strings and apply coloring for checkmarks
                styled_row = []
                for item in row:
                    if item == "✓":
                        styled_row.append(f"[green]{item}[/green]")
                    elif item == "✗":
                        styled_row.append(f"[red]{item}[/red]")
                    else:
                        styled_row.append(str(item))
                table.add_row(*styled_row)

            self.console.print(table)
        else:
            # Fallback to simple text table
            if title:
                print(f"\n{title}")
                print("=" * 60)

            # Print header
            header = " | ".join(str(col).ljust(15) for col in columns)
            print(header)
            print("-" * len(header))

            # Print rows
            for row in rows:
                row_str = " | ".join(str(item).ljust(15) for item in row)
                print(row_str)
            print()


# Global ColorPrinter instance for convenient access
printer = ColorPrinter()