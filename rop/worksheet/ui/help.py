"""
Help text and panels for the worksheet interface.
"""

from rich.panel import Panel

# Full help text
HELP = """[bold cyan]COMMANDS[/bold cyan]

[yellow]ASM Operations (Intel syntax):[/yellow]
  mov <dst> <src>          Move value (e.g., mov EAX, 0xdeadbeef)
  add <dst> <src>          Add (dst = dst + src)
  xor <dst> <src>          XOR (dst = dst ^ src)
  xchg <dst> <src>         Exchange/swap values (dst ↔ src)
  inc <dst>                Increment (dst++)
  dec <dst>                Decrement (dst--)
  neg <dst>                Negate (two's complement)
  push <src>               Push to stack (ESP -= 4, [ESP] = src)
  pop <dst>                Pop from stack (dst = [ESP], ESP += 4)
  next                     Pop EIP — step to next gadget (alias: n, Ctrl+N)

[yellow]Quick Operations:[/yellow]
  set <target> <value>     Set value directly (alias: s)
  clr <target>             Clear register/stack/named value (alias: clear)
  name <name> <value>      Create named value (e.g., name shellgen 0x501000)
  stack <offset> <value>   Set stack value at offset (e.g., stack +0x10 0xdeadbeef)

[yellow]Gadget Library:[/yellow]
  gadget <addr> "<inst>"   Add gadget to library (e.g., gadget 0x1001 "pop eax ; ret")
  gadget del <addr>        Delete gadget from library
  gadget clear             Clear entire gadget library

[yellow]ROP Chain Building:[/yellow]
  chain add <value>        Add to chain (address, gadget ID, or literal value)
                           - Address: chain add 0x10001234
                           - Gadget ID: chain add G1 (references gadget from library)
                           - Literal: chain add AAAA (placeholder value)
  chain del <index>        Delete chain entry by index (1-based)
  chain clear              Clear entire ROP chain
  del <index>              Delete chain entry (backward compatibility)

[yellow]Import from WinDbg:[/yellow]
  importregs               Paste WinDbg register output to import register values
  importstack              Paste WinDbg stack dump to import stack values

[yellow]Display & File:[/yellow]
  v                        View worksheet (aliases: view, show, r, refresh)
  save [file]              Save worksheet (default: rop.json)
  load [file]              Load worksheet
  new                      New blank worksheet
  notes                    Edit notes
  auto                     Toggle auto-gadget processing on/off
  logmanual                Toggle manual operation logging on/off
  help                     Show this help (aliases: h, ?)
  quit                     Exit (aliases: q, exit)

[yellow]Execution Log:[/yellow]
  The EXECUTION LOG displays the last 10 operations (both manual and auto).
  - Manual operations: User-typed commands (mov, add, etc.) when log-manual is ON
  - Auto operations: Auto-executed gadget instructions when auto-gadget is ON
  Use 'logmanual' to toggle manual operation logging. Status shown in header.

[yellow]Navigation:[/yellow]
  ↑ / ↓                    Browse command history
  TAB                      Autocomplete

[bold cyan]EXAMPLES - Basic Operations[/bold cyan]

  mov EAX, 0xdeadbeef      Set EAX to value
  mov EAX, ESP+0x10        Move stack value to EAX
  add EAX, 0x100           EAX = EAX + 0x100
  xor EAX, EAX             Zero out EAX
  inc EAX                  EAX++
  push EAX                 Push EAX onto stack
  pop EBX                  Pop from stack into EBX

  name shellgen 0x501000  Create named value
  mov EAX, shellgen       Use named value
  add EAX, 0x100           Add to named value

[bold cyan]EXAMPLES - ROP Chain Workflow[/bold cyan]

  # 1. Build gadget library
  gadget 0x10001234 "pop eax ; ret"
  gadget 0x10005678 "pop ebx ; ret"
  gadget 0x1000abcd "add eax, ebx ; ret"

  # 2. Build ROP chain using gadget IDs
  chain add G1             Add first gadget (pop eax ; ret)
  chain add 0xdeadbeef     Add literal value (will be popped into EAX)
  chain add G2             Add second gadget (pop ebx ; ret)
  chain add 0x12345678     Add literal value (will be popped into EBX)
  chain add G3             Add third gadget (add eax, ebx ; ret)

  # 3. Mix addresses and placeholders
  chain add 0x10001234     Add by direct address
  chain add AAAA           Add placeholder value
  chain add G1             Add by gadget ID
"""


def build_help_panel() -> Panel:
    """
    Build the compact help panel for bottom of screen.

    Returns:
        Rich Panel with quick command reference
    """
    help_text = """[yellow]ASM:[/yellow] mov add xor xchg inc dec neg push pop  [yellow]|[/yellow]  [yellow]Quick:[/yellow] set clr name stack  [yellow]|[/yellow]  [yellow]Step:[/yellow] next (Ctrl+N)  [yellow]|[/yellow]  [yellow]Import:[/yellow] importregs importstack  [yellow]|[/yellow]  [yellow]ROP:[/yellow] gadget chain  [yellow]|[/yellow]  help quit  [dim](TAB=complete ↑↓=history)[/dim]"""
    return Panel(
        help_text, title="QUICK COMMANDS", border_style="dim blue", padding=(0, 1)
    )
