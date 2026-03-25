# Target Builder - AI Development Guide

**Tool:** `target_builder` — Vulnerable server generator for security training
**Purpose:** Generate compilable C++ Windows servers with configurable vulnerabilities, mitigations, and protocols for authorized security testing and exploit development practice.

---

IMPORTANT NOTES on the TOOL:
- As much as possible, should have tests that verify the generated C++ code is well-formed and contains the expected patterns (e.g. correct buffer sizes, presence of vulnerable function calls, correct mitigation flags in build script)
- The code must comply with the defined styling and formatting guidelines (e.g. 4-space indentation, max line length, consistent naming conventions) and should pass the linter without warnings.

---

## Architecture Overview

### Design Principles
- **Templates are Python functions** returning C++ code strings — no Jinja2 or external template engines
- **Core logic in `src/`** — no terminal dependencies, returns data structures
- **CLI in `src/cli.py`** — argparse, validation, orchestration
- **Uses `lib/color_printer`** for all colored terminal output
- **No new dependencies** — pure Python stdlib only

### Module Responsibilities

```
src/
├── config.py              # Enums and dataclasses only, no logic
├── bad_chars.py           # Generates C++ filter_bad_chars() function body
├── renderer.py            # Orchestrates template assembly into complete C++ source
├── exploit_skeleton.py    # Generates starter Python exploit scripts
├── build_script.py        # Generates build.bat with correct cl.exe flags
└── templates/
    ├── base.py            # Winsock2 skeleton: includes, main(), accept loop, threading
    ├── protocols/
    │   ├── tcp.py         # Text command parsing: "COMMAND <data>\n"
    │   ├── http.py        # HTTP/1.1 request parsing (method, path, headers, body)
    │   └── rpc.py         # Binary protocol: 4-byte len + 2-byte opcode + payload
    ├── buffer_overflow.py # strcpy into undersized stack buffer
    ├── seh_overflow.py    # __try/__except with overwritable SEH chain (x86 only)
    ├── egghunter.py       # Small stack buffer + heap stash for remainder (x86 only)
    ├── format_string.py   # printf(user_data) — no format specifier
    ├── decoys.py          # Safe-looking commands (strncpy, bounded memcpy, etc.)
    └── rop_dll.py         # DLL or embedded __asm gadget blocks
```

### Data Flow
1. CLI parses args → builds `ServerConfig` dataclass
2. `renderer.render(config)` → calls template functions → returns complete C++ string
3. Optional: `exploit_skeleton.generate(config)` → returns Python exploit string
4. Optional: `build_script.generate(config)` → returns build.bat string
5. CLI writes output files

---

## Vulnerability Types

| Type        | Arch       | Mechanism                                    | Exploitation                          |
|-------------|------------|----------------------------------------------|---------------------------------------|
| `bof`       | x86, x64   | `strcpy` into stack `char buf[N]`            | Direct EIP/RIP overwrite              |
| `seh`       | x86 only   | Overflow inside `__try/__except`             | SEH chain overwrite                   |
| `egghunter` | x86 only   | Tiny stack buf + heap stash for remainder    | Short jump → egghunter → egg in heap  |
| `fmtstr`    | x86, x64   | `printf(user_data)` without format string    | Stack read (%x), arbitrary write (%n) |

### Architecture Constraints
- `--vuln seh` + `--arch x64` → **error** (no classic SEH on x64)
- `--vuln egghunter` + `--arch x64` → **error** (x86 egghunter techniques)
- `--safeSEH` requires `--vuln seh`

---

## Protocols

Each protocol template provides:
- `generate_connection_handler(config)` → C++ connection handler function
- `generate_command_dispatcher(config)` → C++ command routing logic
- `generate_banner_send(config)` → C++ code to send banner on connect

| Protocol | Recv Pattern            | Command Routing            | Info Leak Endpoint     |
|----------|-------------------------|----------------------------|------------------------|
| `tcp`    | `recv` + string parse   | `strncmp(buf, "CMD", N)`   | `DEBUG` command        |
| `http`   | `recv` + HTTP parse     | Method + path matching     | `GET /info`            |
| `rpc`    | `recv` + length/opcode  | Opcode switch              | Opcode 255             |

---

## Mitigations → Compile Flags

| Flag             | Enabled                    | Disabled (default)         |
|------------------|----------------------------|----------------------------|
| DEP              | `/NXCOMPAT`                | `/NXCOMPAT:NO`             |
| ASLR             | `/DYNAMICBASE`             | `/DYNAMICBASE:NO`          |
| Stack canary     | `/GS`                      | `/GS-`                     |
| SafeSEH          | `/SAFESEH`                 | `/SAFESEH:NO`              |

### DEP Bypass API Usage
When `--dep` is set, the server uses the selected API for a legitimate purpose so it appears in the IAT:
- `VirtualProtect` → re-protecting a config buffer
- `VirtualAlloc` → allocating a working buffer
- `WriteProcessMemory` → patching a function pointer table
- `HeapCreate` + `HeapAlloc` → custom heap for connection data
- `SetProcessDEPPolicy` → (called but commented as "legacy compat check")
- `NtAllocateVirtualMemory` → low-level allocation wrapper

### ASLR Info Leak
When `--aslr` is set, a safe command/endpoint inadvertently leaks an address:
- TCP: `DEBUG` command prints internal state including a stack/heap pointer
- HTTP: `GET /info` returns JSON with a "debug_handle" field containing an address
- RPC: Opcode 255 response includes a pointer in the binary response struct

---

## Decoy Commands

Decoy command types and their "near-miss" patterns:
- **Near-miss buffer**: `strncpy(buf, input, sizeof(buf))` — correct bounds
- **Safe format**: `printf("%s", input)` — proper format specifier
- **Bounded copy**: `memcpy(buf, input, min(len, sizeof(buf)))` — safe length
- **Heap buffer**: `strcpy(malloc_buf, input)` — heap overflow, not stack

Each decoy gets a randomizable command name that sounds plausible (e.g. `PROCESS`, `QUERY`, `UPDATE`, `VALIDATE`).

---

## ROP Companion DLL

### Gadget Categories by Density

**minimal**: The bare essentials (hardest — no ESP capture gadgets)
- `pop eax; ret` / `pop ecx; ret` / `pop edx; ret`
- `jmp esp`
- `push esp; ret`
- No ESP realignment gadgets — students must find creative paths

**standard**: Working exploit set (medium — dirty ESP gadgets)
- All of minimal, plus:
- `pop pop ret` (for SEH)
- `xchg eax, esp; ret` (stack pivot)
- `mov [eax], ecx; ret` (write-what-where)
- `add esp, N; ret` (stack adjustment)
- `inc/dec` register gadgets
- **Randomized dirty ESP capture routes** (seed-based selection from pool):
  - Each route provides a multi-step path to capture ESP (e.g. ESP→EBP→EAX)
  - Gadgets have side effects (clobber registers, extra pops) requiring creative chaining
  - 1-2 routes selected per generation, guaranteeing at least one solvable DEP bypass path
  - Dirty adjust gadgets with side effects (`add eax, 0x20; pop ecx; ret`)

**full**: Rich surface (easiest — clean ESP gadgets)
- All of standard, plus:
- **Clean ESP capture/adjust**: `push esp; pop eax; ret`, `mov eax, esp; ret`,
  `add eax, N; ret`, `sub eax, N; ret` — straightforward DEP bypass
- Multiple stack pivot variants
- Gadgets ending in `ret N`, `call reg`, `jmp reg`
- Memory read gadgets (`mov eax, [ecx]; ret`)
- Arithmetic chains

---

## Randomization

### What Gets Randomized (`--random`)
- Vulnerability type (constrained by `--arch`)
- Architecture (x86 / x64)
- Protocol (tcp / http / rpc)
- Buffer size (per vuln type range)
- Bad characters (count + selection)
- Bad char action (drop / replace / terminate)
- Mitigations (which are enabled)
- DEP bypass API
- Vulnerable command name
- Server banner (from pool)
- Decoy count and types
- **ESP realignment gadget routes** (standard density ROP DLL / embedded gadgets)

### Seed Behavior
- `--random-seed SEED` makes everything deterministic
- Same seed → identical C++ output, identical exploit skeleton, identical gadget selection
- Seed is propagated to `RopDllConfig.seed` and `EmbeddedGadgetsConfig.seed`
- Seed is printed to stderr so it can be recorded/shared

---

## Testing Strategy

### Unit Tests
- `test_config.py` — enum values, dataclass defaults, validation
- `test_bad_chars.py` — C++ code generation for each filter mode
- `test_renderer.py` — template assembly, correct includes, well-formed C++
- `test_templates.py` — each vuln/protocol template produces valid C++ fragments
- `test_exploit_skeleton.py` — Python script generation per protocol/level

### Integration Tests
- `test_integration.py` — full CLI invocations, output file generation
- Verify arch/vuln compatibility checks reject invalid combos
- Verify `--random-seed` produces deterministic output
- Verify `--build-script` flags match selected mitigations

### What We DON'T Test
- Actual compilation (requires MSVC / Windows)
- Actual exploitation (out of scope)
- Runtime behavior of generated servers

---

## Key Design Decisions

1. **No Jinja2** — templates are Python functions returning strings. Avoids external dependency, keeps tool self-contained, and allows type-safe parameter passing.

2. **C++ not C** — MSVC `__try/__except` is C++ only. The `__asm` blocks for the ROP DLL also need MSVC C++ compilation.

3. **Single payload for egghunter** — the server splits the received data into stack copy + heap stash. More realistic than a separate deposit command — the attacker sends one payload that achieves both goals.

4. **Legitimate API usage for DEP bypass** — the selected Win32 API isn't just imported, it's called for a real purpose. This means `dumpbin /imports` shows it naturally, mimicking real-world binaries.

5. **Exploit skeleton is optional** — the tool's primary output is C++. The Python exploit is a convenience, not the core product.

---

## Changelog

### March 2026
- Initial design and planning (TODO_VULNSERVER.md)
- Created directory structure and CLAUDE.md
- **Full implementation** (18 source files):
  - `config.py` — 8 enums (VulnType, Architecture, Protocol, BadCharAction, Difficulty, DepBypassApi, ExploitLevel, GadgetDensity, DecoyType), 3 dataclasses (ServerConfig, RopDllConfig, ExploitConfig), validation, arch/vuln compat constants, banner/decoy/difficulty pools
  - `bad_chars.py` — C++ filter generation for 3 modes (drop, replace, terminate)
  - `templates/base.py` — Winsock2 skeleton, compile instructions, DEP API usage for all 6 APIs, main() with accept loop + threading
  - `templates/protocols/{tcp,http,rpc}.py` — Protocol-specific connection handlers, command dispatchers, safe commands, ASLR info leak endpoints
  - `templates/{buffer_overflow,seh_overflow,egghunter,format_string}.py` — Vulnerability templates with bad char filter integration
  - `templates/decoys.py` — 4 decoy types with per-protocol dispatcher branches
  - `templates/rop_dll.py` — Companion DLL with 3 gadget density levels (minimal/standard/full), DllMain, exported init
  - `renderer.py` — Orchestrates all templates into complete C++ source
  - `exploit_skeleton.py` — Python exploit at 3 levels x 3 protocols with ASLR leak parsing
  - `build_script.py` — build.bat with correct cl.exe flags per mitigation/arch
  - `cli.py` — Full argparse, randomization with seed/difficulty, challenge summary output
  - `target_builder_cli.py` — Entry point
- **114 tests** across 6 test files (test_config, test_bad_chars, test_templates, test_renderer, test_exploit_skeleton, test_integration)

### March 24, 2026 — Bug Fixes and Embedded Gadgets
- **fix: exploit skeleton byte encoding** — TCP and HTTP exploit skeletons were
  mangling bytes >= 0x80 through a `str.encode()`/`decode(errors='replace')` round-trip.
  Fixed `send_cmd()` to accept raw bytes and `send_request()` to send binary bodies
  separately from headers. RPC exploit was already correct.
- **fix: cli.py syntax error** — `--bad-chars` help string had unterminated string
  literal (broke all integration test imports)
- **feat: `--embedded-gadgets`** — Embed ROP gadgets directly in the server binary
  (x86 only, MSVC `__asm` blocks). Alternative to `--rop-dll` for standalone binaries.
  Supports `--embedded-gadgets-density` (minimal/standard/full). Mutually exclusive
  with `--rop-dll`. Volatile pointer array prevents MSVC from stripping unreferenced
  gadget functions.
- **New config**: `EmbeddedGadgetsConfig` dataclass, validation for x86-only and
  mutual exclusion with ROP DLL
