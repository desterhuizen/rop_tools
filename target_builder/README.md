# Target Builder

Generate compilable C++ Windows servers with configurable vulnerabilities for authorized security testing and exploit development practice.

**For authorized security testing only.**

---

## Overview

Target Builder produces complete C++ source code for vulnerable TCP/HTTP/RPC servers that can be compiled with MSVC. It is designed for practicing exploit development techniques in a controlled environment.

The tool generates:
- **Server source** (.cpp) — compilable vulnerable Windows server
- **Build script** (.bat) — cl.exe invocation with correct flags
- **Exploit skeleton** (.py) — starter Python exploit script
- **ROP DLL** (.cpp) — companion DLL with useful ROP gadgets

---

## Quick Start

```bash
# Simple buffer overflow server (TCP)
target_builder --vuln bof --output server.cpp --build-script

# SEH overflow with mitigations (HTTP)
target_builder --vuln seh --dep --aslr --protocol http --output server.cpp

# BOF with ASLR + format string leak for bypass practice
target_builder --vuln bof --dep --aslr --fmtstr-leak --output server.cpp

# Randomized challenge
target_builder --random --random-seed 42 --difficulty hard \
  --output server.cpp --exploit crash --rop-dll

# Format string vulnerability (RPC)
target_builder --vuln fmtstr --protocol rpc --output server.cpp
```

---

## Vulnerability Types

| Type        | Arch     | Mechanism                                | Exploitation                     |
|-------------|----------|------------------------------------------|----------------------------------|
| `bof`       | x86, x64 | `strcpy` into undersized stack buffer   | Direct EIP/RIP overwrite         |
| `seh`       | x86 only | Overflow inside `__try/__except` + AV trigger | SEH chain overwrite (POP POP RET + short jmp) |
| `egghunter` | x86 only | Small stack buf + heap stash            | Egghunter scans for egg in heap  |
| `fmtstr`    | x86, x64 | `printf(user_data)` without format spec | Stack read (%x), write (%n)     |

### Architecture Constraints
- `--vuln seh` + `--arch x64` is rejected (no classic SEH on x64)
- `--vuln egghunter` + `--arch x64` is rejected (x86 egghunter techniques)

---

## Protocols

| Protocol | Format                              | Vuln Trigger          | Info Leak (ASLR) | FmtStr Leak        |
|----------|-------------------------------------|-----------------------|-------------------|---------------------|
| `tcp`    | `COMMAND <data>\n`                  | Vulnerable command    | `DEBUG` command   | `ECHO` command      |
| `http`   | Standard HTTP/1.1 requests          | `POST /vulnerable`    | `GET /info`       | `POST /echo`        |
| `rpc`    | 4-byte len + 2-byte opcode + data  | Vulnerable opcode     | Opcode 255        | Opcode 254          |

---

## Mitigations

| Flag           | Compile Effect     | Exploitation Impact                    |
|----------------|--------------------|-----------------------------------------|
| `--dep`        | `/NXCOMPAT`        | Must build ROP chain to bypass DEP     |
| `--aslr`       | `/DYNAMICBASE`     | Must leak address via info leak        |
| `--fmtstr-leak`| (no compile flag)  | Adds printf leak command for ASLR bypass practice |
| `--stack-canary`| `/GS`             | Must leak or bypass stack cookie       |
| `--safeSEH`    | `/SAFESEH`         | Must use gadget from non-SafeSEH module|

### DEP Bypass APIs

When `--dep` is enabled, the server imports one of these APIs for a legitimate purpose (appears in IAT):

| `--dep-api` value      | API Used                    |
|------------------------|-----------------------------|
| `virtualprotect`       | `VirtualProtect`            |
| `virtualalloc`         | `VirtualAlloc`              |
| `writeprocessmemory`   | `WriteProcessMemory`        |
| `heapcreate`           | `HeapCreate` + `HeapAlloc`  |
| `setprocessdeppolicy`  | `SetProcessDEPPolicy`       |
| `ntallocate`           | `NtAllocateVirtualMemory`   |

### Base Address

The default base address is `0x11110000` — chosen to avoid null bytes in code addresses. Standard Windows EXEs load at `0x00400000`, but that means every code address contains `0x00`, making string-based exploits (strcpy, etc.) impossible.

```bash
# Uses default 0x11110000 (no null bytes in upper address bytes)
target_builder --vuln bof

# Explicit base address
target_builder --vuln bof --base-address 0x22220000

# Auto-select based on bad chars (avoids all specified bad bytes)
target_builder --vuln bof --bad-chars "00,0a,0d,11" --base-address auto
```

When `--random` is used with bad characters, a safe base address is automatically selected.

Only the upper 2 bytes of the base address matter — the lower 2 bytes (`0x0000` from 64KB alignment) are replaced by the RVA offset in actual code addresses.

---

## Bad Characters

```bash
# Explicit bad chars
target_builder --vuln bof --bad-chars "00,0a,0d,25" --bad-char-action drop

# Random bad chars
target_builder --vuln bof --bad-char-count 5 --bad-char-action terminate
```

| Mode        | Behavior                              |
|-------------|---------------------------------------|
| `drop`      | Silently removes bad bytes from input |
| `replace`   | Substitutes bad bytes with `0x41`     |
| `terminate` | Truncates input at first bad byte     |

---

## Decoy Commands

```bash
target_builder --vuln bof --decoy-commands 3
```

Adds non-exploitable commands that look suspicious but are safe:
- **Near-miss buffer** — `strncpy` with correct bounds
- **Safe format** — `printf("%s", input)` with format specifier
- **Bounded copy** — `memcpy` with `min(len, sizeof(buf))`
- **Heap buffer** — `strcpy` into `malloc`'d buffer (heap, not stack)

---

## Exploit Skeleton

```bash
target_builder --vuln bof --exploit crash --exploit-output exploit.py
```

| Level      | What it does                                              |
|------------|-----------------------------------------------------------|
| `connect`  | Connect to server, receive banner                         |
| `interact` | Connect + send all commands with test data                |
| `crash`    | Connect + interact + send overflow payload with TODOs     |

Adapted per protocol (raw socket for TCP, HTTP requests for HTTP, binary packing for RPC).

---

## ROP Companion DLL

```bash
target_builder --vuln bof --dep --rop-dll --rop-dll-gadgets full \
  --rop-dll-base 0x62500000
```

Generates a DLL with inline assembly gadgets the server loads at startup.

| `--rop-dll-gadgets` | Gadgets Included                                        |
|---------------------|---------------------------------------------------------|
| `minimal`           | pop reg; ret, jmp esp, push esp; ret                    |
| `standard`          | + pop pop ret, xchg, mov, add/sub, inc/dec              |
| `full`              | + stack pivots, memory reads, ret N, call/jmp reg       |

Use `--rop-dll-no-aslr` (default) for fixed base address, `--rop-dll-base` to set preferred base.

---

## Randomization

```bash
# Fully random challenge
target_builder --random --output server.cpp

# Reproducible (share the seed)
target_builder --random --random-seed 42 --output server.cpp

# Constrained by difficulty
target_builder --random --difficulty hard --output server.cpp
```

Randomizes: vuln type, arch, protocol, buffer size, bad chars, mitigations, DEP API, banner, decoys, stack layout.

### Constrained Randomization

Pin specific values while randomizing the rest:

```bash
# Random, but always x86 architecture
target_builder --random --arch x86 --output server.cpp

# Random, but only bof or seh vulnerabilities
target_builder --random --vuln bof,seh --output server.cpp

# Random, but never enable DEP or ASLR
target_builder --random --exclude-protection dep,aslr --output server.cpp

# Combine constraints
target_builder --random --vuln bof,seh --arch x86 --protocol tcp,http \
  --exclude-protection canary --output server.cpp
```

Comma-separated values for `--vuln`, `--protocol`, `--bad-char-action`, and
`--padding-style` restrict the randomizer to pick from the given set.

`--exclude-protection` forces named protections OFF. Valid values:
`dep`, `aslr`, `canary`, `safeseh`, `fmtstr-leak`.

### Difficulty Presets

| Difficulty | Buffer  | Bad Chars | Mitigations         | Decoys | Stack Padding | Landing Pad |
|------------|---------|-----------|---------------------|--------|---------------|-------------|
| `easy`     | 1024-2048 | none    | none                | 0      | none          | unlimited   |
| `medium`   | 256-512 | 3-6       | DEP                 | 1-2    | 32-128 bytes  | 64-256 bytes |
| `hard`     | 64-128  | 8-12      | DEP + ASLR + canary | 3-5    | 64-256 bytes  | 8-32 bytes  |

---

## Stack Layout

Control the stack layout complexity to create more realistic exploit challenges:

```bash
# Add 64 bytes of padding between buffer and saved EBP (increases EIP offset)
target_builder --vuln bof --pre-padding 64 --padding-style mixed --output server.cpp

# Tight landing pad — only 16 bytes after EIP (forces short jump)
target_builder --vuln bof --landing-pad 16 --output server.cpp

# Both: offset padding + tight landing pad
target_builder --vuln bof --pre-padding 96 --landing-pad 24 \
  --padding-style struct --output server.cpp
```

### Pre-buffer Padding
Local variables placed between the vulnerable buffer and the saved EBP/EIP on the stack. Increases the offset the attacker must calculate.

| Style    | Description                                     |
|----------|-------------------------------------------------|
| `none`   | No padding (default)                            |
| `array`  | Single `char` array                             |
| `mixed`  | Mix of ints, chars, doubles — realistic locals  |
| `struct` | A struct with named fields                      |
| `multi`  | Multiple smaller arrays                         |

### Landing Pad
Limits how many bytes of controlled data can follow the EIP overwrite. When small (8-32 bytes), the attacker must use a short jump backward to reach shellcode placed before EIP — a common OSED/OSCP technique.

---

## Full CLI Reference

```
target_builder --vuln <type> [options]

Required:
  --vuln {bof,seh,egghunter,fmtstr}

Server:
  --port PORT              Listen port (default: 9999)
  --arch {x86,x64}         Target architecture (default: x86)
  --buffer-size SIZE       Vulnerable buffer size (default: 2048)
  --protocol {tcp,http,rpc} Network protocol (default: tcp)
  --command COMMAND        Command that triggers vuln
  --additional-commands    Comma-separated safe commands
  --decoy-commands N       Number of decoy commands
  --banner TEXT            Custom server banner
  --base-address ADDR      EXE base address: hex or "auto" (default: 0x11110000)

Bad Characters:
  --bad-chars HEXBYTES     e.g. "00,0a,0d,25"
  --bad-char-count N       Generate N random bad chars
  --bad-char-action {drop,replace,terminate}

Stack Layout:
  --pre-padding SIZE       Bytes of padding before buffer (default: 0)
  --landing-pad SIZE       Max bytes after EIP overwrite; 0=unlimited
  --padding-style STYLE    {none,array,mixed,struct,multi} (default: none)

Mitigations:
  --dep                    Enable DEP
  --dep-api API            DEP bypass API selection
  --aslr                   Enable ASLR (adds info leak)
  --fmtstr-leak            Add format string leak command for ASLR bypass
  --stack-canary           Enable /GS stack cookies
  --safeSEH                Enable SafeSEH (seh vuln only)

Randomization:
  --random                 Randomize all aspects
  --random-seed SEED       Reproducible random seed
  --difficulty {easy,medium,hard}
  --exclude-protection     Comma-separated protections to force OFF
                           (dep, aslr, canary, safeseh, fmtstr-leak)

Output:
  --output FILE            Output .cpp file (default: stdout)
  --build-script           Generate build.bat
  --exploit {connect,interact,crash}
  --exploit-output FILE    Exploit script output
  --rop-dll                Generate companion ROP DLL
  --rop-dll-output FILE    DLL source output
  --rop-dll-gadgets {minimal,standard,full}
  --rop-dll-base ADDRESS   DLL preferred base address
  --no-color               Disable colored output
  --cheat-sheet            Print exploit hints
```

---

## Compiling Generated Servers

Generated servers include compile instructions in the header comment. You need:
- **Visual Studio** with C++ Desktop Development workload (or Build Tools alone)
- **Visual Studio Native Tools Command Prompt** (x86 or x64 matching `--arch`)

### Visual Studio Build Tools Setup

Build Tools is the lightest option (no IDE needed):

1. Run Visual Studio Installer (search Start Menu)
2. Click Modify on "Build Tools 2026"
3. Check "Desktop development with C++"
4. Under "Individual components" make sure these are checked:
   - MSVC v144 — VS 2026 C++ x64/x86 build tools
   - Windows SDK (latest version)
5. Click Install/Modify

### Compiling

```bat
REM From the Visual Studio x86 Native Tools Command Prompt:
cl.exe /GS- /EHsc server.cpp /link ws2_32.lib /DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO

REM Or use the generated build script:
build.bat
```

---

## Testing

```bash
# Run target_builder tests
make test-target-builder

# Or directly
python3 -m unittest discover -s target_builder/tests -p "test_*.py" -t . -v
```

114 tests covering config validation, bad char generation, all vulnerability and protocol templates, the renderer pipeline, exploit skeleton output, and full CLI integration.

---

**For authorized security testing and defensive research only.**
