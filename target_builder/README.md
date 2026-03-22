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
| `seh`       | x86 only | Overflow inside `__try/__except`        | SEH chain overwrite              |
| `egghunter` | x86 only | Small stack buf + heap stash            | Egghunter scans for egg in heap  |
| `fmtstr`    | x86, x64 | `printf(user_data)` without format spec | Stack read (%x), write (%n)     |

### Architecture Constraints
- `--vuln seh` + `--arch x64` is rejected (no classic SEH on x64)
- `--vuln egghunter` + `--arch x64` is rejected (x86 egghunter techniques)

---

## Protocols

| Protocol | Format                              | Vuln Trigger          | Info Leak (ASLR) |
|----------|-------------------------------------|-----------------------|-------------------|
| `tcp`    | `COMMAND <data>\n`                  | Vulnerable command    | `DEBUG` command   |
| `http`   | Standard HTTP/1.1 requests          | `POST /vulnerable`    | `GET /info`       |
| `rpc`    | 4-byte len + 2-byte opcode + data  | Vulnerable opcode     | Opcode 255        |

---

## Mitigations

| Flag           | Compile Effect     | Exploitation Impact                    |
|----------------|--------------------|-----------------------------------------|
| `--dep`        | `/NXCOMPAT`        | Must build ROP chain to bypass DEP     |
| `--aslr`       | `/DYNAMICBASE`     | Must leak address via info leak        |
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

Randomizes: vuln type, arch, protocol, buffer size, bad chars, mitigations, DEP API, banner, decoys.

| Difficulty | Buffer  | Bad Chars | Mitigations             | Decoys |
|------------|---------|-----------|-------------------------|--------|
| `easy`     | 1024-2048 | none    | none                    | 0      |
| `medium`   | 256-512 | 3-6       | DEP                     | 1-2    |
| `hard`     | 64-128  | 8-12      | DEP + ASLR + canary     | 3-5    |

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

Bad Characters:
  --bad-chars HEXBYTES     e.g. "00,0a,0d,25"
  --bad-char-count N       Generate N random bad chars
  --bad-char-action {drop,replace,terminate}

Mitigations:
  --dep                    Enable DEP
  --dep-api API            DEP bypass API selection
  --aslr                   Enable ASLR (adds info leak)
  --stack-canary           Enable /GS stack cookies
  --safeSEH                Enable SafeSEH (seh vuln only)

Randomization:
  --random                 Randomize all aspects
  --random-seed SEED       Reproducible random seed
  --difficulty {easy,medium,hard}

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
- **Visual Studio** with C++ Desktop Development workload
- **Visual Studio Native Tools Command Prompt** (x86 or x64 matching `--arch`)

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