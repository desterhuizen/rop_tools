"""ROP companion DLL template.

Generates a C++ DLL source with inline assembly (__asm) blocks containing
useful ROP gadgets at three density levels (minimal, standard, full).
x86 only — __asm blocks are MSVC x86 specific.

Gadget density philosophy:
  - minimal: Bare essentials + one indirect ESP capture path (hard)
  - standard: Working set + randomly selected dirty ESP gadgets (medium)
  - full: Everything including clean ESP capture/adjust (easy)

Each level guarantees at least one solvable DEP bypass path, but lower
densities require creative chaining through "dirty" gadgets with side effects.
"""

import random as _random_mod
from typing import Optional

from target_builder.src.config import DepBypassApi, GadgetDensity, RopDllConfig

# ── Dirty ESP gadget pools ───────────────────────────────────────────
#
# Each "route" is a coherent pair: a CAPTURE gadget that gets ESP into
# some register, and a RECOVERY gadget that moves it into EAX (so the
# existing `xchg eax, esp; ret` can pivot).  Routes are designed to
# require 2-3 gadgets where the clean version needs 1.

_ESP_CAPTURE_ROUTES = [
    # Route A: ESP → EBP → EAX  (clobbers EBX on recovery)
    {
        "name": "RouteEBP",
        "capture": """\
        // mov ebp, esp; pop ebx; ret  — ESP into EBP (clobbers EBX)
        mov ebp, esp
        pop ebx
        ret""",
        "recovery": """\
        // mov eax, ebp; pop ebx; ret  — recover EBP into EAX (clobbers EBX)
        mov eax, ebp
        pop ebx
        ret""",
    },
    # Route B: ESP → ESI → EAX  (clobbers ECX on capture)
    {
        "name": "RouteESI",
        "capture": """\
        // push esp; pop esi; inc ecx; ret  — ESP into ESI (clobbers ECX)
        push esp
        pop esi
        inc ecx
        ret""",
        "recovery": """\
        // push esi; pop eax; ret  — recover ESI into EAX
        push esi
        pop eax
        ret""",
    },
    # Route C: ESP → EAX directly but with side effects
    {
        "name": "RouteDirectDirty",
        "capture": """\
        // mov eax, esp; pop ebp; ret  — ESP into EAX but pops garbage into EBP
        mov eax, esp
        pop ebp
        ret""",
        "recovery": None,  # No recovery needed — already in EAX
    },
    # Route D: ESP → EDI → EAX  (clobbers ESI on recovery)
    {
        "name": "RouteEDI",
        "capture": """\
        // push esp; pop edi; pop esi; ret  — ESP into EDI (clobbers ESI, pops)
        push esp
        pop edi
        pop esi
        ret""",
        "recovery": """\
        // xchg eax, edi; ret  — swap EDI into EAX
        xchg eax, edi
        ret""",
    },
    # Route E: ESP → EBX → EAX  (clobbers EDX on capture)
    {
        "name": "RouteEBX",
        "capture": """\
        // mov ebx, esp; xor edx, edx; ret  — ESP into EBX (zeros EDX)
        mov ebx, esp
        xor edx, edx
        ret""",
        "recovery": """\
        // push ebx; pop eax; pop ecx; ret  — recover EBX into EAX (pops ECX)
        push ebx
        pop eax
        pop ecx
        ret""",
    },
]

# Dirty adjust gadgets — each adjusts EAX with side effects
_DIRTY_ADJUST_GADGETS = [
    """\
        // add eax, 0x20; pop ecx; ret  — adjust +0x20 (clobbers ECX)
        add eax, 0x20
        pop ecx
        ret""",
    """\
        // add eax, 0x10; pop ebx; ret  — adjust +0x10 (clobbers EBX)
        add eax, 0x10
        pop ebx
        ret""",
    """\
        // sub eax, 0x10; inc ecx; ret  — adjust -0x10 (clobbers ECX)
        sub eax, 0x10
        inc ecx
        ret""",
    """\
        // add eax, 0x3c; pop edx; ret  — adjust +0x3c past pushad (clobbers EDX)
        add eax, 0x3c
        pop edx
        ret""",
]


def generate_embedded_gadgets(
    density: GadgetDensity, seed: Optional[int] = None
) -> str:
    """Generate ROP gadget functions for embedding directly in the server source.

    Unlike generate_rop_dll(), this produces only the gadget functions without
    DLL boilerplate (no DllMain, no dllexport, no compile header).
    Includes a volatile reference array to prevent the linker from stripping
    unreferenced functions.

    Args:
        density: Gadget density level.
        seed: Optional RNG seed for reproducible gadget selection.

    Returns:
        C++ function blocks as a string.
    """
    gadgets = _generate_gadget_functions(density, seed)

    # Collect function names so we can create a linker anti-strip reference
    func_names = []
    for line in gadgets.split("\n"):
        if "void " in line and "(" in line and "__declspec" in line:
            # Extract function name from: __declspec(noinline) void FuncName() {
            name = line.split("void ")[1].split("(")[0].strip()
            func_names.append(name)

    # Create a volatile pointer array that references each gadget function.
    # This prevents MSVC from stripping the functions as unreferenced.
    ref_lines = [
        "// Prevent linker from stripping unreferenced gadget functions",
        "volatile void* _gadget_refs[] = {",
    ]
    for name in func_names:
        ref_lines.append(f"    (void*)&{name},")
    ref_lines.append("};")

    return (
        "// --- Embedded ROP gadgets ---\n\n" + gadgets + "\n\n" + "\n".join(ref_lines)
    )


def generate_rop_dll(config: RopDllConfig) -> str:
    """Generate complete ROP companion DLL C++ source.

    Args:
        config: ROP DLL configuration.

    Returns:
        Complete C++ source as a string.
    """
    base_hex = f"0x{config.base_address:08X}"

    parts = [
        _generate_header(base_hex),
    ]

    dep_api_code = _generate_dep_api_usage(config.dep_api)
    if dep_api_code:
        parts.append(dep_api_code)

    parts.extend(
        [
            _generate_gadget_functions(config.gadget_density, config.seed),
            _generate_dllmain(),
            _generate_init_export(config.dep_api),
        ]
    )

    return "\n\n".join(parts)


def generate_dll_build_command(config: RopDllConfig) -> str:
    """Generate the cl.exe command to compile the DLL."""
    output = config.output_file
    base_hex = f"0x{config.base_address:08X}"

    flags = ["/LD", "/GS-"]
    link_flags = [
        f"/BASE:{base_hex}",
        "/DYNAMICBASE:NO" if config.no_aslr else "/DYNAMICBASE",
        "/SAFESEH:NO",
        "/NXCOMPAT:NO",
    ]

    return f"cl.exe {' '.join(flags)} {output} /link {' '.join(link_flags)}"


def _generate_dep_api_usage(dep_api: Optional[DepBypassApi]) -> str:
    """Generate a legitimate use of the DEP bypass API so it appears in the DLL IAT.

    Mirrors the server-side pattern: each API is called for a real purpose so
    ``dumpbin /imports`` shows it naturally.  The student can then use the
    DLL's IAT entry (at a known, non-ASLR address) in their ROP chain.

    Args:
        dep_api: Which DEP bypass API to import, or None to skip.

    Returns:
        C++ function code as a string, or empty string if dep_api is None.
    """
    if dep_api is None:
        return ""

    _DEP_API_DLL_CODE = {
        "virtualprotect": """\
// Legitimate use of VirtualProtect — re-protect helper data as read-only
static char g_helper_data[4096];

void rop_init_helper_data() {
    DWORD old_protect;
    memset(g_helper_data, 0, sizeof(g_helper_data));
    strcpy(g_helper_data, "rop_helper_v1");
    VirtualProtect(g_helper_data, sizeof(g_helper_data),
                   PAGE_READONLY, &old_protect);
}""",
        "virtualalloc": """\
// Legitimate use of VirtualAlloc — allocate scratch buffer
static char* g_scratch_buffer = NULL;

void rop_init_scratch() {
    g_scratch_buffer = (char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (g_scratch_buffer) {
        memset(g_scratch_buffer, 0, 4096);
    }
}""",
        "writeprocessmemory": """\
// Legitimate use of WriteProcessMemory — patch callback table
typedef void (*callback_t)(void);
static callback_t g_callbacks[8] = {0};

void rop_patch_callback(int index, callback_t func) {
    if (index >= 0 && index < 8) {
        SIZE_T written;
        WriteProcessMemory(
            GetCurrentProcess(),
            &g_callbacks[index],
            &func,
            sizeof(callback_t),
            &written
        );
    }
}""",
        "heapcreate": """\
// Legitimate use of HeapCreate/HeapAlloc — private heap for helper data
static HANDLE g_helper_heap = NULL;

void rop_init_heap() {
    g_helper_heap = HeapCreate(0, 4096, 1024 * 1024);
}

void* rop_heap_alloc(SIZE_T size) {
    if (g_helper_heap) {
        return HeapAlloc(g_helper_heap, HEAP_ZERO_MEMORY, size);
    }
    return NULL;
}""",
        "setprocessdeppolicy": """\
// Legacy DEP compatibility check via SetProcessDEPPolicy
void rop_check_dep() {
    SetProcessDEPPolicy(0);
}""",
        "ntallocate": """\
// Low-level allocation via NtAllocateVirtualMemory
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
);

static pNtAllocateVirtualMemory g_NtAllocVm = NULL;

void rop_init_nt_alloc() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        g_NtAllocVm = (pNtAllocateVirtualMemory)GetProcAddress(
            ntdll, "NtAllocateVirtualMemory"
        );
    }
}""",
    }

    return _DEP_API_DLL_CODE.get(dep_api.value, "")


def _generate_header(base_hex: str) -> str:
    """Generate DLL header with compile instructions."""
    return f"""\
/*
 * ROP Helper DLL - Generated by target_builder
 * FOR AUTHORIZED SECURITY TESTING ONLY
 *
 * This DLL contains inline assembly gadgets for ROP chain practice.
 * Compile from: Visual Studio x86 Native Tools Command Prompt
 *
 *   cl.exe /LD /GS- rop_helper.cpp /link /BASE:{base_hex} /DYNAMICBASE:NO /SAFESEH:NO /NXCOMPAT:NO
 */

#include <windows.h>
#include <stdio.h>"""


def _generate_gadget_functions(
    density: GadgetDensity, seed: Optional[int] = None
) -> str:
    """Generate functions containing inline assembly gadgets.

    Args:
        density: Gadget density level.
        seed: Optional RNG seed for reproducible route selection at
              standard density.
    """
    functions = []

    # Minimal gadgets — always included
    functions.append(_gadgets_minimal())

    if density in (GadgetDensity.STANDARD, GadgetDensity.FULL):
        functions.append(_gadgets_standard())
        functions.append(_gadgets_esp_dirty(seed))

    if density == GadgetDensity.FULL:
        functions.append(_gadgets_full())
        functions.append(_gadgets_esp_clean())

    return "\n\n".join(functions)


def _gadgets_minimal() -> str:
    """Bare essentials: pop reg; ret, jmp esp, push esp; ret."""
    return """\
// --- Minimal gadget set ---

__declspec(noinline) void HelperInit() {
    __asm {
        // pop eax; ret
        pop eax
        ret

        // pop ecx; ret
        pop ecx
        ret

        // pop edx; ret
        pop edx
        ret

        // jmp esp
        jmp esp

        // push esp; ret
        push esp
        ret
    }
}

__declspec(noinline) void HelperValidate() {
    __asm {
        // pop ebx; ret
        pop ebx
        ret

        // pop esi; ret
        pop esi
        ret

        // pop edi; ret
        pop edi
        ret

        // pop ebp; ret
        pop ebp
        ret
    }
}"""


def _gadgets_standard() -> str:
    """Working exploit set: pivots, write-what-where, arithmetic."""
    return """\
// --- Standard gadget set ---

__declspec(noinline) void ProcessData() {
    __asm {
        // pop pop ret (for SEH)
        pop esi
        pop edi
        ret

        // xchg eax, esp; ret (stack pivot)
        xchg eax, esp
        ret

        // mov [eax], ecx; ret (write-what-where)
        mov [eax], ecx
        ret

        // add esp, 8; ret (skip 8 bytes on stack)
        add esp, 0x08
        ret

        // add esp, 0x10; ret (skip 16 bytes)
        add esp, 0x10
        ret
    }
}

__declspec(noinline) void ValidateInput() {
    __asm {
        // inc eax; ret
        inc eax
        ret

        // dec eax; ret
        dec eax
        ret

        // inc ecx; ret
        inc ecx
        ret

        // dec ecx; ret
        dec ecx
        ret

        // xor eax, eax; ret (zero eax)
        xor eax, eax
        ret

        // neg eax; ret (negate)
        neg eax
        ret
    }
}

__declspec(noinline) void TransformBuffer() {
    __asm {
        // mov eax, ecx; ret
        mov eax, ecx
        ret

        // mov ecx, eax; ret
        mov ecx, eax
        ret

        // add eax, ecx; ret
        add eax, ecx
        ret

        // sub eax, ecx; ret
        sub eax, ecx
        ret

        // push eax; pop ecx; ret
        push eax
        pop ecx
        ret
    }
}"""


def _gadgets_esp_dirty(seed: Optional[int] = None) -> str:
    """Randomly selected dirty ESP capture/adjust gadgets for DEP bypass.

    Always includes at least one complete capture→recovery route and one
    adjust gadget, but the specific gadgets vary per seed.  This forces
    students to adapt their chain to the available gadgets rather than
    memorizing a fixed recipe.
    """
    rng = _random_mod.Random(seed)

    # Pick 1-2 routes (always at least 1)
    num_routes = rng.randint(1, 2)
    routes = rng.sample(_ESP_CAPTURE_ROUTES, num_routes)

    # Pick 1-2 adjust gadgets
    num_adjust = rng.randint(1, 2)
    adjusts = rng.sample(_DIRTY_ADJUST_GADGETS, num_adjust)

    # Build the asm block
    asm_lines = []
    for route in routes:
        asm_lines.append(f"        // --- ESP capture: {route['name']} ---")
        asm_lines.append(route["capture"])
        if route["recovery"]:
            asm_lines.append("")
            asm_lines.append(route["recovery"])
        asm_lines.append("")

    asm_lines.append("        // --- ESP adjustment ---")
    for adj in adjusts:
        asm_lines.append(adj)
        asm_lines.append("")

    body = "\n".join(asm_lines).rstrip()

    return f"""\
// --- ESP realignment gadgets (dirty — require creative chaining) ---

__declspec(noinline) void AlignBuffer() {{
    __asm {{
{body}
    }}
}}"""


def _gadgets_esp_clean() -> str:
    """Clean ESP capture/adjust gadgets — full density only (easy mode)."""
    return """\
// --- Clean ESP realignment gadgets ---

__declspec(noinline) void ResolveAddress() {
    __asm {
        // push esp; pop eax; ret  — capture ESP into EAX
        push esp
        pop eax
        ret

        // mov eax, esp; ret  — capture ESP into EAX (alternate)
        mov eax, esp
        ret

        // push esp; pop esi; ret  — capture ESP into ESI
        push esp
        pop esi
        ret

        // add eax, 0x10; ret  — adjust captured ESP forward
        add eax, 0x10
        ret

        // add eax, 0x20; ret
        add eax, 0x20
        ret

        // add eax, 0x3c; ret  — common offset to reach past pushad frame
        add eax, 0x3c
        ret

        // sub eax, 0x10; ret  — adjust captured ESP backward
        sub eax, 0x10
        ret

        // sub eax, 0x20; ret
        sub eax, 0x20
        ret
    }
}"""


def _gadgets_full() -> str:
    """Rich gadget surface: multiple pivots, conditionals, varied endings."""
    return """\
// --- Full gadget set ---

__declspec(noinline) void AnalyzeStream() {
    __asm {
        // Stack pivot variants
        xchg eax, esp
        ret

        xchg ecx, esp
        ret

        // mov esp, eax; ret
        mov esp, eax
        ret

        // add esp, 0x20; ret (large skip)
        add esp, 0x20
        ret

        // add esp, 0x40; ret
        add esp, 0x40
        ret

        // pop pop pop ret
        pop eax
        pop ecx
        pop edx
        ret
    }
}

__declspec(noinline) void CompressPayload() {
    __asm {
        // Memory read gadgets
        // mov eax, [ecx]; ret
        mov eax, [ecx]
        ret

        // mov eax, [eax]; ret
        mov eax, [eax]
        ret

        // mov ecx, [edx]; ret
        mov ecx, [edx]
        ret

        // Arithmetic chains
        // add eax, ebx; ret
        add eax, ebx
        ret

        // sub eax, ebx; ret
        sub eax, ebx
        ret

        // and eax, ecx; ret
        and eax, ecx
        ret

        // or eax, ecx; ret
        or eax, ecx
        ret
    }
}

__declspec(noinline) void EncodeResult() {
    __asm {
        // Gadgets with ret N
        pop eax
        ret 4

        pop ecx
        ret 8

        // call reg variants
        push eax
        call eax

        push ecx
        call ecx

        // jmp reg variants
        jmp eax
        jmp ecx

        // Write gadgets
        // mov [ecx], eax; ret
        mov [ecx], eax
        ret

        // mov [edx], eax; ret
        mov [edx], eax
        ret

        // mov [eax+4], ecx; ret
        mov [eax+4], ecx
        ret
    }
}

__declspec(noinline) void DecryptBlock() {
    __asm {
        // Shift operations
        shl eax, 1
        ret

        shr eax, 1
        ret

        rol eax, 1
        ret

        ror eax, 1
        ret

        // Exchange variants
        xchg eax, ecx
        ret

        xchg eax, edx
        ret

        xchg eax, ebx
        ret

        // pushad; ret (push all general registers)
        pushad
        ret

        // popad; ret (pop all general registers)
        popad
        ret
    }
}"""


def _generate_dllmain() -> str:
    """Generate DllMain entry point."""
    return """\
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}"""


def _generate_init_export(dep_api: Optional[DepBypassApi] = None) -> str:
    """Generate the exported init function the server calls."""
    _DEP_INIT_CALLS = {
        "virtualprotect": "    rop_init_helper_data();\n",
        "virtualalloc": "    rop_init_scratch();\n",
        "writeprocessmemory": "",  # No init needed — called on demand
        "heapcreate": "    rop_init_heap();\n",
        "setprocessdeppolicy": "    rop_check_dep();\n",
        "ntallocate": "    rop_init_nt_alloc();\n",
    }

    dep_init = ""
    if dep_api is not None:
        dep_init = _DEP_INIT_CALLS.get(dep_api.value, "")

    return f"""\
// Exported function called by the server after LoadLibrary
extern "C" __declspec(dllexport) void RopHelperInit() {{
    printf("[+] ROP Helper DLL initialized\\n");
{dep_init}}}"""
