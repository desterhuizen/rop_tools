# Bad Character Avoidance Techniques (Non-Encoding)

> ⚠️ **EDUCATIONAL AND AUTHORIZED TESTING ONLY**
> This document is provided for security research, education, and authorized penetration testing purposes only. These techniques must only be used on systems you own or have explicit written permission to test. Unauthorized use may violate laws and regulations. The authors are not responsible for misuse of this information.

---

These techniques avoid bad characters without using overall encoding schemes like XOR or Base64. They work at the instruction level to construct values that contain bad characters.

## 1. **NEG (Negate) Technique**
Two's complement negation to construct values.
```asm
; To get 0x12345678 (if it contains bad chars)
mov eax, 0xEDCBA988    ; Encoded value (negated)
neg eax                ; Result: 0x12345678
```
**Formula**: `encoded = (0x100000000 - target) & 0xFFFFFFFF`

**Use Case**: Best for avoiding nulls and other bad bytes in immediate values.

---

## 2. **ADD/SUB Construction**
Build target values by adding or subtracting components.

### Simple Addition:
```asm
; To get 0x00000100 (avoiding null bytes)
xor eax, eax           ; eax = 0
add eax, 0x80          ; eax = 0x80
add eax, 0x80          ; eax = 0x100
```

### Subtraction:
```asm
; To get 0x01 (if 0x01 is bad)
mov al, 0x06           ; al = 6
sub al, 0x05           ; al = 1
```

**Use Case**: Small values, incrementing through ranges, avoiding specific bytes.

---

## 3. **XOR Construction**
XOR two safe values to produce the target.
```asm
; To get 0xDEADBEEF
mov eax, 0x12345678
xor eax, 0xCC99E897    ; Result: 0xDEADBEEF
```

**Formula**: Find `A` and `B` where `A XOR B = target` and neither contains bad chars.

**Use Case**: When you can find two clean values that XOR to your target.

---

## 4. **NOT (Bitwise Complement)**
Invert bits to construct values.
```asm
; To get 0x12345678
mov eax, 0xEDCBA987    ; Bitwise inverse
not eax                ; Result: 0x12345678
```

**Formula**: `encoded = ~target & 0xFFFFFFFF`

**Use Case**: Similar to NEG but produces different encoded bytes.

---

## 5. **INC/DEC (Increment/Decrement)**
Step through values one at a time.
```asm
; To get 0x10 (avoiding 0x10 byte)
xor al, al             ; al = 0
mov cl, 0x10           ; Loop counter
increment_loop:
    inc al
    loop increment_loop ; al = 0x10
```

**Use Case**: Small values, loop counters, fine-tuning after other operations.

---

## 6. **SHL/SHR (Shift Operations)**
Shift bits to construct or avoid values.

### Left Shift:
```asm
; To get 0x00000100 (avoiding nulls)
xor eax, eax
inc eax                ; eax = 1
shl eax, 8             ; eax = 0x100
```

### Right Shift:
```asm
; To construct 0x01 from 0x100
mov ax, 0x0100
shr ax, 8              ; ax = 0x01
```

**Use Case**: Multiplying by powers of 2, extracting byte portions, avoiding nulls.

---

## 7. **ROL/ROR (Rotate Operations)**
Rotate bits to rearrange byte positions.
```asm
; To get 0x12345678 with different byte arrangement
mov eax, 0x78563412
ror eax, 16            ; Result: 0x12345678
```

**Use Case**: Reordering bytes, avoiding specific byte positions.

---

## 8. **MUL/IMUL (Multiplication)**
Multiply to construct target values.
```asm
; To get 0x200 (512)
xor eax, eax
mov al, 0x40           ; al = 64
mov cl, 0x08           ; cl = 8
mul cl                 ; ax = 64 * 8 = 512 (0x200)
```

**Use Case**: Creating larger values from smaller safe values.

---

## 9. **Push/Pop Manipulation**
Use stack operations to construct values indirectly.
```asm
; Build string without null bytes directly in code
push 0x68732f2f        ; "//sh"
push 0x6e69622f        ; "/bin"
mov ebx, esp           ; EBX = pointer to "/bin//sh"
```

**Use Case**: String construction, pointer manipulation.

---

## 10. **Partial Register Operations**
Use smaller register portions (AL, AH, AX) to avoid nulls.

```asm
; To get 0x00000001 (avoiding null bytes)
xor eax, eax           ; Uses XOR (2-byte) instead of mov eax, 0
inc eax                ; eax = 1
```

```asm
; Building word values
xor eax, eax
mov ax, 0x6c6c         ; Only sets lower 16 bits
```

**Use Case**: Small values, avoiding MOV with immediate nulls.

---

## 11. **OR Construction**
OR multiple safe values together.
```asm
; To get 0x12345678
mov eax, 0x12340000
or eax, 0x00005678     ; Result: 0x12345678
```

**Use Case**: Combining bit fields, setting specific bits.

---

## 12. **LEA (Load Effective Address)**
Perform arithmetic without using arithmetic instructions.
```asm
; To get eax + 8 (avoiding immediate value)
lea eax, [eax + 8]

; To get eax * 2 + 4
lea eax, [eax*2 + 4]
```

**Use Case**: Adding offsets, scaling, avoiding null immediates.

---

## 13. **XCHG (Exchange)**
Swap register contents to rearrange data.
```asm
; Reorder bytes without immediate values
mov eax, 0x12345678
xchg al, ah            ; Swap lower bytes
```

**Use Case**: Byte reordering, register swapping (XCHG EAX, REG is 1 byte).

---

## 14. **BSWAP (Byte Swap)**
Reverse byte order in a register.
```asm
; Convert between endianness
mov eax, 0x12345678
bswap eax              ; Result: 0x78563412
```

**Use Case**: Endianness conversion, byte reordering.

---

## 15. **Conditional Moves (CMOV)**
Move based on conditions to construct values dynamically.
```asm
; Set value based on flag
xor eax, eax
mov ecx, 0x100
test ebx, ebx
cmovz eax, ecx         ; If zero flag set, eax = 0x100
```

**Use Case**: Dynamic value construction, avoiding branches.

---

## 16. **LOOP Instruction**
Use natural loop counter (ECX/RCX) instead of immediate values.
```asm
; Decrement ECX and branch if not zero
mov ecx, 0x10
loop_start:
    ; ... operations ...
    loop loop_start     ; Implicit: dec ecx; jnz loop_start
```

**Use Case**: Counted loops without explicit comparisons.

---

## 17. **ADC/SBB (Add/Subtract with Carry)**
Use carry flag to construct values.
```asm
; To add 1 only if carry flag is set
clc                    ; Clear carry
mov eax, 0x10
adc eax, 0             ; Add with carry (eax = 0x10)
```

**Use Case**: Conditional arithmetic, building values based on flags.

---

## 18. **Stack Alignment Tricks**
Use ESP/RSP manipulation to create pointers without nulls.
```asm
; Get current stack position without null bytes
push esp
pop eax                ; eax = current ESP value
sub eax, 0x100         ; Allocate space
```

**Use Case**: Stack allocation, pointer creation.

---

## 19. **FPU Instructions**
Use floating point unit to manipulate data.
```asm
; Store integer via FPU
fild dword ptr [esp]   ; Load integer
fistp dword ptr [esp]  ; Store integer
```

**Use Case**: Niche cases, obfuscation, special constraints.

---

## 20. **String Instructions (STOS/LODS/MOVS)**
Manipulate memory in patterns.
```asm
; Zero memory without mov [addr], 0
xor eax, eax
mov ecx, 0x100
rep stosb              ; Fill ECX bytes at EDI with AL
```

**Use Case**: Memory initialization, copying, pattern filling.

---

## Practical Combination Example

Building the string "cmd.exe" avoiding null bytes:

```asm
; Method 1: NEG encoding
mov eax, 0xF2CCFF9C    ; Encoded "exe\x00"
neg eax
push eax

mov eax, 0xFA9A9793    ; Encoded "cmd."
neg eax  
push eax

push esp
pop ebx                ; EBX -> "cmd.exe\x00"

; Method 2: ADD/SUB with XOR
xor eax, eax           ; Clear EAX (no null byte in instruction)
mov al, 0x65           ; 'e'
shl eax, 8
add al, 0x78           ; 'x'
shl eax, 8
add al, 0x65           ; 'e'
shl eax, 8             ; Last byte becomes null
push eax

; ... continue for "cmd."
```

---

## Tips for Selection

1. **NEG**: Best for immediate values with nulls
2. **ADD/SUB**: Best for small sequential values
3. **XOR**: Best when you have flexibility in choosing encoding values
4. **Shift Operations**: Best for powers of 2 and byte manipulation
5. **Partial Registers**: Best for small values (< 256)
6. **Stack Operations**: Best for strings and complex structures

---

## Common Pattern: Avoiding Null Bytes

Most commonly, you want to avoid `\x00`. Here are the go-to techniques:

```asm
; Instead of: mov eax, 0x00000001 (contains nulls)
xor eax, eax           ; eax = 0 (2 bytes, no nulls)
inc eax                ; eax = 1 (1 byte, no nulls)

; Instead of: mov eax, 0x00000100
xor eax, eax
mov ax, 0x0100         ; Only sets lower 16 bits (no null in instruction)

; Instead of: push 0
xor eax, eax
push eax

; Instead of: mov eax, 0x12345600 (has null)
mov eax, 0xEDCBA900
neg eax
```

