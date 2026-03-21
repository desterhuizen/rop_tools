"""
Gadget categorization for ROP analysis.

Defines categories for ROP gadgets and provides categorization logic.
"""

import re

from .gadget import Gadget


class GadgetCategory:
    """Common ROP gadget categories for defensive security analysis"""

    # Stack manipulation - essential for ROP chains
    STACK_PIVOT = "stack_pivot"
    STACK_POP = "stack_pop"
    STACK_PUSH = "stack_push"

    # Register control - controlling register values
    LOAD_REGISTER = "load_register"
    MOVE_REGISTER = "move_register"
    XCHG_REGISTER = "xchg_register"

    # Memory operations
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"

    # Arithmetic/Logic
    ARITHMETIC = "arithmetic"
    LOGIC = "logic"

    # Control flow
    CALL = "call"
    JMP = "jmp"
    CONDITIONAL = "conditional"

    # System/Interrupt
    SYSCALL = "syscall"
    INTERRUPT = "interrupt"

    # String operations
    STRING_OPS = "string_ops"

    # Other/Unknown
    OTHER = "other"


def categorize_gadget(gadget: Gadget) -> str:
    """Categorize a gadget based on its instructions"""
    instructions_lower = [inst.lower() for inst in gadget.instructions]
    first_inst = instructions_lower[0] if instructions_lower else ""
    last_inst = instructions_lower[-1] if instructions_lower else ""

    # Stack pivots (esp/rsp manipulation)
    if any(
            re.match(r"(xchg|xor|add|sub|lea).*[er]sp", inst) for inst in
            instructions_lower
    ):
        return GadgetCategory.STACK_PIVOT

    # Stack pops
    if "pop" in first_inst:
        return GadgetCategory.STACK_POP

    # Stack push
    if "push" in first_inst:
        return GadgetCategory.STACK_PUSH

    # Calls
    if "call" in last_inst:
        return GadgetCategory.CALL

    # Jumps
    if "jmp" in last_inst or "jne" in last_inst or "je" in last_inst:
        return GadgetCategory.JMP

    # Conditionals
    if any(
            inst.startswith(
                ("jne", "je", "jz", "jnz", "jl", "jg", "jle", "jge"))
            for inst in instructions_lower
    ):
        return GadgetCategory.CONDITIONAL

    # Memory read operations
    if any(re.match(r"mov.*,.*\[", inst) for inst in instructions_lower):
        return GadgetCategory.MEMORY_READ

    # Memory write operations
    if any(re.match(r"mov.*\[.*,", inst) for inst in instructions_lower):
        return GadgetCategory.MEMORY_WRITE

    # Register moves
    if "mov" in first_inst and "[" not in first_inst:
        return GadgetCategory.MOVE_REGISTER

    # Register exchange
    if "xchg" in first_inst:
        return GadgetCategory.XCHG_REGISTER

    # Load operations
    if any(inst.startswith(("lea", "ld", "ldr", "ldd")) for inst in
           instructions_lower):
        return GadgetCategory.LOAD_REGISTER

    # Arithmetic
    if any(
            inst.split()[0]
            in ("add", "sub", "inc", "dec", "mul", "imul", "div", "idiv", "neg")
            for inst in instructions_lower
    ):
        return GadgetCategory.ARITHMETIC

    # Logic operations
    if any(
            inst.split()[0]
            in ("and", "or", "xor", "not", "shl", "shr", "ror", "rol", "sal",
                "sar")
            for inst in instructions_lower
    ):
        return GadgetCategory.LOGIC

    # String operations
    if any(
            inst.split()[0]
            in ("movs", "lods", "stos", "scas", "cmps", "movsb", "movsw",
                "movsd")
            for inst in instructions_lower
    ):
        return GadgetCategory.STRING_OPS

    # System calls
    if any(
            inst in ("syscall", "sysenter", "int 0x80", "int 0x2e")
            for inst in instructions_lower
    ):
        return GadgetCategory.SYSCALL

    # Interrupts
    if any(inst.startswith("int") for inst in instructions_lower):
        return GadgetCategory.INTERRUPT

    return GadgetCategory.OTHER


def get_category_style(category: str) -> str:
    """Get rich style for a gadget category"""
    category_styles = {
        GadgetCategory.STACK_PIVOT: "bold red",
        GadgetCategory.STACK_POP: "green",
        GadgetCategory.STACK_PUSH: "cyan",
        GadgetCategory.LOAD_REGISTER: "yellow",
        GadgetCategory.MOVE_REGISTER: "yellow",
        GadgetCategory.XCHG_REGISTER: "yellow",
        GadgetCategory.MEMORY_READ: "magenta",
        GadgetCategory.MEMORY_WRITE: "bold magenta",
        GadgetCategory.ARITHMETIC: "blue",
        GadgetCategory.LOGIC: "blue",
        GadgetCategory.CALL: "red",
        GadgetCategory.JMP: "red",
        GadgetCategory.CONDITIONAL: "yellow",
        GadgetCategory.SYSCALL: "bold red",
        GadgetCategory.INTERRUPT: "red",
        GadgetCategory.STRING_OPS: "cyan",
        GadgetCategory.OTHER: "white",
    }
    return category_styles.get(category, "white")
