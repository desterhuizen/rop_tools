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


def _is_stack_pivot(instructions_lower, first_inst, last_inst):
    return any(
        re.match(r"(xchg|xor|add|sub|lea).*[er]sp", inst)
        for inst in instructions_lower
    )


def _is_stack_pop(instructions_lower, first_inst, last_inst):
    return "pop" in first_inst


def _is_stack_push(instructions_lower, first_inst, last_inst):
    return "push" in first_inst


def _is_call(instructions_lower, first_inst, last_inst):
    return "call" in last_inst


def _is_jmp(instructions_lower, first_inst, last_inst):
    return "jmp" in last_inst or "jne" in last_inst or "je" in last_inst


def _is_conditional(instructions_lower, first_inst, last_inst):
    return any(
        inst.startswith(("jne", "je", "jz", "jnz", "jl", "jg", "jle", "jge"))
        for inst in instructions_lower
    )


def _is_memory_read(instructions_lower, first_inst, last_inst):
    return any(re.match(r"mov.*,.*\[", inst) for inst in instructions_lower)


def _is_memory_write(instructions_lower, first_inst, last_inst):
    return any(re.match(r"mov.*\[.*,", inst) for inst in instructions_lower)


def _is_move_register(instructions_lower, first_inst, last_inst):
    return "mov" in first_inst and "[" not in first_inst


def _is_xchg_register(instructions_lower, first_inst, last_inst):
    return "xchg" in first_inst


def _is_load_register(instructions_lower, first_inst, last_inst):
    return any(
        inst.startswith(("lea", "ld", "ldr", "ldd"))
        for inst in instructions_lower
    )


def _is_arithmetic(instructions_lower, first_inst, last_inst):
    arith_ops = {"add", "sub", "inc", "dec", "mul", "imul", "div", "idiv", "neg"}
    return any(inst.split()[0] in arith_ops for inst in instructions_lower)


def _is_logic(instructions_lower, first_inst, last_inst):
    logic_ops = {"and", "or", "xor", "not", "shl", "shr", "ror", "rol", "sal", "sar"}
    return any(inst.split()[0] in logic_ops for inst in instructions_lower)


def _is_string_ops(instructions_lower, first_inst, last_inst):
    str_ops = {"movs", "lods", "stos", "scas", "cmps", "movsb", "movsw", "movsd"}
    return any(inst.split()[0] in str_ops for inst in instructions_lower)


def _is_syscall(instructions_lower, first_inst, last_inst):
    return any(
        inst in ("syscall", "sysenter", "int 0x80", "int 0x2e")
        for inst in instructions_lower
    )


def _is_interrupt(instructions_lower, first_inst, last_inst):
    return any(inst.startswith("int") for inst in instructions_lower)


# Ordered list of (check_func, category) - first match wins
_CATEGORY_RULES = [
    (_is_stack_pivot, GadgetCategory.STACK_PIVOT),
    (_is_stack_pop, GadgetCategory.STACK_POP),
    (_is_stack_push, GadgetCategory.STACK_PUSH),
    (_is_call, GadgetCategory.CALL),
    (_is_jmp, GadgetCategory.JMP),
    (_is_conditional, GadgetCategory.CONDITIONAL),
    (_is_memory_read, GadgetCategory.MEMORY_READ),
    (_is_memory_write, GadgetCategory.MEMORY_WRITE),
    (_is_move_register, GadgetCategory.MOVE_REGISTER),
    (_is_xchg_register, GadgetCategory.XCHG_REGISTER),
    (_is_load_register, GadgetCategory.LOAD_REGISTER),
    (_is_arithmetic, GadgetCategory.ARITHMETIC),
    (_is_logic, GadgetCategory.LOGIC),
    (_is_string_ops, GadgetCategory.STRING_OPS),
    (_is_syscall, GadgetCategory.SYSCALL),
    (_is_interrupt, GadgetCategory.INTERRUPT),
]


def categorize_gadget(gadget: Gadget) -> str:
    """Categorize a gadget based on its instructions"""
    instructions_lower = [inst.lower() for inst in gadget.instructions]
    first_inst = instructions_lower[0] if instructions_lower else ""
    last_inst = instructions_lower[-1] if instructions_lower else ""

    for check_func, category in _CATEGORY_RULES:
        if check_func(instructions_lower, first_inst, last_inst):
            return category

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
