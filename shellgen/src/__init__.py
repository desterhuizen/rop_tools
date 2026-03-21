"""
Shellcode Generator Package
Multi-architecture shellgen generation with bad character avoidance
"""

__version__ = "1.0.0"
__author__ = "Dawid Esterhuizen"

from .assembler import (
    assemble_to_binary,
    assemble_with_keystone,
    verify_shellcode_bad_chars,
)
from .encoders import encode_dword, encode_qword, string_to_push_dwords

__all__ = [
    "encode_dword",
    "encode_qword",
    "string_to_push_dwords",
    "assemble_with_keystone",
    "assemble_to_binary",
    "verify_shellcode_bad_chars",
]
