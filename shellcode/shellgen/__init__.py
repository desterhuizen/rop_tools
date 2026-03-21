"""
Shellcode Generator Package
Multi-architecture shellcode generation with bad character avoidance
"""

__version__ = "1.0.0"
__author__ = "Dawid Esterhuizen"

from .encoders import encode_dword, encode_qword, string_to_push_dwords
from .assembler import assemble_with_keystone, assemble_to_binary, verify_shellcode_bad_chars

__all__ = [
    'encode_dword',
    'encode_qword',
    'string_to_push_dwords',
    'assemble_with_keystone',
    'assemble_to_binary',
    'verify_shellcode_bad_chars',
]