"""
Gadget processing and library management.
"""

from .processor import process_gadget, find_gadget_by_address, log_execution
from .library import cmd_gadget_add, cmd_gadget_del, cmd_gadget_clear

__all__ = [
    'process_gadget', 'find_gadget_by_address', 'log_execution',
    'cmd_gadget_add', 'cmd_gadget_del', 'cmd_gadget_clear',
]