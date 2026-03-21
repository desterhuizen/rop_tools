"""
PE file information extraction module.

Provides classes and functions for extracting information from PE files,
including base addresses, section information, and other PE metadata.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import pefile


@dataclass
class PESection:
    """Represents a PE file section"""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int

    def get_characteristics_flags(self) -> List[str]:
        """Return list of human-readable characteristic flags"""
        flags = []
        if self.characteristics & 0x20000000:
            flags.append("EXECUTABLE")
        if self.characteristics & 0x40000000:
            flags.append("READABLE")
        if self.characteristics & 0x80000000:
            flags.append("WRITABLE")
        if self.characteristics & 0x00000020:
            flags.append("CODE")
        if self.characteristics & 0x00000040:
            flags.append("INITIALIZED_DATA")
        if self.characteristics & 0x00000080:
            flags.append("UNINITIALIZED_DATA")
        return flags


@dataclass
class IATEntry:
    """Represents an Import Address Table entry"""

    dll: str
    function: str
    address: int  # RVA (Relative Virtual Address)
    ordinal: Optional[int] = None

    def get_absolute_address(self, image_base: int) -> int:
        """Return absolute address (ImageBase + RVA)"""
        return image_base + self.address


@dataclass
class PEInfo:
    """Represents PE file information"""

    filepath: str
    image_base: int
    entry_point: int
    machine_type: str
    subsystem: str
    sections: List[PESection]

    def get_absolute_entry_point(self) -> int:
        """Return absolute entry point address (ImageBase + EntryPoint)"""
        return self.image_base + self.entry_point


class PEAnalyzer:
    """Analyzes PE files to extract information"""

    # Machine type constants
    MACHINE_TYPES = {
        0x14C: "x86 (I386)",
        0x8664: "x64 (AMD64)",
        0x1C0: "ARM",
        0xAA64: "ARM64",
        0x1C4: "ARM Thumb-2",
    }

    # Subsystem constants
    SUBSYSTEMS = {
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        7: "POSIX_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM",
        14: "XBOX",
    }

    @staticmethod
    def analyze_file(filepath: str) -> PEInfo:
        """
        Analyze a PE file and extract information.

        Args:
            filepath: Path to the PE file

        Returns:
            PEInfo object containing PE information

        Raises:
            FileNotFoundError: If file doesn't exist
            pefile.PEFormatError: If file is not a valid PE
        """
        pe = pefile.PE(filepath)

        # Get machine type
        machine = pe.FILE_HEADER.Machine
        machine_type = PEAnalyzer.MACHINE_TYPES.get(machine,
                                                    f"Unknown (0x{machine:x})")

        # Get subsystem
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        subsystem_name = PEAnalyzer.SUBSYSTEMS.get(subsystem,
                                                   f"Unknown ({subsystem})")

        # Extract sections
        sections = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sections.append(
                PESection(
                    name=name,
                    virtual_address=section.VirtualAddress,
                    virtual_size=section.Misc_VirtualSize,
                    raw_size=section.SizeOfRawData,
                    characteristics=section.Characteristics,
                )
            )

        pe_info = PEInfo(
            filepath=filepath,
            image_base=pe.OPTIONAL_HEADER.ImageBase,
            entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            machine_type=machine_type,
            subsystem=subsystem_name,
            sections=sections,
        )

        pe.close()
        return pe_info

    @staticmethod
    def get_base_address(filepath: str) -> int:
        """
        Extract just the ImageBase from a PE file.

        Args:
            filepath: Path to the PE file

        Returns:
            ImageBase address as integer

        Raises:
            FileNotFoundError: If file doesn't exist
            pefile.PEFormatError: If file is not a valid PE
        """
        pe = pefile.PE(filepath)
        base_address = pe.OPTIONAL_HEADER.ImageBase
        pe.close()
        return base_address

    @staticmethod
    def get_iat_entries(filepath: str) -> List[IATEntry]:
        """
        Extract Import Address Table (IAT) entries from a PE file.

        Args:
            filepath: Path to the PE file

        Returns:
            List of IATEntry objects containing import information

        Raises:
            FileNotFoundError: If file doesn't exist
            pefile.PEFormatError: If file is not a valid PE
        """
        pe = pefile.PE(filepath)
        iat_entries = []

        # Check if the PE has an import directory
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            pe.close()
            return iat_entries

        # Iterate through all imported DLLs
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")

            # Iterate through all imported functions from this DLL
            for imp in entry.imports:
                # Get function name (if imported by name) or ordinal
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="ignore")
                    ordinal = imp.ordinal if hasattr(imp, "ordinal") else None
                else:
                    # Import by ordinal only
                    func_name = f"Ordinal_{imp.ordinal}"
                    ordinal = imp.ordinal

                # Add IAT entry
                iat_entries.append(
                    IATEntry(
                        dll=dll_name,
                        function=func_name,
                        address=imp.address,
                        ordinal=ordinal,
                    )
                )

        pe.close()
        return iat_entries
