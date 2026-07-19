import os
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
import capstone

def analyze_so(so_path: str):
    """
    Parses ELF to find architecture and exported functions (from .dynsym).
    Returns info dict and list of exports.
    """
    exports = []
    arch = "Unknown"
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)

        # Check architecture
        machine = elf.header['e_machine']
        if machine == 'EM_AARCH64':
            arch = "ARM64"
        elif machine == 'EM_ARM':
            arch = "ARM"
        else:
            arch = f"Unknown ({machine})"

        # Extract exported functions from dynamic symbol table (.dynsym)
        dynsym = elf.get_section_by_name('.dynsym')
        if dynsym:
            for sym in dynsym.iter_symbols():
                # We want function symbols that are visible (usually global or weak) and have a valid address
                info = sym.entry['st_info']
                bind = info['bind']
                sym_type = info['type']
                name = sym.name

                # Check if it's a function or if it's a dynamic symbol that could be an entry
                # STT_FUNC or STT_NOTYPE (sometimes used)
                if name and sym_type in ('STT_FUNC', 'STT_NOTYPE') and sym.entry['st_value'] != 0:
                    exports.append({
                        "name": name,
                        "address": sym.entry['st_value'],
                        "size": sym.entry['st_size'],
                        "bind": bind,
                        "type": sym_type
                    })

    # Sort exports by address
    exports.sort(key=lambda x: x['address'])
    return {"arch": arch, "exports": exports}

def disassemble_func(so_path: str, arch: str, addr: int, size: int):
    """
    Disassembles the bytes of a function at physical/virtual offset `addr` inside the SO.
    """
    # For simplicity, if size is 0 or extremely large, we limit or guess it.
    if size <= 0:
        size = 128 # Default guess for demonstration

    with open(so_path, 'rb') as f:
        # Find physical offset of address using program headers
        elf = ELFFile(f)
        phys_offset = None
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                vaddr = segment['p_vaddr']
                memsz = segment['p_memsz']
                filesz = segment['p_filesz']
                if vaddr <= addr < vaddr + memsz:
                    phys_offset = segment['p_offset'] + (addr - vaddr)
                    break

        if phys_offset is None:
            # Fallback to absolute file offset if vaddr mapping wasn't resolved straightforwardly
            phys_offset = addr

        f.seek(phys_offset)
        code_bytes = f.read(size)

    # Initialize Capstone
    if arch == "ARM64":
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    else:
        # Default 32-bit ARM
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    md.detail = True
    instructions = []
    for insn in md.disasm(code_bytes, addr):
        instructions.append({
            "address": insn.address,
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex()
        })

    return instructions
