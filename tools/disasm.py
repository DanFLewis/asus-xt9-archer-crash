#!/usr/bin/env python3
"""Disassemble around the archer_dhd_tx_packet crash site.

Resolves the symbol from the module's .symtab (the .ko is not stripped),
then disassembles a window around the faulting offset.

Usage:  python disasm.py <archer.ko> [symbol] [fault_offset_hex]
"""
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile


def find_symbol(elf, name):
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        sys.exit("no .symtab - module is stripped")
    for sym in symtab.iter_symbols():
        if sym.name == name:
            return sym
    sys.exit(f"symbol {name!r} not found")


def main(path, name, fault):
    raw = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    sym = find_symbol(elf, name)

    val = sym.entry["st_value"]
    size = sym.entry["st_size"]
    sec = elf.get_section(sym.entry["st_shndx"])
    thumb = bool(val & 1)
    file_off = sec["sh_offset"] + (val & ~1) - sec["sh_addr"]

    print(f"{name}: {size} (0x{size:x}) bytes in {sec.name}, "
          f"{'Thumb' if thumb else 'ARM'} mode")
    print(f"file offset 0x{file_off:x}\n")

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    code = raw[file_off:file_off + size]
    lo, hi = fault - 0x40, fault + 0x14

    for ins in md.disasm(code, 0):
        if not lo <= ins.address <= hi:
            continue
        mark = "   <== FAULT" if ins.address == fault else ""
        print(f"  +0x{ins.address:04x}:  {ins.bytes.hex():<10} "
              f"{ins.mnemonic:<8} {ins.op_str}{mark}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1],
         sys.argv[2] if len(sys.argv) > 2 else "archer_dhd_tx_packet",
         int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x218)
