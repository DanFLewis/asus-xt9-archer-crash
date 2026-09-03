#!/usr/bin/env python3
"""Find every call site of a symbol inside a kernel module, and show what the
caller does with the return value.

Call targets in a .ko are unresolved until load time, so capstone alone shows
`bl #<own address>`. The real target lives in the .rel.text relocations.

Usage:  python callers.py <archer.ko> [symbol]
"""
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile


def main(path, target):
    raw = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    symtab = elf.get_section_by_name(".symtab")
    syms = list(symtab.iter_symbols())
    text = elf.get_section_by_name(".text")
    sh = text["sh_offset"]

    idx = [n for n, s in enumerate(syms) if s.name == target]
    if not idx:
        sys.exit(f"symbol {target!r} not found")

    rel = elf.get_section_by_name(".rel.text")
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)

    for r in rel.iter_relocations():
        if r["r_info_sym"] not in idx:
            continue
        va = r["r_offset"]
        owner = None
        for sy in syms:
            if sy.entry["st_info"]["type"] != "STT_FUNC":
                continue
            base = sy.entry["st_value"] & ~1
            if base <= va < base + sy.entry["st_size"]:
                owner = sy.name
                break
        print(f"\n=== call from {owner} (.text+0x{va:x}) ===")
        blob = raw[sh + va - 8:sh + va + 10 * 4]
        for ins in md.disasm(blob, va - 8):
            mark = f"   <== bl {target}" if ins.address == va else ""
            print(f"  0x{ins.address:05x}: {ins.mnemonic:<8} "
                  f"{ins.op_str}{mark}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1],
         sys.argv[2] if len(sys.argv) > 2 else "archer_dhd_tx_packet")
