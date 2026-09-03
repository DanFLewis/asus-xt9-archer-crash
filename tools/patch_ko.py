#!/usr/bin/env python3
"""Apply the verified guard patch to archer.ko, producing a loadable module.

Grows .text by 24 bytes (appends the cave) and fixes section offsets + e_shoff.
For a REL/ARM .ko, symbol values and relocation offsets are section-relative,
so appending to the END of .text touches no existing code and needs no reloc
fixups. Refuses to run if the bytes at the patch site don't match (wrong fw).

Usage:  python patch_ko.py [archer.ko] [archer_patched.ko]
"""
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

FN = 0x1320c
FAULT = FN + 0x218
ORIG_STORE = bytes.fromhex('87028ce7')   # str r0, [ip, r7, lsl #5]


def b_enc(frm, to, cond='al'):
    imm = ((to - (frm + 8)) >> 2) & 0xFFFFFF
    cb = {'al': 0xE, 'eq': 0x0}[cond]
    return struct.pack('<I', (cb << 28) | (0xA << 24) | imm)


def main(src, dst):
    raw = bytearray(open(src, 'rb').read())
    elf = ELFFile(open(src, 'rb'))
    e_shoff = struct.unpack_from('<I', raw, 0x20)[0]
    e_shnum = struct.unpack_from('<H', raw, 0x30)[0]
    assert struct.unpack_from('<H', raw, 0x2e)[0] == 40, 'unexpected e_shentsize'

    text = elf.get_section_by_name('.text')
    text_idx = next(i for i in range(elf.num_sections())
                    if elf.get_section(i).name == '.text')
    t_off, t_size = text['sh_offset'], text['sh_size']
    if bytes(raw[t_off + FAULT:t_off + FAULT + 4]) != ORIG_STORE:
        sys.exit('patch site does not match - wrong firmware version?')

    cave_va = t_size
    cave = bytearray()
    cave += struct.pack('<I', 0xE35C0000)             # cmp ip, #0
    cave += b_enc(cave_va + 0x04, cave_va + 0x10, 'eq')  # beq null_path
    cave += ORIG_STORE                                # str r0, [ip, r7, lsl #5]
    cave += b_enc(cave_va + 0x0c, FN + 0x21c, 'al')   # b resume (+0x21c)
    cave += struct.pack('<I', 0xE3A0B000)             # mov fp, #0
    cave += b_enc(cave_va + 0x14, FN + 0x194, 'al')   # b epilogue (+0x194)
    assert len(cave) == 24

    raw[t_off + FAULT:t_off + FAULT + 4] = b_enc(FAULT, cave_va, 'al')
    ins_at = t_off + t_size
    raw[ins_at:ins_at] = cave
    grow = len(cave)

    # fix section headers (shdr table has itself shifted if it followed .text)
    for i in range(e_shnum):
        p = e_shoff + i * 40 + (grow if e_shoff >= ins_at else 0)
        sh_offset = struct.unpack_from('<I', raw, p + 0x10)[0]
        sh_size = struct.unpack_from('<I', raw, p + 0x14)[0]
        if i == text_idx:
            struct.pack_into('<I', raw, p + 0x14, sh_size + grow)
        elif sh_offset >= ins_at:
            struct.pack_into('<I', raw, p + 0x10, sh_offset + grow)
    if e_shoff >= ins_at:
        struct.pack_into('<I', raw, 0x20, e_shoff + grow)

    open(dst, 'wb').write(raw)

    # validate: reparse, confirm symbol unchanged + cave disassembles
    e2 = ELFFile(open(dst, 'rb'))
    sym = next(s for s in e2.get_section_by_name('.symtab').iter_symbols()
               if s.name == 'archer_dhd_tx_packet')
    print(f"wrote {dst}: +{grow} bytes; "
          f"symbol st_value unchanged: {sym['st_value'] == FN}")
    to = e2.get_section_by_name('.text')['sh_offset']
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    raw2 = open(dst, 'rb').read()
    for ins in md.disasm(raw2[to + cave_va:to + cave_va + 24], cave_va):
        print(f"  +0x{ins.address:05x}: {ins.mnemonic:<6} {ins.op_str}")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'archer.ko',
         sys.argv[2] if len(sys.argv) > 2 else 'archer_patched.ko')
