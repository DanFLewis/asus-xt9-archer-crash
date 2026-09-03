#!/usr/bin/env python3
"""Build the archer_dhd_tx_packet NULL-guard patch.

Appends a 24-byte code cave to .text and redirects the unguarded store at
+0x218 through a NULL check. Writes text_orig.bin and text_patched.bin for
the verifier.

The cave is appended to .text (not placed in .exit.text) so that it lives in
the same section as the patch site: the module loader keeps a section
contiguous, so a PC-relative branch is valid with no added relocation.

Usage:  python build_patch.py [archer.ko]
"""
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

FN_OFF   = 0x1320c   # archer_dhd_tx_packet, .text-relative
STORE    = 0x218     # the unguarded store
RESUME   = 0x21c     # instruction after it
EPILOGUE = 0x194     # mov r0, fp ; add sp,sp,#0x2c ; pop {..., pc}
ORIG_STORE = bytes.fromhex('87028ce7')   # str r0, [ip, r7, lsl #5]


def b_enc(frm, to, cond='al'):
    """ARM B: cond 1010 imm24, where imm24 = (to - (frm + 8)) >> 2."""
    imm24 = ((to - (frm + 8)) >> 2) & 0xFFFFFF
    cond_bits = {'al': 0xE, 'eq': 0x0, 'ne': 0x1}[cond]
    return struct.pack('<I', (cond_bits << 28) | (0xA << 24) | imm24)


def main(path):
    raw = open(path, 'rb').read()
    elf = ELFFile(open(path, 'rb'))
    text = elf.get_section_by_name('.text')
    sh, size = text['sh_offset'], text['sh_size']
    body = bytearray(raw[sh:sh + size])

    fault = FN_OFF + STORE
    resume = FN_OFF + RESUME
    epilogue = FN_OFF + EPILOGUE
    cave_at = size

    found = bytes(body[fault:fault + 4])
    if found != ORIG_STORE:
        sys.exit(f"unexpected instruction at +0x{STORE:x}: {found.hex()} "
                 f"(expected {ORIG_STORE.hex()}) - wrong firmware version?")

    cave = bytearray()
    cave += struct.pack('<I', 0xE35C0000)             # cmp ip, #0
    cave += b_enc(cave_at + 0x04, cave_at + 0x10, 'eq')  # beq null_path
    cave += ORIG_STORE                                # str r0, [ip, r7, lsl #5]
    cave += b_enc(cave_at + 0x0c, resume, 'al')       # b resume
    cave += struct.pack('<I', 0xE3A0B000)             # mov fp, #0
    cave += b_enc(cave_at + 0x14, epilogue, 'al')     # b epilogue

    patched = bytearray(body)
    patched[fault:fault + 4] = b_enc(fault, cave_at, 'al')
    patched += cave

    open('text_orig.bin', 'wb').write(bytes(body))
    open('text_patched.bin', 'wb').write(bytes(patched))

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    print(f".text 0x{size:x} -> 0x{len(patched):x} (+{len(cave)} bytes)")
    print(f"cave at .text+0x{cave_at:x}\n")
    for ins in md.disasm(bytes(cave), cave_at):
        print(f"  0x{ins.address:05x}: {ins.bytes.hex():<9} "
              f"{ins.mnemonic:<6} {ins.op_str}")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'archer.ko')
