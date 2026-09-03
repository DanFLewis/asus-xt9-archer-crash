#!/usr/bin/env python3
"""Rewrite the rootfs inside a ZenWiFi XT9 FIT (.pkgtb) image.

Replaces the rootfs squashfs blob, updates the FIT `data-size`, and recomputes
the rootfs `hash-1/value`. The FIT carries SHA-256 integrity hashes but NO
signature, so no key is needed.

Layout (reverse-engineered, then verified: re-wrapping the original squashfs
reproduces the stock .pkgtb byte-for-byte):
  [0:936]            FIT header (DTB) + pad; data-base = 936
  [936:10113212]     bootfs blob   (data-offset 0,        unchanged)
  [10113212:EOF]     rootfs blob   (data-offset 10112276, 4096-padded)
Edited header fields:
  data-size  @ 0x164  u32 BE  = roundup(new_squashfs, 4096)
  hash value @ 0x1d0  32 B    = sha256(padded rootfs blob)
The rootfs hash covers the 4096-PADDED blob, not the raw squashfs (verified
against the stock stored hash).

Usage:  python fit_rewrite.py <new_rootfs.squashfs> <out.pkgtb> [stock.pkgtb]
"""
import hashlib
import struct
import sys

DATA_BASE = 936
ROOTFS_DOFF = 10112276
DS_FIELD = 0x164     # nand_squashfs data-size (u32 BE)
HASH_FIELD = 0x1d0   # nand_squashfs hash-1/value (32 bytes)


def rewrite(stock_path, new_sqfs_path, out_path):
    stock = open(stock_path, 'rb').read()
    header_and_bootfs = stock[:DATA_BASE + ROOTFS_DOFF]   # unchanged prefix
    sq = open(new_sqfs_path, 'rb').read()
    padded_size = (len(sq) + 4095) // 4096 * 4096
    blob = sq + b'\x00' * (padded_size - len(sq))
    out = bytearray(header_and_bootfs) + blob
    struct.pack_into('>I', out, DS_FIELD, padded_size)
    out[HASH_FIELD:HASH_FIELD + 32] = hashlib.sha256(blob).digest()
    open(out_path, 'wb').write(out)
    return len(sq), padded_size, hashlib.sha256(blob).hexdigest(), len(out)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    stock = sys.argv[3] if len(sys.argv) > 3 else \
        'ZenWiFi_XT9_3.0.0.4_388_24854-g9c246e8_nand_squashfs.pkgtb'
    s, p, h, tot = rewrite(stock, sys.argv[1], sys.argv[2])
    print(f"  squashfs {s} -> padded {p}  hash {h[:16]}...  total {tot} -> {sys.argv[2]}")
