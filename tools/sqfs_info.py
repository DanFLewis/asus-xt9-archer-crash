#!/usr/bin/env python3
"""Locate and describe squashfs images embedded in an ASUS .pkgtb firmware file.

The .pkgtb is a FIT (flattened image tree) wrapper. The rootfs is a squashfs
blob at some offset inside it; this finds it and prints its superblock.

Usage:  python sqfs_info.py <firmware.pkgtb>
"""
import re
import struct
import sys

COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def main(path):
    data = open(path, "rb").read()
    print(f"{path}: {len(data)} bytes")

    for m in re.finditer(b"hsqs", data):
        off = m.start()
        hdr = data[off:off + 96]
        if len(hdr) < 96:
            continue
        (_magic, inodes, _mkfs, blocksize, _frags, comp,
         _blocklog, _flags, _ids, vmaj, vmin, _root, used) = struct.unpack_from(
            "<IIIIIHHHHHHQQ", hdr, 0)
        # a real superblock has sane values; garbage matches do not
        if vmaj != 4 or blocksize > (1 << 20):
            continue
        print(f"\nsquashfs at offset 0x{off:x} ({off})")
        print(f"  version    {vmaj}.{vmin}")
        print(f"  inodes     {inodes}")
        print(f"  blocksize  {blocksize}")
        print(f"  compressor {COMP.get(comp, comp)}")
        print(f"  bytes_used {used} ({used / 1024 / 1024:.1f} MB)")
        print(f"\n  carve with:")
        print(f"    data[{off}:{off + used}] -> rootfs.squashfs")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
