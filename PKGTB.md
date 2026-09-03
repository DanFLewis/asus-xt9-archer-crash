# The `.pkgtb` firmware container

The XT9 firmware `.zip` contains a single `.pkgtb`: a **FIT** (Flattened Image
Tree) with external data. The tree is a small flattened device-tree blob; the
actual images sit after it, referenced by offset/size.

## Layout (reverse-engineered, then verified)

```
[0        : 936]        FIT header (DTB, totalsize 933) + pad to 936 = data base
[936      : 10113212]   bootfs blob   data-offset 0          size 10112276
[10113212 : EOF]        rootfs blob   data-offset 10112276   size (4096-padded)
```

The FIT references each image by `data-offset` (relative to the 936-byte data
base) and `data-size`, and carries a `hash-1` node per image:

```
images/bootfs_6756_a0+   data-size, data-offset, hash-1{ algo=sha256, value }
images/nand_squashfs     data-size, data-offset, hash-1{ algo=sha256, value }
configurations/...       (Brcm Image Bundle)
```

Key header field offsets (this exact build):

| field | file offset | encoding |
|---|---|---|
| `nand_squashfs` data-size | `0x164` | u32 big-endian |
| `nand_squashfs` hash-1/value | `0x1d0` | 32 raw bytes |

## Hash convention (the detail that matters)

- `data-size` = `roundup(squashfs_bytes, 4096)`. The rootfs blob is zero-padded
  to a 4 KiB boundary.
- The `hash-1/value` is `sha256` of the **padded** blob, **not** the raw
  squashfs. Confirmed by recomputing both against the stock stored hash.
- There is **no signature node** (no `signature`, `rsa`, or `key`). Integrity
  only. A rebuilt rootfs needs its SHA-256 recomputed; no signing key.

## Correctness proof

`fit_rewrite.py` was validated by re-wrapping the *original* carved squashfs
and confirming the result is **byte-identical** to the stock `.pkgtb` (same
SHA-256). Only then was it trusted with a modified rootfs.

And empirically: an unmodified self-repack flashed to an AiMesh node was
accepted and booted, so nothing outside the FIT hash gates a self-built image
on this platform. See `DEPLOYMENT.md`.

## Repack round-trip

Windows-native `squashfs-tools-ng` (no WSL) does a metadata-preserving
round-trip via tar:

```bash
sqfs2tar rootfs.squashfs > rootfs.tar          # preserves 719 symlinks, modes
# ... swap archer.ko in the tar ...
tar2sqfs -c xz -b 131072 -f rootfs_new.squashfs < rootfs_new.tar
```

An unmodified round-trip was verified byte-for-byte at the content level: all
3,512 members (2,565 files by SHA-256, 719 symlink targets, every mode) match.
