# Guard patch — verified in emulation, NOT deployed

> Supersedes the "Status" section of the README: a patch now exists and is
> verified against an emulator. It has **not** been flashed to hardware.

## What it does

Redirects the unguarded store at `archer_dhd_tx_packet+0x218` through a NULL
check. On NULL it returns `0` — which every caller treats as *"packet not
consumed, caller disposes"* — instead of writing to address `0`.

```c
if (ip == 0) { fp = 0; goto epilogue; }   /* caller frees the packet */
else          str r0, [ip, r7, lsl #5];   /* original behaviour */
```

## Mechanics

There is **no existing code cave** — `.text` is 121,712 bytes with zero runs
of >= 8 zero bytes. So the cave is *appended* to `.text`, which grows the
section by 24 bytes.

Appending (rather than reusing `.exit.text`) matters: the cave then lives in
the **same section** as the patch site, so the module loader keeps them
contiguous and a PC-relative `b` is valid **without adding a relocation**.
Existing relocations and symbol values are section-relative and are unaffected
by an append.

```asm
; patch site
0x13424: b      #0x1db70          ; was: str r0, [ip, r7, lsl #5]

; cave at .text+0x1db70
0x1db70: 00005ce3   cmp    ip, #0
0x1db74: 0100000a   beq    #0x1db80
0x1db78: 87028ce7   str    r0, [ip, r7, lsl #5]   ; original, relocated
0x1db7c: 29d6ffea   b      #0x13428               ; resume (+0x21c)
0x1db80: 00b0a0e3   mov    fp, #0                 ; return 0 = not consumed
0x1db84: 05d6ffea   b      #0x133a0               ; epilogue (+0x194)
```

Remaining ELF work to produce a loadable module: bump `.text` `sh_size`,
shift `sh_offset` of following sections, fix `e_shoff`.

## Verification

`tools/verify.py` executes both paths under Unicorn. `.text` is mapped at a
non-zero base so **address 0 stays unmapped** — a NULL store genuinely faults
rather than silently succeeding. `fp` is poisoned to `0x41414141` beforehand,
so `fp == 0` can only be our deliberate write.

```
[PASS] original faults on NULL              UC_ERR_WRITE_UNMAPPED at 0x13424
[PASS] patched: NULL -> no fault
[PASS] patched: NULL -> reaches epilogue    0x13424 -> cave -> 0x133a0
[PASS] patched: NULL -> fp == 0
[PASS] patched: valid -> no fault
[PASS] patched: valid -> resumes at +0x21c  0x13424 -> cave -> 0x13428
[PASS] patched: valid -> store landed       [ip]      == 0xdeadbeef
[PASS] patched: r7=2 -> store at +0x40      [ip+0x40] == 0xdeadbeef

8/8 checks passed
```

The **control** case is the important one: the unmodified binary faults in the
emulator exactly as it does on hardware, which is what makes the harness
credible rather than merely green.

Note `fp` is left untouched on the normal path — the patch only writes it when
bailing.

## What this does NOT establish

- **Emulation is not kernel context.** It proves control flow and register
  effects. It models no concurrency, DMA, allocator, or locking.
- **It is a defensive fix, not a cure.** It stops the consumer dereferencing
  NULL; it does not fix whatever lets `d3lut_del` race a TX in flight.
  Packets will still be dropped during churn — dropped instead of panicking.
- **Unresolved:** whether the same NULL `ip` is dereferenced again between
  `+0x218` and the next `cmp ip, #0` at `+0x3b4`. If so the guard must bail
  earlier or cover more ground.
- **Unresolved:** whether other `d3lut_lkup` consumers share the race. This
  fixes the instance that was observed, not the class.
- The image carries SHA-256 hashes but **no signature**, so repacking is not
  gated by a key — but whether the bootloader or web UI verifies anything
  outside the FIT is **untested**.

## Before this should go near hardware

1. Repack and flash an **unmodified** image first — tests whether verification
   exists outside the FIT, and costs nothing if it fails.
2. Rehearse recovery (rescue mode + Firmware Restoration) *before* needing it.
3. Flash the **mesh node**, not the router — a failure then costs a node, not
   the network.
4. Finish the control-flow analysis of the two unresolved items above.

## Reproducing

```bash
pip install --user capstone pyelftools unicorn
python tools/build_patch.py    # writes text_orig.bin, text_patched.bin
python tools/verify.py         # runs the 8 checks
```
