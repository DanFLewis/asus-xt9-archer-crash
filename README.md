# archer_dhd_tx_packet NULL-pointer panic (BCM96756)

Root-cause analysis of a reproducible kernel panic in Broadcom's `archer`
packet accelerator, as shipped on the ASUS ZenWiFi XT9.

At the time of writing, searching for `archer_dhd_tx_packet` returns nothing.
This is an attempt to document it.

## Environment

| | |
|---|---|
| Device | ASUS ZenWiFi XT9 (AX7800 tri-band) |
| SoC | Broadcom **BCM96756**, ARM32 |
| Kernel | 4.19.183 |
| Firmware | 3.0.0.4.388_24854 (2026-08-04) |
| Module | `/lib/modules/4.19.183/extra/archer.ko` |
| Topology | 2-node AiMesh, **wireless** backhaul |

The same `archer` driver ships on other BCM6756 platforms (e.g. RT-AXE7800),
so the defect is likely not XT9-specific.

## The panic

```
Unable to handle kernel NULL pointer dereference at virtual address 00000000
pgd = 93bf97c6   [00000000] *pgd=00000000
Internal error: Oops: 805 [#1] PREEMPT SMP ARM
CPU: 3 PID: 382 Comm: bcm_archer_us  Tainted: P           O      4.19.183 #1
PC is at archer_dhd_tx_packet+0x218/0x768 [archer]
LR is at 0x2
pc : [<bf141424>]    lr : [<00000002>]    psr: 20000013
sp : dbfe7e58  ip : 00000000  fp : 00000000
r10: 00000000  r9 : 00000000  r8 : bf15d4a8
r7 : 00000000  r6 : 114725c0  r5 : 000005d6  r4 : d7338000
Kernel panic - not syncing: Fatal exception
```

The crashlog is emitted at next boot before NTP sync, so it carries a
meaningless `Dec 31` timestamp.

## Faulting instruction

`archer_dhd_tx_packet` resolves to `.text+0x1320c`, size `0x768` — matching
`+0x218/0x768` in the trace. ARM mode, not Thumb.

```asm
+0x01f4:  09c09ce7   ldr    ip, [ip, sb]          ; ip = *(D3LUT base + offset)
+0x01f8:  918e21e0   mla    r1, r1, lr, r8        ; stride 0x2d0 element array
+0x0200:  baafbfe6   rev16  sl, sl
+0x0204:  5a94e3e7   ubfx   sb, sl, #8, #4        ; 4-bit field from a header word
+0x020c:  829289e1   orr    sb, sb, r2, lsl #5
+0x0214:  6c1091e5   ldr    r1, [r1, #0x6c]
+0x0218:  87028ce7   str    r0, [ip, r7, lsl #5]  ; <-- PANIC PC
```

With `ip = 0` and `r7 = 0`, the destination is `0 + (0 << 5)` = address `0`.
It is a **write**, not a read.

`ip` is loaded at `+0x1f4` from a pointer table and stored to at `+0x218`
**with no NULL check in between**. The intervening instructions are
straight-line arithmetic containing no branch.

This is not a general absence of defensive coding: the same function performs
15 zero-compares elsewhere, including `cmp ip, #0` at `+0x138`, `+0x3b4` and
`+0x5e8`. The check is simply missing on this path.

## The table is D3LUT — keyed by station MAC

The pointer comes from Broadcom's **D3LUT** (destination/3-address lookup
table), exported by `bcmlibs.ko` and consumed by `dhd.ko`:

```
bcmlibs.ko : d3lut_ins  d3lut_del  d3lut_lkup  d3lut_clr  d3lut_get
             d3lut_e2k  d3lut_k2e  d3lut_dump  d3lut_policy_set  [d3lut_elem]
dhd.ko     : _d3lut_find_sta   d3lut_lkup   dhd_awl_pktlist_add
```

`e2k` / `k2e` are element-to-key / key-to-element, and `_d3lut_find_sta`
resolves a **station**. The key is a station MAC address.

## Trigger

The panic is preceded by forwarding-table churn — a station's interface
binding being rewritten repeatedly:

```
br2: port 8(wds2.0.1.502) received tcn bpdu     (x8, repeating)
br2: topology change detected, propagating
wl_pktfwd_lut_ins: DA=SYM<NODE_BSSID> to roam from eth4 to wds0.0.1.
wl_pktfwd_lut_ins: DA=SYM<NODE_BSSID> to roam from wds0.0.1 to eth4.
<PANIC>
```

A `d3lut_del` during WDS instability leaves a slot NULL that an in-flight TX
can still index. The missing check at `+0x218` turns that race into a panic.

Note the LUT churn is on the **base** interfaces (`eth4`, `wds0.0.1`), while
the STP storm is on the `.502` VLAN subinterface. `wds0.0.1.502` is a VLAN
subinterface *of* `wds0.0.1` — the same physical link — so both are symptoms
of one underlying WDS instability rather than cause and effect.

## Return convention

All 7 internal call sites (`archer_socket_task_handler`,
`archer_dhd_rx_complete_task_handler`, `archer_dma_task_rx_handler`,
`archer_dpi_transmit`) share one pattern:

```asm
bl   archer_dhd_tx_packet
cmp  r0, #0
bne  <continue>          ; non-zero: packet consumed, caller moves on
                         ; zero falls through to disposal:
  mov r0, r7 ; bl <helper>                     (rx_complete)
  ldr r3,[sp,#0x48]; mov r0,r7; ldr r3,[r3,#0x10]; blx r3   (socket: free cb)
  ldr r0,[sp,#0x20]; ... ; str sb,[r2,r3,lsl #2]            (dma: recycle)
```

**Return 0 = "not consumed, caller disposes." Non-zero = consumed.**

That makes the correct guard well-defined — return 0 and let the caller free:

```c
if (ip == 0) { fp = 0; goto epilogue; }   /* +0x194: mov r0, fp ; pop {..., pc} */
else          str r0, [ip, r7, lsl #5];
```

The function has a **single** exit at `+0x194` and calls no free/drop helper
itself — its only calls are `archer_dhd_buffer_table_try_write`,
`bcm_timer_*`, and `__stack_chk_fail`. Packet ownership is entirely decided
by the return value.

## Why an in-place binary patch is blocked

The guard does not fit in the 4 bytes available at `+0x218`, so it needs a
code cave. **There is none:**

- `.text` is 121,712 bytes with **zero** runs of >= 8 zero bytes anywhere.
- `.exit.text` (292 B) and `.text.unlikely` (124 B) contain live code, and are
  separate sections — the module loader decides their placement at load time,
  so a hardcoded inter-section branch offset would be wrong without adding a
  relocation entry.

Growing `.text` means shifting every subsequent section offset and fixing all
relocations — invasive ELF surgery with no way to validate before it runs.

Rebuilding from ASUS GPL source is separately blocked: ASUS omits the
model-specific prebuilt objects (`api-broadcom.o`, `tcode.o`, `amas_utils.o`,
`private.o`) from public GPL drops, and `amas_utils.o` is the AiMesh
component. See the RT-AXE7800 / BCM6756 porting research on SNBForums.

Note the firmware image itself carries **SHA-256 hashes but no cryptographic
signature** (no `signature`/`rsa`/`key` node in the FIT; trailing bytes are
zero padding), so repacking is not gated by a signing key — only by the
above.

## Mitigations that do not require patching

The defect needs D3LUT churn to fire, so anything that stabilises the mesh
reduces the trigger rate without fixing the bug:

- Pin the wireless backhaul to a channel that can actually bond. ASUS `Auto`
  may select ch165, which is **20 MHz-only** in UNII-3 and silently caps a
  `20/40/80` setting — a saturated backhaul drives association churn.
- A wired (or MoCA) backhaul removes WDS entirely.
- `ctf_disable=1` disables **NAT/flow-cache** acceleration (GUI: LAN ->
  Switch Control). Note this does **not** disable the Archer WLAN path —
  that is compile-time (`BRCM_DRIVER_ARCHER_WLAN=y`, `BUILD_BCM_PKTFWD=y` in
  `/rom/etc/96756GW`) — so it is unlikely to prevent this specific panic.

## Reproducing the analysis

See `tools/`. No Linux required; extraction is pure Python.

```bash
pip install --user PySquashfsImage capstone pyelftools
python tools/sqfs_info.py   <firmware.pkgtb>   # locate the squashfs
python tools/disasm.py      <archer.ko>        # disassemble the crash site
```

## Status

The defect is characterised; **no fix is available.** Reported here in case
it is useful to anyone else seeing `bcm_archer_us` panics on BCM6756.
