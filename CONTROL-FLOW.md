# Control-flow analysis — are there sibling defects?

Resolves the two questions left open in `PATCH.md`.

## All `ip`-based memory accesses in `archer_dhd_tx_packet`

| offset | insn | status |
|---|---|---|
| `+0x0144` | `strne r1, [ip, #0xc]` | guarded by invariant (count != 0 => head valid) |
| `+0x01f4` | `ldr ip, [ip, sb]` | the D3LUT lookup itself |
| `+0x0218` | `str r0, [ip, r7, lsl #5]` | **the bug — patched** |
| `+0x02a4` | `strh r1, [ip, r0]` | **unguarded store through a loaded pointer** |
| `+0x03c0` | `ldr r8, [ip, #4]` | guarded by `cmp ip,#0` @ `+0x3b4` |
| `+0x03c8` | `ldr r0, [ip]` | guarded @ `+0x3b4` |
| `+0x03cc` | `ldrh r1, [ip, #8]` | guarded @ `+0x3b4` |
| `+0x03d4` | `ldrh ip, [ip, #0xa]` | guarded @ `+0x3b4` |
| `+0x05cc` | `ldr r1, [ip, #4]` | computed address (`r8 + r1*0x2d0`), not a loaded pointer |
| `+0x05e0` | `str lr, [ip, #4]` | same |
| `+0x05f4` | `strne r1, [ip, #0xc]` | guarded by invariant |

`+0x02a4` is structurally identical to the bug — load a pointer out of a
struct, immediately store through it, no check:

```asm
+0x02a0:  ldr   ip, [r2, #0x68]
+0x02a4:  strh  r1, [ip, r0]
```

## Dominance: `+0x218` dominates `+0x2a4`

Complete CFG over the function (474/474 instructions reachable from entry;
conditional branches included — an earlier pass that followed only
unconditional `b` wrongly reported the crash site as unreachable):

```
0x2a4 reachable from entry            : True
0x2a4 reachable WITHOUT passing 0x218 : False
  => 0x218 DOMINATES 0x2a4
```

### Consequence 1 — the guard is sufficient for the observed bug

When the D3LUT pointer is NULL, the patch bails to the epilogue at `+0x218`,
so `+0x2a4` is never reached. The failure mode that was actually observed
cannot reach the sibling.

### Consequence 2 — `+0x2a4` must NOT get the same guard

Because `+0x218` dominates it, reaching `+0x2a4` means the store at `+0x218`
already executed — the packet pointer is written into the table slot. That is
the handoff.

Bailing at `+0x2a4` with `fp = 0` would tell the caller *"not consumed, you
free it"* for a buffer already committed to the ring: **a double free**, which
is strictly worse than the panic being fixed.

If `[r2+0x68]` can independently be NULL it remains a latent defect, but it
needs a different remedy (skip-and-continue, not return-0) with its own
justification. No evidence it has ever fired.

## Verdict

**Ship the `+0x218` guard as-is. Do not extend it to `+0x2a4`.**

## Limits of this analysis

- Constant-propagation of `fp` returned *unknown* at both sites, because `fp`
  is loaded from memory at `+0xf8` (`ldr fp, [r4, #0x20]`). The dominance
  argument stands on its own; the return value was not independently
  confirmed analytically.
- The CFG models direct branches only. No indirect intra-function jumps were
  observed, but their absence was not exhaustively proven.
- Whether other `d3lut_lkup` consumers elsewhere in the driver share the race
  is still unexamined.
