# Deployment record

The patch was built, validated offline, and flashed to a live AiMesh node.

## Pipeline

| stage | result |
|---|---|
| Firmware download | official image, SHA-256 matches ASUS's published hash |
| Patch (`patch_ko.py`) | archer.ko +24 B, symbol value unchanged, ELF sound |
| Emulation (`verify.py`) | 8/8 on built .text, 7/7 re-run on .text from the .ko |
| Control-flow (`cfg.py`) | +0x218 dominates the sibling store; guard is sufficient and safe |
| Squashfs round-trip | byte-identical content (3,512 members) unmodified |
| FIT rewrite (`fit_rewrite.py`) | reproduces stock .pkgtb byte-for-byte |

## Device-acceptance test (the critical unknown)

Static analysis could not tell whether anything verifies a self-built image
beyond the FIT hash. So an **unmodified repack** was flashed first:

- Flashed to the AiMesh node via the router UI's per-node **manual Upload**
  (`Administration -> Firmware Upgrade -> AiMesh Node -> Upload`). No rescue
  mode needed.
- Node rebooted (~94 s) and rejoined the mesh healthy.
- => the device accepts self-repacked images. Green light for the patched one.

Note: a per-node manual upload exists in the UI and updates only the selected
node. AiMesh only re-syncs a node on version *mismatch*; the patched image
keeps the same version string, so it is not auto-reverted. `Auto Firmware
Upgrade` should be turned OFF so a future ASUS release doesn't overwrite it.

## Patched flash

- `XT9_archer_patched.pkgtb` uploaded to the same node.
- Reboot ~94 s (identical to the unmodified flash - no bootloop).
- 4-minute post-flash stability watch: **119 samples, 0 drops, median 6 ms,
  p90 7 ms**. Node held steady and stayed meshed.

## What is and isn't confirmed

- **Confirmed:** the node accepts and boots the patched image; it is stable.
- **Not observable:** the node reports the same version string whether stock or
  patched, so "the patch is live" can't be read from the UI. The only
  behavioural confirmation is the absence of an `archer` panic under mesh
  churn over time.
- The router itself was left on stock. Only the node carries the patch.
