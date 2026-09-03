#!/usr/bin/env python3
"""Verify the NULL-guard patch by emulating both paths with Unicorn.

.text is mapped at a NON-ZERO base so address 0 stays unmapped: a NULL store
then genuinely faults instead of silently succeeding. fp is poisoned first so
that fp==0 can only be the patch's deliberate write.

Run build_patch.py first.

Usage:  python verify.py
"""
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, \
    UC_MODE_LITTLE_ENDIAN, Uc, UcError
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R7, UC_ARM_REG_R11, \
    UC_ARM_REG_R12, UC_ARM_REG_SP

BASE, SCRATCH, STACK = 0x40000000, 0x50000000, 0x60000000
FN = 0x1320c
FAULT, RESUME, EPILOGUE = FN + 0x218, FN + 0x21c, FN + 0x194
POISON = 0x41414141


def run(image, ip_val, r7=0, r0=0xDEADBEEF, label=""):
    code = open(image, 'rb').read()
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(BASE, ((len(code) + 0xFFF) & ~0xFFF) + 0x1000)
    uc.mem_write(BASE, code)
    uc.mem_map(SCRATCH, 0x1000)
    uc.mem_map(STACK, 0x10000)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x8000)
    uc.reg_write(UC_ARM_REG_R12, ip_val)
    uc.reg_write(UC_ARM_REG_R7, r7)
    uc.reg_write(UC_ARM_REG_R0, r0)
    uc.reg_write(UC_ARM_REG_R11, POISON)

    trace = []

    def hook(u, addr, _size, _user):
        trace.append(addr - BASE)
        if addr in (BASE + RESUME, BASE + EPILOGUE):
            u.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    fault = None
    try:
        uc.emu_start(BASE + FAULT, BASE + len(code), count=40)
    except UcError as exc:
        fault = str(exc)

    res = {
        'trace': trace,
        'landed': trace[-1] if trace else None,
        'fp': uc.reg_read(UC_ARM_REG_R11),
        'scratch': int.from_bytes(uc.mem_read(SCRATCH + (r7 << 5), 4), 'little'),
        'fault': fault,
    }
    print(f"\n=== {label} ===")
    print("  path:", " -> ".join(f"0x{a:05x}" for a in trace[:10]))
    print(f"  fp   : 0x{res['fp']:08x}   "
          f"[scratch+{r7 << 5}] : {res['scratch']:#010x}")
    print(f"  fault: {res['fault']}")
    return res


def main():
    ctl = run('text_orig.bin', 0, label="CONTROL: original, ip=0")
    a = run('text_patched.bin', 0, label="patched, ip=0")
    b = run('text_patched.bin', SCRATCH, r7=0, label="patched, ip=valid, r7=0")
    c = run('text_patched.bin', SCRATCH, r7=2, label="patched, ip=valid, r7=2")

    checks = [
        ("original faults on NULL", ctl['fault'] is not None),
        ("patched: NULL -> no fault", a['fault'] is None),
        ("patched: NULL -> reaches epilogue", a['landed'] == EPILOGUE),
        ("patched: NULL -> fp == 0", a['fp'] == 0),
        ("patched: valid -> no fault", b['fault'] is None),
        ("patched: valid -> resumes at +0x21c", b['landed'] == RESUME),
        ("patched: valid -> store landed", b['scratch'] == 0xDEADBEEF),
        ("patched: r7=2 -> store at +0x40", c['scratch'] == 0xDEADBEEF),
    ]
    print("\n" + "=" * 56 + "\nVERDICT\n" + "=" * 56)
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    print(f"\n{sum(1 for _, p in checks if p)}/{len(checks)} checks passed")


if __name__ == '__main__':
    main()
