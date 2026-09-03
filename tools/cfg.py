#!/usr/bin/env python3
"""Control-flow analysis of a function in an ARM kernel module.

Builds a CFG, reports reachability and dominance between two offsets, and
classifies every memory access through a chosen base register as guarded or
unguarded by a preceding `cmp <reg>, #0`.

NOTE: capstone renders conditional branches as `bne`/`beq`/... so successor
edges must be taken from ARM_INS_B plus the condition code, not from a
mnemonic string comparison. Following only unconditional `b` produces a
badly wrong CFG.

Usage:  python cfg.py <archer.ko> [fn_file_off_hex] [size_hex]
"""
import sys

from capstone import CS_ARCH_ARM, CS_AC_WRITE, CS_MODE_ARM, \
    CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm import ARM_CC_AL, ARM_INS_B, ARM_INS_CMP, ARM_INS_POP, \
    ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_IP


def build(path, fn_off, size):
    raw = open(path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    ins = list(md.disasm(raw[fn_off:fn_off + size], 0))
    return ins, {i.address: n for n, i in enumerate(ins)}


def succs(ins, idx, i):
    out = []
    n = idx[i.address]
    is_ret = i.id == ARM_INS_POP and 'pc' in i.op_str
    is_b = i.id == ARM_INS_B
    uncond = is_b and i.cc == ARM_CC_AL
    if is_b and i.op_str.startswith('#'):
        try:
            tgt = int(i.op_str[1:], 16)
            if tgt in idx:
                out.append(tgt)
        except ValueError:
            pass
    if not uncond and not is_ret and n + 1 < len(ins):
        out.append(ins[n + 1].address)
    return out


def reach(ins, idx, start, avoid=None):
    seen, stack = set(), [start]
    while stack:
        a = stack.pop()
        if a in seen or a not in idx or a == avoid:
            continue
        seen.add(a)
        stack += succs(ins, idx, ins[idx[a]])
    return seen


def main(path, fn_off=0x1327c, size=0x768):
    ins, idx = build(path, fn_off, size)
    r = reach(ins, idx, 0)
    print(f"reachable: {len(r)}/{len(ins)} instructions")

    print("\n=== memory accesses through ip(r12) ===")
    derefs = []
    for i in ins:
        for op in i.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_IP:
                derefs.append(i.address)
                print(f"  +0x{i.address:04x}: {i.mnemonic:<7} {i.op_str}")

    print("\n=== guard status ===")
    for addr in derefs:
        guarded, via = False, None
        for j in range(idx[addr] - 1, -1, -1):
            a = ins[j]
            rewrites = any(
                op.type == ARM_OP_REG and op.reg == ARM_REG_IP
                and op.access & CS_AC_WRITE for op in a.operands)
            if (a.id == ARM_INS_CMP
                    and a.operands[0].type == ARM_OP_REG
                    and a.operands[0].reg == ARM_REG_IP
                    and a.operands[1].type == ARM_OP_IMM
                    and a.operands[1].imm == 0):
                guarded, via = True, a.address
                break
            if rewrites:
                via = a.address
                break
        state = (f"guarded by cmp @+0x{via:04x}" if guarded
                 else f"NO CHECK (ip set @+0x{via:04x})" if via
                 else "NO CHECK")
        print(f"  +0x{addr:04x}: {state}")

    if len(sys.argv) > 4:
        a, b = int(sys.argv[3], 16), int(sys.argv[4], 16)
        without = reach(ins, idx, 0, avoid=a)
        print(f"\n0x{b:x} reachable without 0x{a:x}: {b in without}")
        print(f"  -> 0x{a:x} {'DOMINATES' if b not in without else 'does not dominate'} 0x{b:x}")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'archer.ko',
         int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x1327c,
         0x768)
