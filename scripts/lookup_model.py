#!/usr/bin/env python3
"""Access-shape model of the two-table lookup.

Correctness is checked by scripts/run-hosttest.sh, which compiles the real policy.c. This
model only states what the C cannot easily assert about itself: which addresses a query
touches, and how many, as a function of (caller, target) alone -- never of the policy
contents.
"""

WAY = 8          # target slots per 64-byte line
CLINE = 8        # caller slots per 64-byte line
GOLD = 0x9E3779B97F4A7C15
M64 = (1 << 64) - 1


def phash(caller, target, shift):
    return ((((target << 32) | caller) * GOLD) & M64) >> (32 + shift)


def caller_line(caller, cshift):
    return phash(caller, 0x5BD1E995, cshift)


def mirror_unit(target, bits=7):
    """The kernel's own bucket line: uid_hash(target) >> 3, 8 buckets per line."""
    return (((target >> bits) + target) & ((1 << bits) - 1)) >> 3


def loads(nmask_words, lines=16):
    """Loads per query: caller line + target slots + every mask of that line."""
    return CLINE + WAY * 1 + WAY * nmask_words, lines * WAY * (1 + nmask_words) * 8


print('which addresses a query touches:')
print('  caller line  : phash(caller)            -> depends on the caller only')
print('  target slots : uid_hash(target) >> 3    -> the kernel\'s own bucket line')
print('  masks        : every mask of that line  -> read whether or not a slot matches')
print('  -> for a fixed (caller, target) the address set and the load count are constant,')
print('     so hidden / absent / out-of-range answers read exactly the same words.')

for nh, tag in ((7, 'device policy (7 callers)'), (400, 'uid-scale callers (400)')):
    nmw = max(1, (nh + 63) // 64)
    l, bytes_ = loads(nmw)
    print(f'  {tag:28s} mask words={nmw}  loads/query={l:3d}  table={bytes_} B')

print('\ncaller capacity: POLICY_MAX_CALLERS = 4096 (same scale as uids)')
for nh in (7, 64, 400, 4096):
    nmw = max(1, (nh + 63) // 64)
    print(f'  {nh:5d} callers -> masks {nmw:2d} word(s), loads/query={loads(nmw)[0]}')
