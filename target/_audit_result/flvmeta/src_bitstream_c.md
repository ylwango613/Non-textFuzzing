I've now fully analyzed `bitstream.c` and its complete call chain. Let me document my findings for each function:

**`skip_bits()`** (line 9–12): Advances `bb->current` without a bounds check. However, all callers in `avc.c` pass small compile-time constants (8, 16, 1), so no attacker-controlled value reaches `nbits`. Subsequent `get_bit()` calls detect any over-advance via the `bb->current - bb->start > bb->size - 1` check and return -1.

**`get_bit()`** (line 14–30): Correctly bounds-checks before every dereference. Safe.

**`get_bits()`** (line 32–50): Clamps `nbits` to `sizeof(uint32)*8 = 32` before the loop. Safe.

**`exp_golomb_ue()`** (line 52–73): Real C UB — `1 << significant_bits` when `significant_bits` (uint8, can reach 255) exceeds 31 is a signed left-shift UB. However, tracing all uses of the return value in `avc.c` shows it's only used for: discarded calls, comparisons (`== 3`), a loop counter (DoS path only — buffer exhausts fast), and width/height arithmetic (no memory operations). No memory corruption is reachable.

**`avc.c:242` — `body_length - 12` underflow**: When `body_length` is 10 or 11 (passes line 205 gate), `body_length - 12` wraps to `UINT32_MAX-1` or `UINT32_MAX`, bypassing the `sps_size` validation. However `sps_size` is `uint16` (max 65535), `malloc(sps_size)` allocates exactly that, and `flv_read_tag_body` reads exactly `sps_size` bytes — no heap overflow follows.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
