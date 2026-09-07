I have completed a thorough multi-pass audit of `tif_swab.c` (243 lines) and all its callers in the core library. Let me summarize my findings:

**Group 1 (lines 1–131): Swab functions**
- `TIFFSwabShort`, `TIFFSwabLong`: fixed-size byte swaps on caller-supplied pointers — no issue.
- `TIFFSwabArrayOfShort`, `TIFFSwabArrayOfTriples`, `TIFFSwabArrayOfLong`: iterate `n` times; `n` and buffer size must match — correctness is a caller contract, not an internal bug.
- `TIFFSwabDouble`: calls `TIFFSwabArrayOfLong(lp, 2)` with fixed count — no issue.
- **`TIFFSwabArrayOfDouble` line 125**: `TIFFSwabArrayOfLong(lp, n + n)` — on a 32-bit system with `unsigned long = 32-bit`, `n >= 2^31` would cause `n + n` to wrap to 0 or a small value, then the subsequent `while (n-- > 0)` loop would OOB-access the buffer far past its end.

**Tracing all callers of `TIFFSwabArrayOfDouble`:**
1. `tif_dirread.c:1285` — immediately preceded by `if (!dir->tdir_count || !w || cc / w != dir->tdir_count) goto bad;`, which limits `dir->tdir_count` (w=8 for TIFF_DOUBLE) to ≤ `0x1FFFFFFF` on 32-bit. Max `n + n = 0x3FFFFFFE` — no overflow.
2. `_TIFFSwab64BitData` via `tif_read.c:740` with `cc/8` — `cc` comes from `TIFFVStripSize` / `TIFFScanlineSize` which clamp to 0 on overflow and are bounded to ≤ 2^29 by the `TIFFhowmany8(multiply(...))` chain — always non-negative.
3. On the **64-bit target system** (`unsigned long = 64 bits`), `n = dir->tdir_count` at most `0xFFFFFFFF`, so `n + n = 0x1FFFFFFFE` — mathematically impossible to overflow a 64-bit `unsigned long`.

**Group 2 (lines 133–243): Bit-reversal tables and `TIFFReverseBits`**
- Table lookups are `TIFFBitRevTable[cp[i]]` where `cp[i]` is `unsigned char ∈ [0, 255]` and the table has exactly 256 entries — no OOB.
- Loop logic subtracts 8 per iteration then handles the remainder — correct.

**Conclusion**: On the audit target (64-bit Linux, tiffsplit using core libtiff), every potential overflow in `tif_swab.c` is either architecturally impossible or definitively blocked by an explicit upstream bounds check (`cc / w != dir->tdir_count`). No externally-triggerable memory safety vulnerability exists in this file or its core-library call paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
