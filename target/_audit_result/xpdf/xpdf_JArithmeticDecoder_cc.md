I have now completed a thorough analysis of the full file, all callers, and context. Here is my reasoning summary before the final output:

**JArithmeticDecoder.cc — analysis groups:**

**Group 1 (lines 20–48, Stats class):** `copyFrom` copies `this->contextSize` bytes from `stats->cxTab`; OOB read would require `stats->contextSize < this->contextSize`. All JBIG2Stream.cc callers verify both sizes equal before calling. `setEntry` lacks bounds check on `cx`, but all callers use compile-time constants (indices 0, 17, 18 vs `contextSize = jpxNContexts = 19`). No OOB.

**Group 2 (lines 87–183, readByte/start/restart/cleanup):** `readBuf[32]` writes guarded by `readBufLength < (int)sizeof(readBuf)`. `restart()` large-`k` loop is a logic concern (potential slow path), not memory corruption.

**Group 3 (lines 186–260, decodeBit/decodeByte):** No bounds check on `context` vs `contextSize`. `iCX = cxTab[context] >> 1` — `iCX` could reach 127, but `qeTab`/`nmpsTab`/`nlpsTab`/`switchTab` only have 47 entries. However, `cxTab` values are only ever set to values where `iCX <= 46`: `reset()` zeros all, `setEntry` callers use `i ≤ 46`, and `decodeBit`'s own writes use `nlpsTab`/`nmpsTab` (max 46). Invariant holds.

**Group 4 (lines 262–346, decodeInt/decodeIntBit/decodeIAID):** `decodeIntBit` keeps `prev` bounded to `[0x100, 0x1ff]` = max 511; all int-stats objects have `contextSize = 512`. Safe. `decodeIAID(codeLen, stats)`: `prev` grows to `(1<<(codeLen+1))-1`; requires `contextSize = 1<<(codeLen+1)`. `resetIntStats(symCodeLen)` correctly resizes `iaidStats` for `symCodeLen ≤ 29`. For `symCodeLen = 30-31` (UB: `1<<31` or `1<<32`), this would mis-size the table — but reaching `symCodeLen ≥ 30` requires `numInputSyms + numNewSyms ≥ 2^28+1`, which causes the preceding `gmallocn(numInputSyms+numNewSyms, 8)` to trigger `gMemError` (sanity check: `nObjs >= INT_MAX/objSize`). The UB path is never reached in practice.

**Group 5 (lines 348–369, byteIn):** Arithmetic only, no memory safety issue.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
