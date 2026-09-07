**Batch 1 (lines 0–415) findings:**

- `MemReader` / `FileReader` / `StreamReader`: all `getByte`, `getU16BE`, `getU32BE`, `getU32LE`, `getUVarBE`, `cmp` methods perform bounds checks before any array access. No OOB possible through the Reader API.
- `StreamReader::fillBuf` (lines 371–415): internal `char buf[1024]`. After any memmove or discard-loop branch, the final while writes `buf[bufLen++]` only while `bufLen < len ≤ sizeof(buf)`, so no overflow of the internal buffer.

**Batch 2 (lines 531–642) findings:**

- `identifyOpenType`: `nTables` is U16 (max 65535), `12 + i*16` max ≈ 1,048,556 — no int32 overflow.
- `identifyCFF` line 591: `pos += 3 + (n+1)*offSize1 + (int)offset1 - 1` — `(n+1)*offSize1` max = 262144, `offset1` ≤ INT_MAX (checked), so this can produce signed-int overflow (UB), but the subsequent `if (pos < 0)` guard and the Reader's own bounds checks prevent memory corruption; worst case is wrong font-type identification.
- Lines 612–613 also have the same overflow pattern and a logic bug (endPos computed from already-updated pos), but again the Reader bounds-checks all subsequent reads. No memory corruption path.

**Batch 3 (lines 670–797) findings:**

- `nFonts`, `nTables`, `nNames`, `stringLength` all gated by file-length checks or U16 domain (max 65535).
- `gmallocn(nTables, 16)` / `gmallocn(nNames, 12)`: `nTables` max 65535 × 16 = 1 MB; `nNames` max 65535 × 12 = 786 KB — checked against `fileLength` before allocation, and `gmallocn` itself does multiplication-overflow checking.
- `stringOffset` at lines 767–768 can theoretically overflow int if `nameTabOffset` is near INT_MAX, but the subsequent `stringOffset < 0` check and Reader bounds-checking prevent OOB reads or writes.
- `buf2[j] = buf2[2*j+1]` (line 783): allocated size is `stringLength` (before /= 2), max index is `2*(stringLength/2 - 1)+1 = stringLength - 1`. Safe.

**Batch 4 (lines 799–885) findings:**

- `resMapLength` is capped at 32768 (line 826–829) before `gmalloc(resMapLength)`.
- All index arithmetic into `resMap[]` is validated against `resMapLength` before access.
- `nameLen = resMap[offset]` (byte, max 255), `offset + 1 + nameLen` checked against `resMapLength`. Safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
