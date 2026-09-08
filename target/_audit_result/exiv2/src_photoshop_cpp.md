Having completed the full analysis of `photoshop.cpp`:

**Summary of findings:**

1. **Pascal string `psSize` uint8_t truncation (lines 75-77):** When `pPsData[position]` equals 254 or 255, the `byte psSize` value wraps to 0 due to uint8_t overflow, causing `position` to not advance past the Pascal string. However, `dataSize` is then read from the Pascal string length byte (0xFE or 0xFF), making it ≥ 0xFE000000 (~4.2 GB). The bounds check at line 87 (`dataSize > sizePsData - position`) always catches this for any real-world buffer size and returns -2. Not exploitable as a memory safety bug.

2. **`sizeHdr` / `sizeData` returned to callers:** In all call sites (`jpgimage.cpp:303`, `pngchunk_int.cpp:243`, `tiffvisitor_int.cpp:337`, `preview.cpp:435`), the invariant `sizeData <= sizePsData - sizeHdr` is guaranteed by `locateIrb`'s check, so `record + sizeHdr + sizeData` always falls within the buffer boundary.

3. **`position += dataSize + (dataSize & 1)` loop continuation (line 110):** The `(dataSize & 1)` padding could advance position one byte past the last byte, but only to `sizePsData + 1` at most; the loop condition `position <= sizePsData - 12` immediately exits, and `isIrb` is not called.

4. **`isIrb` 4-byte read (lines 31-35):** Always called with `position <= sizePsData - 12` guaranteed, so the 4-byte read is always in bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
