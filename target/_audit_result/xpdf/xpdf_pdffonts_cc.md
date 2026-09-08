**Analysis complete.** The file is 468 lines. Key findings from each section:

- **Lines 31-44** `fontTypeNames[]`: 12 entries (indices 0–11). The `GfxFontType` enum has exactly 12 values (`fontUnknownType`=0 … `fontCIDType2OT`=11). All possible `font->getType()` values map into valid array slots — no OOB.

- **Lines 179-183** `seenObjs` allocation: `gmalloc(numObjects)` where `numObjects = last + 1`. `gmalloc` rejects negative sizes via `gMemError`. If `numObjects = 0`, gmalloc returns NULL; `memset(NULL, 0, 0)` is benign.

- **Lines 449-468** `checkObject`: Bounds check `objNum < 0 || objNum >= numObjects` correctly guards every access to `seenObjs[objNum]`. Out-of-bounds refs return a null object (not a memory error).

- **Lines 437-446** `fonts` array growth: `fontsSize` overflow is explicitly guarded (`fontsSize <= INT_MAX - 32`), and the intentional `fontsSize = -1` path causes `greallocn` to call `gMemError` (throws/exits), never reaches the write at `fonts[fontsLen++]`.

- **`greallocn`**: Correctly rejects `nObjs < 0` and `nObjs >= INT_MAX / objSize`, preventing integer overflow in allocation size.

- Recursive `scanFonts` cycles are broken by `seenObjs` tracking reference objects. No unbounded recursion for reference-linked structures.

No directly exploitable memory safety vulnerabilities exist within `pdffonts.cc` itself.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
