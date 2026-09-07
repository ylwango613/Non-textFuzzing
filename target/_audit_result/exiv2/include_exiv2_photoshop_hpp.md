I've completed a thorough multi-pass analysis of `photoshop.hpp`, `photoshop.cpp`, and all callers in `jpgimage.cpp`, `psdimage.cpp`, `pngimage.cpp`, and `tiffvisitor_int.cpp`. Summary of findings:

**`psSize` byte truncation** (photoshop.cpp:75-77): When Pascal string length byte = 0xFE or 0xFF, `psSize` wraps to 0, so `position` doesn't advance. However the subsequent `dataSize = getULong(pPsData + position, bigEndian)` reads the Pascal string length byte as the high byte (0xFE/0xFF), making `dataSize ≥ 0xFE000000`. The check `if (dataSize > (sizePsData - position))` always catches this for any sub-4GB buffer and returns -2. Callers handle -2 correctly — no OOB memory access.

**`sizeHdr + sizeIptc + (sizeIptc & 1)` in callers** (jpgimage.cpp:305, photoshop.cpp:46): `sizeHdr` is bounded to ≤265 and `sizeIptc` is bounded by `sizePsData`. For JPEG (max ~65535 bytes), no uint32_t overflow possible. For TIFF with huge buffers >4GB — theoretically possible but impractical.

**`dataSize + (dataSize & 1)`** uint32_t overflow when `dataSize = UINT32_MAX` and buffer >4GB: causes `position` to not advance → infinite loop (DoS), not memory corruption.

**psdimage.cpp parsing** uses `enforce()` bounds-checks at every step; no unsafe arithmetic found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
