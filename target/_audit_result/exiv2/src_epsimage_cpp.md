After a complete multi-pass read and analysis of all 1133 lines of `epsimage.cpp`, covering:

**Batch 1 (lines 1–400):** DOS EPS header parsing, `getULong`-derived offsets, `enforce` guards, `readLine`/`readPrevLine`, `findXmp` inner loop bounds.

**Batch 2 (lines 400–800):** Comment-scan loop, all `posXxx` assignments, `removableEmbeddings` tracking, XMP trailer search, AI7 thumbnail `size_` computation, Photoshop section bounds.

**Batch 3 (lines 800–1133):** Write-path `writeTemp(data + prevSkipPos, pos - prevSkipPos)`, DOS EPS header reconstruction, `NativePreview` push_back conditions, `EpsImage::readMetadata`/`writeMetadata` dispatch.

**Key checks performed:**
- `posEndEps = getULong(data+8) + posEps` — both are `uint32_t`-derived; on 64-bit `size_t` arithmetic, no overflow; enforced at line 289 on 32-bit.
- All `data + offset` accesses guarded by `enforce(offset <= size ...)` at lines 285–291.
- `findXmp` inner loops bounded by `size` (buffer length) at every step; `xmpSize` set only after valid trailer end within bounds.
- `xmpPacket.assign(data + xmpPos, xmpSize)` safe: `xmpPos + xmpSize <= posEndEps <= size` maintained by `findXmp`.
- `writeTemp(data + prevSkipPos, pos - prevSkipPos)`: `pos <= posEndEps <= size`, underflow checked at line 814.
- `nativePreview.size_` underflow scenario analysed: only reachable push_back path has `posAi7ThumbnailEndData > posAfterBeginData` guaranteed by sequential scan order.
- No unbounded recursion; `depth`/`maxDepth` guards prevent `SIZE_MAX` increment.
- No unchecked `memcpy`/`memset`; only `memcmp` calls inside bounds-checked regions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
