I have now completed a full multi-pass read of `pngimage.cpp` (711 lines) and `pngchunk_int.cpp` (595 lines), tracing every data path from file input through allocations. Key findings from each group:

**Group 1 (pngimage.cpp lines 1-120):** `zlibToDataBuf` — correctly bounded by 16MB cap; no OOB. `tEXtToDataBuf` — allocation via two-pass nibble count is safe; raw pointer `r` writes at most `count/2` bytes into `(count+1)/2`-byte buffer.

**Group 2 (pngimage.cpp lines 120-378, printStructure):** All DataBuf accesses use throw-on-OOB methods (`read_uint8`, `cmpBytes`, `c_data`). The enforce chain (line 280 `dataOffset < UINT32_MAX` → line 281 `DataBuf data(dataOffset+1ul)` → line 287 `name_l < dataOffset`) is coherent. `data.c_data(name_l+1)` can reach offset `= dataOffset` (< `data.size() = dataOffset+1`) → valid pointer. zTXt path with `dataOffset - name_l - 1 = 0` causes infinite loop in `zlibToDataBuf` (DoS, not memory corruption).

**Group 3 (pngimage.cpp lines 392-478, readMetadata):** iCCP loop enforces `iccOffset < 80 && iccOffset < chunkLength` before each read — safe. When `iccOffset == chunkLength` post-loop, `zlibToDataBuf` called with length=0 → infinite loop (DoS). No heap corruption.

**Group 4 (pngimage.cpp lines 479-711, writeMetadata):** `dataOffset` checked ≤ 0x7FFFFFFF; `DataBuf chunkBuf(8 + dataOffset + 4)` cannot overflow on 64-bit. No OOB writes.

**Group 5 (pngchunk_int.cpp lines 1-180, parseTXTChunk):** `Safe::add` guards on keysize+nullSeparators. `c_data` returning nullptr for offset==size is safe here since compressedTextSize=0 prevents the null from being dereferenced. `zlibUncompress` with `compressedTextSize=2^31` gives `uncompressedLen=0` via unsigned overflow → DoS loop, not corruption.

**Group 6 (pngchunk_int.cpp lines 180-400, parseChunkContent/zlibUncompress):** `readRawProfile` length integer overflow: overflowed length `k` must satisfy the enforce `k ≤ (eot-sp)/2`, so allocation and decode both use the same clamped `k` — no overwrite. `unhex[103]` indexing is safe: the while-loop guarantees only ['0'..'9','a'..'f'] (ASCII 48–57, 97–102) reach the index, all within bounds.

**Group 7 (pngchunk_int.cpp lines 400-595, readRawProfile):** `string_from_unterminated(nullptr, 0)` early-returns safely when data_length=0. No null-pointer dereferences confirmed.

**DataBuf methods** (`types.cpp` lines 120-199): `c_data(offset == size) → nullptr`, but all callers either skip the block when the derived length is 0, or the offset is strictly less than size. No confirmed null-dereference path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
