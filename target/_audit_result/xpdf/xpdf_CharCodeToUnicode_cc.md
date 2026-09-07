Now I have the complete picture. Let me review the key findings from the full analysis:

**Batch 1 (lines 0–500):**
- `parseCIDToUnicode`: reads from system CID-to-Unicode files (not attacker-controlled PDF content). The `size *= 2` could theoretically overflow CharCode, but this requires ~2 billion lines in the system file — impractical.
- `parseCMap1` (the PDF-facing path): token buffers are stack-local with size passed into `getToken`; code values bounded by `maxCode`; `addMapping`/`addMappingInt` called with validated inputs.

**Batch 2 (lines 500–764):**
- `addMapping`: Guards `code > 0xffffff`. The `mapLen` doubling could mathematically overflow a `CharCode` (uint32), but reaching 0x80000000 Unicode slots requires ~3 GB allocation that would fail first. The `oldLen → mapLen` zeroing loop is correctly bounded.
- `parseUTF16String`: properly guards `uLen < maxUnicodeString` (=8) before writing to `uOut`.
- `addMappingInt`: same safeguards as `addMapping`.
- `setMapping`: no `c < mapLen` bounds check internally, but both callers (GfxFont.cc:1368 and :1882) always pass `c` values strictly within `[0, mapLen)`.
- `greallocn` with nObjs=0 frees and returns NULL — the only code path that could trigger this is in `parseCIDToUnicode` under integer overflow of `size`, which requires 2B-line system file, not PDF content.

**sMap access pattern in `addMapping`**: The `sMapLen >= sMapSize` check (using `>=`) with `sMapSize += 16` correctly ensures a free slot before writing. `uLen - 1` is bounded 0..7 against `u[maxUnicodeString]` array of 8. No OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
