After a thorough analysis of all code paths in `loco.c`:

- **`loco_predict`**: Accesses `data[-stride]`, `data[-1]`, `data[-stride-1]` — always called with `i >= 1` (col) and `j >= 1` (row), so prior-row and prior-col are always within the allocated frame buffer for both positive and negative stride.
- **`loco_decode_plane`**: Writes `data[0..width-1]` per row; `ff_get_buffer` ensures `linesize >= width`, keeping all writes in-bounds. The `ADVANCE_BY_DECODED` macro correctly prevents over-reading between planes.
- **`rotate_faulty_loco`** (negative-stride memmoves): Both memmove destinations/sources resolve to valid rows within `[p->data[plane], p->data[plane] + linesize * height)` — the `if (width >= y)` and `if (y+1 < height)` guards prevent all out-of-bounds arithmetic.
- **Rice decoder**: `val == INT_MIN` correctly catches golomb error sentinels; negative rice residuals stored in `unsigned val` then truncated via modular uint8_t arithmetic is intentional DPCM, not memory corruption.
- **`decode_init`**: Validates `extradata_size >= 12`, `lossy <= 65536U`, and the mode enum before any pixel processing.
- **Large run-length values** from golomb (`r->run` up to INT_MAX): could cause slow decoding (DoS) but no memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
