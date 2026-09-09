The file `vorbis_data.c` is entirely a static data file (2188 lines). Its complete contents are:

- **Lines 1–35**: `ff_vorbis_channel_layout_offsets[8][8]` — compile-time constant uint8 table
- **Lines 37–51**: `ff_vorbis_ch_layouts[9]` — AVChannelLayout structs, null-terminated
- **Lines 53–2115**: Eight `DECLARE_ALIGNED` static float window arrays (`vwin64` through `vwin8192`), all correctly sized with literal element counts matching their declared dimensions
- **Lines 2117–2182**: `ff_vorbis_floor1_inverse_db_table[256]` — 256-element float lookup
- **Lines 2184–2187**: `ff_vorbis_vwin[8]` — pointer array to the 8 window tables

**Analysis**:

- No functions, no loops, no memory allocation (`av_malloc`/`malloc`/`realloc`)
- No `memcpy`/`memmove`
- No integer arithmetic with user-controlled input
- No array indexing driven by external data
- No chunk/atom/packet parsing
- All array sizes are compile-time literals that match their declared types exactly
- The `ff_vorbis_vwin` pointer array maps `blocksize_log ∈ [0,7]` to the 8 window tables; the caller in `vorbisdec.c` uses this index — but that indexing logic is not in this file

There is nothing in this file that can be externally triggered to cause a memory safety bug. It is a read-only data segment baked at compile time.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
