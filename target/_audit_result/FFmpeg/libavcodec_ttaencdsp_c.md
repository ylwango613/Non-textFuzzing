My analysis is complete. Here is the full picture:

**`ttaencdsp.c` (66 lines):** The single DSP function `ttaenc_filter_process_c` accesses `qm[]`, `dx[]`, `dl[]` only at fixed indices 0–7. All three arrays are declared in `TTAFilter` as `int32_t [MAX_ORDER]` with `MAX_ORDER = 8`, so every access is within bounds. The arithmetic (dot-product, shift) involves signed/unsigned integer overflow in the C sense, but none of it writes outside any buffer.

**`ttaenc.c` — encoder caller:** Processes user-provided audio, not an attacker-controlled bitstream. `ch_ctx` is allocated with `av_malloc_array(nb_channels, sizeof(*s->ch_ctx))` and indexed only in `[0, nb_channels)`. The packet reallocation loop handles buffer exhaustion safely.

**`tta.c` — decoder:** The only attacker-controlled code path. Key checks:
- `s->channels` is validated to 1–16 before any allocation.
- `s->frame_length >= UINT_MAX / (s->channels * sizeof(int32_t))` guards the `av_calloc` call.
- `s->bps` is validated to 1–3 via a `switch` before `ff_tta_filter_configs[s->bps-1]` is used.
- Rice counters `k0`/`k1`: `ff_tta_shift_16 = ff_tta_shift_1 + 4`; the sentinel entry `ff_tta_shift_1[40] = 0xFFFFFFFF` means the condition `sum > ff_tta_shift_16[k+1]` can never be true at k=35 (since a `uint32_t` cannot exceed UINT32_MAX), so k is bounded at ≤35 and `ff_tta_shift_16[36]` = `ff_tta_shift_1[40]` = the last valid array entry — no OOB.
- `filter_process` arrays are always the same fixed-size 8-element structs embedded in `TTAChannel`.

No externally triggerable memory-safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
