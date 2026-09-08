I've read the complete `imm5.c` file (193 lines) and traced through all logic paths in detail.

**Analysis of `imm5_decode_frame` (lines 85–161):**

- **Array bounds for `IMM5_units`:** `index` starts as `avpkt->data[10]` (uint8_t, 0–255). It is remapped (17→4, 18→5) then gate-checked `index >= 1 && index <= 12`. After `index -= 1`, the range is 0–11. Accesses to `IMM5_units[12]` and `IMM5_units[13]` are hardcoded. The table has 14 entries (0–13) — all accesses are in bounds.

- **Pointer arithmetic `avpkt->data += 24 - offset`:** `offset = IMM5_units[index].len + 8`. All SPS unit lengths are 12–14 bytes, so offset ∈ [20, 22]. Therefore `24 - offset` ∈ [2, 4] — always positive; the pointer always moves forward, never past the buffer start.

- **`new_size` bounds:** `AV_RL32(avpkt->data + 4)` returns uint32_t stored in `int new_size`. The guard `AV_RL32(...) + 24ULL <= avpkt->size` (uint64_t arithmetic) ensures `new_size ≤ avpkt->size - 24 ≤ INT_MAX - 24`. Thus `new_size + offset` (max offset 22) cannot overflow.

- **`memcpy` destinations:** After pointer adjustment, both `memcpy` calls write into the original pre-adjustment buffer region (header bytes 2–23), well within the allocation.

- **Else branch (lines 129–131):** `avpkt->size -= 24` is safe because the outer condition guarantees `avpkt->size > 24`.

- **`av_packet_make_writable`:** Called before any in-place mutation; error is checked and propagated.

- **Init/close:** `imm5_init` handles allocation failures; `imm5_close` uses `avcodec_free_context` correctly.

No exploitable memory-safety conditions found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
