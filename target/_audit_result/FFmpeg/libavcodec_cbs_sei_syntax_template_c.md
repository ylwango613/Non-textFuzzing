The `ff_cbs_read_unsigned` function at `cbs.c:599` checks `if (get_bits_left(gbc) < width)` before reading — since `get_bits_left` returns `int`, a negative result (from overflowed index) triggers `AVERROR_INVALIDDATA` and early return. This is the critical safety net.

Based on my complete analysis:

1. **`user_data_registered`** (lines 37–74): allocation via `av_refstruct_allocz(payload_size + AV_INPUT_BUFFER_PADDING_SIZE)` is safe; the loop reads from a bounded `payload_gbc` and errors cleanly if exhausted.

2. **`user_data_unregistered`** (lines 76–108): same pattern; `data_length = payload_size - 16` subtraction is guarded by the `< 16` check; writes stay within the allocated `payload_size + 64` byte buffer.

3. **`message()` extension data** (lines 337–423): `bits_left = 8 * current->payload_size - bits_written` could theoretically underflow if `payload_size` overflows uint32_t, but `payload_size` is constrained by the stream's available bits. `init_get_bits` rejects negative `bit_size` and `ff_cbs_read_unsigned` rejects negative `get_bits_left` — no OOB path is reachable.

4. **`message_list()` bounds check** (line 454): `payload_size + 1 > get_bits_left(rw) / 8` — integer overflow in `payload_size + 1` when `payload_size = UINT32_MAX` would require ~16.8 MB of `0xff` size-encoding bytes, exhausting the stream before the payload itself can exist.

5. **`ff_cbs_sei_list_add`**: `av_realloc_array` with `new_count * sizeof(SEIRawMessage)` uses the safe realloc API with separate count and element size parameters, no overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
