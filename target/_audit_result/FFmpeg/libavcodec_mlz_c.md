After fully reading `mlz.c` (207 lines), `mlz.h`, and the primary caller `alsdec.c`, I performed the following checks:

**Analysis summary:**

1. **Dictionary table OOB** (`dict[string_code]`): `string_code` from the bitstream is at most `MAX_CODE = 32767` (because `bump_code` can at most reach 32767, which is pre-empted by `case MAX_CODE:` flush before it could bump `dic_code_bit` beyond 15). TABLE_SIZE = 35023 > 32767 → no OOB.

2. **`decode_string` buffer OOB**: `offset = dict[current_code].match_len - 1` is checked against `bufsize` (line 90) before every write. `buff[offset]` write is only reachable when `offset < bufsize`. For the leaf write `buff[0]`, `bufsize > 0` is guaranteed by the enclosing `while (count < bufsize)` loop guard.

3. **`nchars`/`larray` size mismatch**: `larray` is allocated at `cur_frame_length * 4` bytes (line 2135). `nchars` for Part A is at most `frame_length * 4` (same as allocation size); for Part B at most `frame_length * 3` (since `nbits[i] ≤ 23`, ceil(23/8)=3 bytes). `frame_length` is `get_bits(gb,16)+1 ≤ 65536`, so no integer overflow in the int accumulator.

4. **`next_code` OOB in `set_new_entry_dict`**: The check `next_code >= TABLE_SIZE - 1` is performed immediately after every `set_new_entry_dict` call; `next_code` is bounded to ≤ TABLE_SIZE-1 = 35022 — within the array.

5. **`current_dic_index_max` doubling overflow**: Integer, starts at 512, doubles at most to 32768; the next bump is pre-empted by the `case MAX_CODE:` flush, so it never overflows.

6. **`match_len` chain cycles/infinite loop**: `match_len` is always set as `parent.match_len + 1`; entries are write-once after creation, making cycles impossible; the chain always terminates.

7. **`size` sign / unsigned comparison**: `nchars` is computed as a sum of non-negative terms bounded to ≤ 262144 — never negative, so the `unsigned long output_chars < size` comparison is always correct.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
