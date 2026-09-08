`av_calloc` uses `size_mult` to check for overflow — safe. All callers are in `dxvenc.c` (an encoder) with compile-time constant parameters (`LOOKBACK_HT_ELEMS = 0x20202`, key/val sizes as `sizeof(uint32_t)`/`sizeof(uint64_t)`). No attacker-controlled input reaches the hashtable.

Full analysis summary:
- **`ff_hashtable_alloc`**: The `keyval_size` overflow check correctly guards both `sizeof(*res) + 2*keyval_size` (the `FFHashtableContext` allocation) and `FFALIGN(sizeof(size_t) + keyval_size, ALIGN)` (the entry_size computation). `av_calloc` has its own `size_mult` overflow guard.
- **`ff_hashtable_get`**: `(hash + psl) % max_entries` — `hash < max_entries` and `psl <= max_entries`, so the maximum value is `2*max_entries-1`. A practical `max_entries` is far below `SIZE_MAX/2` because `av_calloc(max_entries, entry_size)` must succeed (min entry_size = 8 bytes), so no overflow.
- **`ff_hashtable_set`**: `swapbuf` is allocated as `2*keyval_size` bytes; `set` and `tmp` split it into two equal non-overlapping halves of `keyval_size` each. `FFSWAP` only swaps pointers between those two regions. Table index `wrapped_index` is always `< max_entries` via the modular increment. All `memcpy` sizes are bounded by allocated regions.
- **`ff_hashtable_delete`**: Physically correct; `nb_entries--` fires correctly when the back-shift finds PSL≤1. The edge case where the inner loop exhausts is a logic error (nb_entries not decremented) but not a memory safety issue.
- **Attack surface**: Only `dxvenc.c` calls this code, with parameters that are compile-time constants, not derived from attacker-controlled media file bytes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
