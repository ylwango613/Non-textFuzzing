The analysis is complete. Here's what I found:

**`libavcodec/half2float.c`** simply `#include`s `libavutil/half2float.c`.

**`libavutil/half2float.c`** contains `ff_init_half2float_tables()` and `convertmantissa()`. **`libavutil/half2float.h`** contains the inline `half2float()` function.

Key analysis of the critical lookup in `half2float()`:
```c
f = t->mantissatable[t->offsettable[h >> 10] + (h & 0x3ff)] + t->exponenttable[h >> 10];
```

- `h` is always `uint16_t` → `h >> 10` ∈ [0, 63] → valid index into `offsettable[64]` and `exponenttable[64]`.
- `t->offsettable[i]` is initialized only to {0, 1024, 2048} → max index into `mantissatable` = 2048 + 1023 = 3071 → `mantissatable[3072]` is exactly sized to cover this (indices 0..3071).

`convertmantissa()` is only called with `i` ∈ [1, 1023], and for all such values `m = i << 13` has its highest bit below bit 23, so the `while(!(m & 0x00800000))` loop terminates in at most 10 iterations (for i=1) without signed overflow.

All table writes in `ff_init_half2float_tables()` stay within their respective array bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
