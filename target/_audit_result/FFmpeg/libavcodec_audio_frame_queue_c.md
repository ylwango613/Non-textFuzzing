Having thoroughly read the 142-line file and traced all allocation sites, integer arithmetic, and pointer arithmetic, here is my conclusion:

- `ff_af_queue_add()`: `av_fast_realloc` with `sizeof(*afq->frames)*(frame_count+1)` — `frame_count` is `unsigned int`; on 64-bit, no overflow; return value is NULL-checked.
- `discard_padding` read via `AV_RL32` (line 59) is a `uint32_t` cast to `int`; the guard `discard_padding > 0 && discard_padding < nb_samples` prevents negative wrapping and over-subtraction.
- `ff_af_queue_remove()`: loop index `i` is bounded `[0, frame_count]`; line 112 decrements `i` by at most 1 (short-circuit prevents `frames[-1]` access when `i==0`); `memmove` size is `(frame_count - i) * sizeof(...)`, always non-negative.
- The stale write at line 119 (`afq->frames[0].pts += nb_samples` when `frame_count==0`) is within the allocated buffer — logically a bug but not an OOB write beyond the heap block.
- None of the inputs here are directly parsed from attacker-controlled file bytes; this is an encoder-side queue fed by already-decoded AVFrames.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
