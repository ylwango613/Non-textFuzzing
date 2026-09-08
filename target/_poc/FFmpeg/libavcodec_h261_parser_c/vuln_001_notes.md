# VULN-001: h261_find_frame_end returns i-2 causing 1-byte heap OOB read in ff_combine_frame

## Summary

`h261_find_frame_end()` in `libavcodec/h261_parser.c` can return `-1` when the second scan
loop matches a start code pattern at `i=1`, yielding `i - 2 = -1`. This negative `next` value
is passed to `ff_combine_frame()` in `libavcodec/parser.c`, which executes:

```c
for (; next < 0; next++) {
    pc->state = pc->state << 8 | pc->buffer[pc->last_index + next];
```

If `pc->last_index == 0`, this reads `pc->buffer[-1]` — one byte before the heap allocation.
The audit report correctly identifies the code path but the trigger conditions for
`pc->last_index == 0` are mathematically unreachable (see Reachability Analysis below).

## Correct Trigger for h261_find_frame_end Returning -1

### Setup: frame_start_found=1 path

`h261_find_frame_end` returns `-1` only via the **second scan loop** when
`frame_start_found=1` at call entry (the second loop then starts at `i=0`):

```c
// With frame_start_found=1, vop_found=1 from the start.
// Second loop starts at i=0:
for (; i < buf_size; i++) {          // i starts at 0
    state = (state << 8) | buf[i];
    for (j = 0; j < 8; j++) {
        if (((state >> j) & 0xFFFFF0) == 0x000100) {
            return i - 2;            // i=1 -> return -1
```

**Required state**: `pc->state` bits 0-7 must be 0 (so that `state_0 = (pc->state<<8)|buf[0]`
has bits 8-15 = 0, preventing a match at `i=0`). Then `buf[0]=0x01`, `buf[1]=0x00`:
- `state_0 = 0x00000001` — no j=0..7 match (all values < 0x100 threshold).
- `state_1 = 0x00000100` — j=0: `0x100 & 0xFFFFF0 = 0x100 = 0x000100`. **MATCH. Return -1.**

### Crafted file layout

| Bytes     | Content                           | Effect                                               |
|-----------|-----------------------------------|------------------------------------------------------|
| 0-1       | `0x00 0x00`                       | state stays 0                                        |
| 2         | `0x01`                            | state = 0x00000001                                   |
| 3         | `0x00`                            | state = 0x00000100, j=0 match → vop_found=1         |
| 4-1023    | `0x00` × 1020                     | second loop: 0x10000→0x1000000→0→0; no match        |
| — end of chunk 1 — | END_NOT_FOUND. fsf=1. pc->state=0. pc->index=1024. |                          |
| 1024      | `0x01`                            | state_0=0x01; no j=0..7 match                        |
| 1025      | `0x00`                            | state_1=0x100; j=0 match → **return 1-2 = -1**     |
| 1026-2047 | `0x00` × 1022                     | padding                                              |

## What Actually Happens at Runtime

### Chunk 1 (bytes 0-1023)

`h261_find_frame_end(state=0, fsf=0, buf=[0x00,0x00,0x01,0x00,...])`:
- First loop matches at i=3 (state=0x000100). vop_found=1.
- Second loop i=4..1023: state cycles 0x10000→0x1000000→0→0. No second match.
- Returns END_NOT_FOUND. fsf=1. pc->state=0.

`ff_combine_frame(END_NOT_FOUND)`: pc->index=1024. pc->buffer allocated (≥1088 bytes).

### Chunk 2, Iteration 1 (bytes 1024-2047)

`h261_find_frame_end(state=0, fsf=1, buf=[0x01,0x00,...])`:
- Second loop at i=0: state_0=0x01. No match. i=1: state_1=0x100. j=0: match. **Return -1.**

`ff_combine_frame(next=-1, pc->index=1024, pc->overread=0)`:
- Copy overread: 0 iterations. (pc->overread=0 → no-op.)
- `pc->last_index = pc->index = 1024`.
- Append block (`pc->index > 0`): runs. `pc->index = 0`. Copies 63 bytes.
- Store overread: `pc->buffer[1024 + (-1)] = pc->buffer[1023]`. **VALID** (within allocation).
- `pc->overread = 1`. Returns 0.

`h261_parse` returns -1. `av_parser_parse2` clamps to 0. **0 bytes consumed.**

### Chunk 2, Iteration 2 (same buf, 0 consumed)

`ff_combine_frame` begins: pc->overread=1.
- Copy overread loop: pc->index goes 0→1. pc->overread=0.
- `pc->last_index = 1`.

`h261_find_frame_end(state=0xFF00, fsf=0, buf=[0x01,0x00,...])`:
- First loop: i=1: state=0xFF000100. j=0: 0xFF000100 & 0x00FFFFF0 = 0x100. Match. vop_found=1.
- Second loop: i=2: 0x00010000. No match. i=3+: 0. No match. END_NOT_FOUND. fsf=1.

`ff_combine_frame(END_NOT_FOUND)`: pc->index=1025. Returns -1.
`h261_parse` returns 1024. `av_parser_parse2` returns 1024. **Demux advances 1024 bytes.**

### Flush (EOF)

`ff_combine_frame(next=0)` delivers the accumulated 2048 bytes as 2 frames (H.261 decoder
interprets the accumulated bytes and produces decoded output).

## Reachability Analysis: Why pc->buffer[-1] is Unreachable

For the OOB at `pc->buffer[-1]`, `pc->last_index` must equal 0 at the time of the overread
store loop. This requires:

1. **`pc->index = 0` AND `pc->overread = 0`** at the start of the `-1`-triggering
   `ff_combine_frame` call (so the copy-overread loop doesn't run and `pc->last_index=0`).

2. **`pc->buffer != NULL`** (for the `av_assert0` not to fire).

For condition (1): `pc->index=0` after a prior call requires a frame delivery (`next≥0` path,
which runs the append block and resets `pc->index=0`). Frame delivery resets
`pc->frame_start_found=0`.

3. **`frame_start_found=1`** is required for `h261_find_frame_end` to return `-1`.
   (Without it, the only path to `-1` requires consecutive matches at i=0 and i=1 in the first
   and second loops respectively. This is algebraically impossible: a first-loop match at i=0
   requires `state_0` bits [8:15] > 0, but a second-loop match at i=1 requires
   `state_1` bits [16:23] = `state_0` bits [8:15] = 0 — contradiction for all j∈{0..7}.)

Conditions (1) and (3) are **mutually exclusive**: `pc->index=0` requires prior frame delivery
which resets `frame_start_found=0`, while `frame_start_found=1` requires an END_NOT_FOUND
call that inevitably increases `pc->index`.

**Conclusion: The pc->buffer[-1] OOB access is theoretically present in the code but
mathematically unreachable with any crafted H.261 bitstream.**

## Why the Original Analysis Was Wrong

The original session analysis claimed j=8 matches (e.g., `state=0x00010000, j=8: match`).
The C loop is `for (j = 0; j < 8; j++)` — j only takes values {0,1,2,3,4,5,6,7}. j=8 is
never tested. This critical error invalidated the entire prior trigger chain.

## Observed Behavior

Running `ffmpeg -f h261 -i vuln_001_input.h261 -f null -`:
- ffmpeg exits with code 0.
- Outputs 2 decoded frames.
- No ASAN heap-buffer-overflow reported.
- No crash or abort.

The `-1` return IS triggered by chunk 2, as confirmed by the analysis. The OOB access
that occurs is at `pc->buffer[1023]` (a valid byte), not `pc->buffer[-1]`.

## Vulnerability Status

**UNVERIFIED** — The code path `h261_find_frame_end returns -1 → ff_combine_frame overread loop`
is exercised by the crafted input, but the specific access `pc->buffer[-1]` (the claimed OOB)
is unreachable due to mutual exclusion between the required preconditions.
