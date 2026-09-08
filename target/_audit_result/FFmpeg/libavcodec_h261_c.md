The file is only 78 lines. Both functions have been fully read. The analysis is complete:

- `h261_loop_filter()`: Uses a fixed `temp[64]` stack array. All index computations are bounded: `x + 7*8` max = 63, `y*8 + x` max = 55 (inner loop, y=1..6), outer third loop max = `7*8+7` = 63, and `yz±1` stays within 0..63. No OOB possible.
- `ff_h261_loop_filter()`: Simply dispatches to the above using internal `MpegEncContext` pointers — no external size fields or allocation here.

No memory allocation, no external field reads, no integer arithmetic that can overflow into an allocation size. The calling site in `mpegvideo_motion.c:216` passes the same internal context.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
