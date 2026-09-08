# VULN 001: Heap Buffer Overflow in FlashSV Encoder via compress2 Output Overrun

## Summary

The FlashSV encoder in `libavcodec/flashsvenc.c` allocates a packet buffer sized as:

```c
s->packet_size = 4 + nb_blocks * (2 + 3 * BLOCK_WIDTH * BLOCK_HEIGHT);
// = 4 + nb_blocks * (2 + 12288) = 4 + nb_blocks * 12290
```

However, when calling `compress2()` for each block, it passes `zsize = 3 * block_width * block_height + 12 = 12300` as the output buffer upper bound — 12 bytes more than allocated per block:

```c
zsize = 3 * block_width * block_height + 12;  // line 178
compress2(buf, &zsize, ...);                   // line 179
```

For nb_blocks blocks, the cumulative potential overflow is `nb_blocks * 12` bytes beyond the allocated region, minus the `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) padding added by `av_grow_packet`. With incompressible (random noise) input, `compress2` may produce output close to or larger than the uncompressed input, writing past the allocated block.

## PoC Approach

- Generate a valid AVI file containing BGR24 raw video frames at 640x480 resolution.
- Frame data is filled with `os.urandom()` to maximize incompressibility, causing `compress2` to produce output near or at the `zsize` limit.
- At 640x480: `nb_blocks = 10 * 8 = 80`, potential overflow = `80 * 12 - 64 = 896 bytes`.
- ffmpeg decodes the AVI and re-encodes with `-vcodec flashsv`, triggering the vulnerable path.

## Expected ASAN Output

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size N at 0x... thread T0
    #0 ... in compress2
    #1 ... in encode_bitstream ffmpeg/libavcodec/flashsvenc.c:179
    ...
```

## Trigger Command

```bash
ffmpeg -i vuln_001_input.avi -vcodec flashsv -f flv /dev/null
```

## Analysis: Why ASAN Does Not Trigger

The vulnerability is logically present (packet buffer semantics are violated) but ASAN cannot detect it because `ff_alloc_packet()` in `libavcodec/encode.c` uses `av_fast_padded_malloc()`, which internally calls `av_fast_mallocz()`. This function allocates `min_size + min_size/16 + 32` bytes, providing approximately 6.25% extra allocation beyond the requested `packet_size + AV_INPUT_BUFFER_PADDING_SIZE`.

For 512x448 (56 full blocks):
- `packet_size = 4 + 56 * 12290 = 688244` bytes
- Intended allocation: `688244 + 64 = 688308` bytes
- Actual `av_fast_mallocz` allocation: `688308 + 688308/16 + 32 = 731359` bytes
- Maximum compress2 overflow: `56 * 11 = 616` bytes past packet_size, or 552 bytes past padding
- Extra slack from av_fast_mallocz: `731359 - 688308 = 43051` bytes

The 552-byte overflow is covered by 43051 bytes of extra slack. This extra slack grows proportionally with packet_size, so no resolution can exceed it: overflow per block is 11 bytes while extra allocation per block is ~768 bytes.

The vulnerability would be exploitable in environments where the allocator provides less slack (e.g., custom allocators, certain OS/libc versions without aggressive pre-allocation, or if `ff_alloc_packet` is replaced with a tighter allocator like `av_new_packet`).

**Result: UNVERIFIED** - The bug exists in the code logic but ASAN cannot detect it with the current binary's allocation strategy.
