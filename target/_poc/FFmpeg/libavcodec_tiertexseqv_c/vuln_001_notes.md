# VULN 001 – OOB Read in seq_decode_op1() (tiertexseqv.c)

## Vulnerability Summary

**File**: `libavcodec/tiertexseqv.c`, function `seq_decode_op1()`, lines 112–120.

In the else branch (when the first byte of an op1 block has bit 7 clear, i.e., `len` ∈ 1–127):

```c
bits = ff_log2_tab[len - 1] + 1;          // line 112
...
color_table = src;                          // len bytes
src += len;
init_get_bits(&gb, src, bits * 8 * 8);     // pixel bitstream
src += bits * 8;
for (b = 0; b < 8; b++) {
    for (i = 0; i < 8; i++)
        dst[i] = color_table[get_bits(&gb, bits)];  // line 120
    dst += seq->frame->linesize[0];
}
```

`bits` is computed as ⌊log₂(len−1)⌋ + 1.  When `len` is **not** a power of 2, the maximum value returned by `get_bits(&gb, bits)` is `2^bits − 1`, which exceeds `len − 1`.  The resulting out-of-bounds read from `color_table` reads past the end of the heap-allocated packet buffer.

## Trigger Parameters

| Parameter | Value | Explanation |
|-----------|-------|-------------|
| `len`     | 65    | Non-power-of-2; lies in (64, 128) |
| `bits`    | 7     | `ff_log2_tab[64] + 1 = 6 + 1` |
| Max index | 127   | `2^7 − 1`; valid range is only 0–64 |
| OOB by   | 6 B   | Packet is 251 bytes; `color_table[127]` reads at packet offset 257 |

With all-`0xFF` pixel data and the little-endian bit-reader (`BITSTREAM_READER_LE`), each 7-bit `get_bits` call returns `0x7F = 127`.  All 64 pixel reads trigger the OOB.

## SEQ File Structure

The Tiertex SEQ demuxer (`libavformat/tiertexseq.c`) enforces these layout rules:

1. **Bytes 0–255**: all-zero (required by `seq_probe`).
2. **Bytes 256+**: 16-bit LE frame-buffer size list, terminated by `0`.
3. **Frame blocks**: fixed-size 6144-byte blocks starting at byte 6144.  Each block header (14 bytes) carries audio/palette offsets, 4 buffer-index bytes, and 4 fill-data offsets.
4. **Preloading**: `seq_read_header` calls `seq_parse_frame_data` 100 times before demuxing begins.

## PoC Strategy

1. **Frame buffer 0** (size 250 B) is declared at file offset 256.
2. **Frame 1** (offset 6144) fills buffer 0 with the crafted 250-byte video block via the fill-offset mechanism (`offset_table[0]=16`, `offset_table[3]=266`).  `buffer_num[0]` is set to 255 so frame 1 produces no output itself.
3. **Frames 2–100** set `buffer_num[0]=255` (no output), leaving buffer 0's `fill_size=250` intact.
4. **Frame 101** sets `buffer_num[0]=0`, causing the demuxer to emit a 251-byte video packet (1 flag byte + 250 bytes from buffer 0) to the decoder.
5. The decoder's `seqvideo_decode` reads the 128-byte block-op bitmap (byte 0 = `0x01` → op=1 for the first block), then calls `seq_decode_op1` with the remaining 122 bytes.
6. Inside `seq_decode_op1`: `len=65`, `bits=7`, check `121 < 121` fails (passes), the 56-byte pixel bitstream of `0xFF` bytes causes `get_bits` to return 127 on every call, and `color_table[127]` reads 6 bytes past the end of the 251-byte heap allocation.

## Expected ASAN Output

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at ...
    #0 ... seq_decode_op1 ...tiertexseqv.c:120
    #1 ... seqvideo_decode ...tiertexseqv.c:197
    #2 ... seqvideo_decode_frame ...tiertexseqv.c:244
```
