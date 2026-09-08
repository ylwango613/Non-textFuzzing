# VULN 002 – lead_decode_frame YUV420P Heap OOB Write

## Vulnerability Summary

**CWE**: CWE-787 (Out-of-bounds Write)  
**Function**: `lead_decode_frame()` in `libavcodec/leaddec.c` (lines 253–285)  
**Affected format**: AVI container with LEAD codec (FourCC "LEAD"), YUV420P pixel format

## Root Cause

In the YUV420P branch (`format=0x1000/0x6/0x8000/0x1006`), the macroblock row loop iterates:

```c
for (int mb_y = 0; mb_y < (avctx->height + 15) / 16 / fields; mb_y++)
```

For luma sub-blocks `b=2` and `b=3`, the write row is:

```c
y = 16*mb_y + 8*(b >> 1)
```

On the last iteration (`mb_y = ceil(height/16) - 1 = 1` for height=17), blocks `b=2,3` produce `y = 24`. The `idct_put` call then writes 8 rows starting at row 24 (rows 24–31).

However, `ff_get_buffer()` for a 16×17 YUV420P frame allocates luma with only ~18 rows (height aligned to an even number). Rows 24–31 are **well past the end of the allocated buffer**, causing an 8-row heap out-of-bounds write.

Chroma planes overflow similarly: chroma height for a 17-row luma frame is 9 rows (ceil(17/2)), but the loop writes chroma at `y = 8*mb_y` for `mb_y=1`, giving `y=8`, and `idct_put` writes rows 8–15 — again beyond the 9-row chroma buffer.

## PoC Approach

1. **`vuln_002_gen.py`**: Constructs a minimal but structurally valid AVI file:
   - RIFF/AVI container with correct chunk nesting
   - `avih` sets width=16, height=17
   - `strh` sets fccType=`vids`, fccHandler=`LEAD`
   - `strf` is a BITMAPINFOHEADER with `biCompression=LEAD` plus 20 bytes of extradata (required by `lead_decode_init` which rejects files with `extradata_size < 20`)
   - One `00dc` frame chunk: 8-byte LEAD header (`format=0x1000`, `q=50`) followed by 200 bytes of `0x80`

2. **Encoded bitstream design**: After the XOR-with-0x80 pass in the decoder, the payload bytes become all zeros. In the canonical Huffman tables used by this codec, the all-zeros bit pattern decodes as:
   - DC code `00` (2 bits) → size=0 (no DC delta)
   - AC code `00` (2 bits) → symbol=0 (EOB)
   
   This lets each 8×8 block decode successfully (DC=0, all AC=0) in 4 bits, consuming only 48 bits across 12 blocks, while 200 payload bytes provide 1600 bits — ensuring `get_bits_left > 0` for every block.

3. **OOB trigger**: After blocks 0–7 decode cleanly (mb_y=0: all 6 blocks; mb_y=1 b=0,1), block 9 (mb_y=1, b=2) calls `decode_block` with `dst = frame->data[0] + 24*linesize`, writing 8×8 pixels at rows 24–31 of a buffer with only ~18 luma rows.

## Expected Behavior with ASAN

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size 8 at ...
    #0 ... idct_put ...
    #1 ... decode_block ...
    #2 ... lead_decode_frame ...
```

## Trigger Command

```bash
bash vuln_002_run.sh
```

Or manually:
```bash
python3 vuln_002_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_002.log" \
  /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg \
  -i vuln_002_input.avi -f null -
```
