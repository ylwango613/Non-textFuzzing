# VULN 001: Off-by-one OOB Read in decode_0() — PoC Notes

## Vulnerability Summary

**File:** `libavcodec/pafvideo.c`  
**Function:** `decode_0()`  
**Line 234:** `if (op > opcode_size)` should be `if (op >= opcode_size)`

When `op == opcode_size`, the bounds check is `op > opcode_size` which evaluates to `false` (not triggered), so execution continues to `opcodes[op]` which reads 1 byte past the valid `opcode_size`-byte opcodes region.

## PoC Approach

### PAF File Layout
```
Offset    Size    Content
0         512     Header block (MAGIC + nb_frames/fps/width/height/etc.)
512       2048    blocks_count_table[512]  (only entry [0]=0 matters)
2560      2048    frames_offset_table[512] (entry [0]=1009: packet at video_frame[1009])
4608      2048    blocks_offset_table[512] (entry [0]=512: video block at vf[512])
6656      512     Block data (video block: 512 bytes loaded into video_frame[512..1023])
```

### Video Dimensions
- Width=8, Height=8 (minimum valid: multiples of 4)
- Produces a 2×2 grid of 4×4 blocks (4 total blocks)

### Packet Construction (15 bytes)
```
Offset  Value   Purpose
0       0x20    code: keyframe (bit5) + decode_0 (bits0-3 = 0)
1       0x00    i=0: skip complex first section in decode_0
2-9     0x00*8  4× set_src_position reads (page=0, x=0, y=0 — valid frame[0] origin)
10-11   0x01 0x00  opcode_size = 1 (uint16 LE)
12-13   0x00 0x00  skipped by bytestream2_skip(gb, 2)
14      0x00    opcodes[0]: both nibbles = 0 → opcode=0 → block_sequences[0] is no-op
```
Packet size = 15 bytes → pkt->data[15..78] = AV_INPUT_BUFFER_PADDING_SIZE zeros

### OOB Trigger Sequence
```
Block 1 (i=0,j=0): op=0, check (0>1)=false, read opcodes[0]>>4 = 0 [VALID]
Block 2 (i=0,j=4): op=0, check (0>1)=false, read opcodes[0]&15  = 0 [VALID], op++ → op=1
Block 3 (i=4,j=0): op=1, check (1>1)=FALSE  ← BUG, read opcodes[1] [OOB READ]
Block 4 (i=4,j=4): op=1, check (1>1)=FALSE  ← BUG, read opcodes[1] [OOB READ AGAIN]
```

With the corrected check `op >= opcode_size`, Block 3 would return `AVERROR_INVALIDDATA`.

## ASAN Detection Limitation

`av_new_packet()` allocates `pkt->size + AV_INPUT_BUFFER_PADDING_SIZE` (size + 64 bytes), and the final 64 bytes are explicitly zeroed. The OOB read at `opcodes[1] = pkt->data[15]` falls within this 64-byte zero padding — within the heap allocation from ASAN's perspective. Therefore, ASAN does **not** raise a `heap-buffer-overflow` for this 1-byte off-by-one.

## Behavioral Evidence

The vulnerability allows the decoder to process frames that should be rejected:
- **With bug:** `decode_0()` reads opcodes[1]=0 (from zero padding), opcode=0, block_sequences[0] does nothing for blocks 3 & 4. Frame is decoded as all-black. FFmpeg exits normally.
- **Without bug (fixed):** `decode_0()` returns `AVERROR_INVALIDDATA` at block 3. FFmpeg logs a decode error.

In a real attack scenario with a carefully crafted file, if the byte following the opcodes region were non-zero (from heap feng-shui or other layout manipulation), the OOB read could yield a non-zero opcode, causing the block-processing loop to issue additional reads from an exhausted stream — potentially leading to additional malfunctions or information leakage.
