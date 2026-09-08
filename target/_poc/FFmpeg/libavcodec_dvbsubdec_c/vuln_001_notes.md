# VULN-001: Heap OOB Read in dvbsub_parse_pixel_data_block (case 0x22)

## Source Location
`FFmpeg/libavcodec/dvbsubdec.c`, lines 971–974

```c
case 0x22:
    for (i = 0; i < 16; i++)
        map4to8[i] = *buf++;   // reads 16 bytes with NO bounds check
    break;
```

## Root Cause
The outer loop (`while (buf < buf_end)`) at line 916 only checks bounds before
consuming the command byte via `switch (*buf++)`. After the increment, `buf` may
equal `buf_end`. Cases 0x20/0x21/0x22 then read 2/4/16 additional bytes without
any secondary bounds check, causing a heap buffer over-read.

## Trigger Condition
Set `top_field_data_block_length = 1` in an Object Data Segment (type 0x13), with
the single pixel-data byte equal to `0x22`. The decoder will:
1. Enter the loop with `buf < buf_end` true (one byte remains).
2. Consume `0x22` via `switch (*buf++)`, advancing `buf` to `buf_end`.
3. Fall into `case 0x22` and execute `for (i = 0; i < 16; i++) map4to8[i] = *buf++`,
   reading 16 bytes **past the end of the allocation**.

## PoC Approach
`vuln_001_gen.py` builds a minimal MPEG-TS using only `struct` and `bytes`:

1. **PAT** (PID 0x0000) — program 1 → PMT at PID 0x1000
2. **PMT** (PID 0x1000) — stream_type=0x06 with SUBTITLING_DESCRIPTOR (tag=0x59)
   on PID 0x0200; composition_page_id=1, ancillary_page_id=1
3. **PES** (PID 0x0200) — DVB subtitle payload containing four segments in order:
   - **Page Composition Segment** (0x10): sets up page with region 1 at (0,0)
   - **Region Composition Segment** (0x11): creates region 1 (320×240, 4-bit depth)
     and object 1 at position (0,0) within the region
   - **Object Data Segment** (0x13): object 1, `top_field_data_block_length=1`,
     pixel data = `[0x22]`  ← **OOB trigger**
   - **End of Display Set Segment** (0xFF)

The PES payload omits the `0x20 0x00` data_identifier prefix so that
`dvbsubdec.c`'s first-byte check (`*buf == 0x0f`, line 1478) passes.

## Trigger Path
```
ffmpeg -i vuln_001_input.ts -f null -
  -> mpegts demuxer identifies PID 0x0200 as AV_CODEC_ID_DVB_SUBTITLE
  -> dvbsub_decode()
     -> dvbsub_parse_page_segment()    [builds page context]
     -> dvbsub_parse_region_segment()  [creates region 1 and object 1]
     -> dvbsub_parse_object_segment()
        -> dvbsub_parse_pixel_data_block(buf=&0x22, buf_size=1)
           buf_end = buf + 1
           while (buf < buf_end): true
           check x_pos(0) < width(320), y_pos(0) < height(240): passes
           switch (*buf++): consumes 0x22, buf == buf_end now
           case 0x22: for i=0..15: map4to8[i] = *buf++   <-- 16-byte OOB READ
```

## Expected Behavior
ASAN reports `heap-buffer-overflow` (READ, 1 byte, 16 times past allocation boundary).
