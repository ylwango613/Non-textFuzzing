# VULN 001 - CWE-125 Out-of-bounds Read in `parse_presentation_segment()`

## Location
- File: `libavcodec/pgssubdec.c`
- Lines: 449-468

## Root Cause

The function checks that at least 8 bytes remain (`buf_end - buf < 8`) before
reading a composition object's basic fields (8 bytes total). After consuming
exactly those 8 bytes, `buf` equals `buf_end`. The code then checks whether the
`composition_flag` has bit 7 (0x80, the crop flag) set and unconditionally reads
8 more bytes for crop coordinates — without any bounds check. This reads 8 bytes
past `buf_end` into adjacent memory.

```c
if (buf_end - buf < 8) {   // passes when exactly 8 bytes remain
    ...return error...
}
object->id               = bytestream_get_be16(&buf);  // +2
object->window_id        = bytestream_get_byte(&buf);  // +1
object->composition_flag = bytestream_get_byte(&buf);  // +1 -> buf == buf_end
object->x = bytestream_get_be16(&buf);                 // +2
object->y = bytestream_get_be16(&buf);                 // +2  -> buf == buf_end

if (object->composition_flag & 0x80) {   // crop flag
    object->crop_x = bytestream_get_be16(&buf);  // OOB +2
    object->crop_y = bytestream_get_be16(&buf);  // OOB +2
    object->crop_w = bytestream_get_be16(&buf);  // OOB +2
    object->crop_h = bytestream_get_be16(&buf);  // OOB +2
}
```

## Crafted SUP File Structure

A raw PGS (.sup) packet with:
- PG magic (2 bytes)
- PTS/DTS = 0 (8 bytes)
- segment_type = 0x16 (PCS)
- segment_length = 19 (11-byte PCS header + 8-byte object entry, no crop bytes)
- PCS data (11 bytes): 1920x1080 video, 1 composition object
- Object entry (8 bytes): `composition_flag = 0x80` (crop flag set, no crop data)

## Trigger Path

```
ffmpeg -i vuln_001.sup -map 0:s:0 -c:s dvb_subtitle -f mpegts /tmp/out.ts
  -> avformat_open_input()
  -> demux packet (SUP: PG + PCS type=0x16 + 22 bytes data)
  -> avcodec_decode_subtitle2()         <- pgssub decoder
     -> pgssub_decode_frame()
        -> parse_presentation_segment() <- OOB read here (8 bytes past buf_end)
        -> display_end_segment()        <- logs "Invalid palette id 0"
```

## Proof of Execution

Running `ffmpeg -i vuln_001.sup -c:s dvbsub -f mpegts /tmp/out.ts` produces:

```
[pgssub @ ...] Invalid palette id 0
Last message repeated 4 times
```

This confirms `parse_presentation_segment()` was called for all 5 PCS packets,
and that it successfully returned (allowing `display_end_segment` to run).

## Why ASAN Does Not Crash

`av_new_packet()` always appends `AV_INPUT_BUFFER_PADDING_SIZE = 64` bytes of
zeroed padding to every packet allocation (see `libavcodec/packet.c`). The
packet logical size is 22 bytes (3-byte segment header + 19-byte PCS data),
but the ASAN heap allocation is 22 + 64 = 86 bytes. The 8-byte crop overread
starts at offset 22, well within the 86-byte allocation. ASAN's red zone begins
at offset 86, which is not reached. The crop values read are all zeros.

## Fix

Add a bounds check before reading crop data:

```c
if (object->composition_flag & 0x80) {
    if (buf_end - buf < 8) {
        av_log(avctx, AV_LOG_ERROR, "Insufficient space for crop\n");
        ctx->presentation.object_count = i;
        return AVERROR_INVALIDDATA;
    }
    object->crop_x = bytestream_get_be16(&buf);
    object->crop_y = bytestream_get_be16(&buf);
    object->crop_w = bytestream_get_be16(&buf);
    object->crop_h = bytestream_get_be16(&buf);
}
```
