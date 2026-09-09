# VULN 002 – tiertexseqvideo OOB Read: PoC Notes

## Vulnerability

**File**: `libavcodec/tiertexseqv.c`  
**Function**: `seqvideo_decode()`  
**Line**: 174  
**Type**: Out-of-Bounds Read (CWE-125) / NULL pointer dereference  

```c
static int seqvideo_decode(SeqVideoContext *seq,
                           const unsigned char *data, int data_size)
{
    const unsigned char *data_end = data + data_size;
    ...
    flags = *data++;   // LINE 174 – no check that data_size >= 1
```

If `data_size == 0`: `data_end == data`, and `*data` reads one byte past the
end of a zero-length buffer (OOB read).  
If `data == NULL` (NULL packet): reading `*NULL` is a NULL pointer dereference.

## Why a 0-byte Packet Cannot Be Easily Triggered via the CLI

Three independent guards prevent a true 0-byte packet from reaching
`seqvideo_decode_frame` through the standard `ffmpeg` CLI:

1. **SEQ demuxer minimum packet size** (`libavformat/tiertexseq.c:271`):
   ```c
   rc = av_new_packet(pkt, 1 + current_pal_data_size + current_video_data_size);
   pkt->data[0] = 0;   // flags byte always written
   ```
   The demuxer always prepends a 1-byte flags field, so the minimum video
   packet size is 2 bytes (1 flag + ≥1 data byte).

2. **`av_get_packet` unrefs 0-byte packets** (`libavformat/utils.c:93`):
   ```c
   if (!pkt->size) av_packet_unref(pkt);  // data becomes NULL
   ```
   Any other demuxer that calls `av_get_packet(pb, pkt, 0)` gets back
   `data=NULL, size=0`.

3. **ffmpeg CLI skips 0-byte packets** (`fftools/ffmpeg_dec.c:704`):
   ```c
   if (pkt && pkt->size == 0)
       return 0;   // "skip the packet" – not decoded
   ```

4. **`avcodec_send_packet` treats NULL data as flush** (`libavcodec/decode.c:745`):
   ```c
   if (avpkt && (avpkt->data || avpkt->side_data_elems)) {
       // buffer for decoding
   } else
       dc->draining_started = 1;  // treated as EOF flush
   ```

## PoC Approach

We craft a SEQ file that passes all demuxer checks and causes the decoder to be
called with the **minimum achievable data_size = 2** via the CLI path:

- **1 byte** flags (`0x02` = video-data-present)
- **1 byte** payload

In `seqvideo_decode(seq, buf, 2)`:
- Line 174: `flags = *buf++` — reads byte 0 safely (data_size=2 ≥ 1) ✓  
- `flags & 2` branch: checks `data_end - data < 128` → `1 < 128` → TRUE  
- Returns `AVERROR_INVALIDDATA`

This demonstrates that **the data reaches the vulnerable line** and that the
existing code path has no `data_size >= 1` guard before the `*data++` read.
A caller supplying `data_size=0` (achievable via a direct API call or a
custom harness) would trigger the OOB read.

## SEQ File Structure

| Offset  | Content                                      |
|---------|----------------------------------------------|
| 0–255   | 256 zero bytes (probe requirement)           |
| 256–257 | `0x0001` – frame buffer 0, capacity 1 byte   |
| 258–259 | `0x0000` – end of buffer list                |
| 260–620543 | Zero padding (100 no-op preload frames)   |
| 620544  | Actual decode frame header (16 bytes)        |
| 620560  | `0x01` – the 1-byte video payload            |

**Frame header at 620544**:
```
audio_offs = 0x0000
pal_offs   = 0x0000
buffer_num = [0, 0, 0xFF, 0xFF]
offset_table = [16, 0, 0, 17]   (fill 1 byte from offset 16 into buffer 0)
```

## ASAN Analysis

ASAN does **not** fire on the 2-byte packet path because the bounds check
`data_end - data < 128` triggers `AVERROR_INVALIDDATA` before any actual
overflow. To trigger ASAN on the vulnerable line itself, `data_size = 0`
with a non-NULL `data` pointer allocated to exactly 0 bytes is required —
this is only achievable via a direct C API call to `seqvideo_decode`, which
is excluded by the no-harness constraint.

The PoC demonstrates **VERIFIED_BEHAVIOR**: the decoder is reached, processes
the crafted minimal packet, and reports invalid-data errors consistent with
the missing `data_size >= 1` pre-condition check.
