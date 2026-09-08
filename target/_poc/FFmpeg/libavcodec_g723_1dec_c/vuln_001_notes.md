# VULN 001 Notes: OOB Read / NULL Pointer Dereference in g723_1_decode_frame()

## Vulnerability Location

- File: `libavcodec/g723_1dec.c`
- Function: `g723_1_decode_frame()`
- Lines: 931-943

## Code Flaw

```c
const uint8_t *buf = avpkt->data;     // line 931
int buf_size       = avpkt->size;     // line 932
int dec_mode       = buf[0] & 3;      // line 933 -- BUG: read before size check
...
if (buf_size < frame_size[dec_mode] * channels) {  // line 943
    if (buf_size)
        av_log(...);
    *got_frame_ptr = 0;
    return buf_size;
}
```

`buf[0]` is read at line 933 unconditionally before `buf_size` is checked at line 943. If `avpkt->size == 0` and `avpkt->data == NULL`, this is a NULL pointer dereference. If `avpkt->size == 0` and `avpkt->data` points to a zero-length buffer, this is a 1-byte OOB heap read.

## PoC Approaches Tried

### Approach 1: AVI file with zero-size G.723.1 audio chunk
- Built a minimal RIFF/AVI file with a `00wb` audio chunk of size 0.
- Result: FFmpeg processed the file but produced no output frames. The AVI demuxer uses `av_get_packet(pb, pkt, 0)` which calls `av_new_packet(pkt, 0)` - this allocates `AV_INPUT_BUFFER_PADDING_SIZE` bytes, making `pkt->data` non-NULL. Then `avcodec_send_packet` rejects the packet (line 742: `if (avpkt && !avpkt->size && avpkt->data)` returns EINVAL).

### Approach 2: Raw g723_1 file (1 byte, dec_mode=3, frame_size=1)
- Created a 1-byte raw file with byte value `0x03` (so `dec_mode = 3`, `frame_size[3] = 1`).
- The g723_1 demuxer reads 1 byte, creates a 1-byte packet. The decoder is called with `size=1, data[0]=0x03`.
- The size check `1 < 1*1` is FALSE, so decoding proceeds past line 943.
- `buf[0]` is a valid read (the 1-byte packet is well-formed). No crash, decoder produces a frame.

### Approach 3: WAV file with zero-size data chunk
- Built a RIFF/WAVE file with codec tag 0x0042 (G.723.1) and empty `data` chunk.
- Result: FFmpeg detected the stream but produced no audio packets (zero-size data chunk results in immediate EOF). No decoder call.

### Approach 4: Empty raw g723_1 file (0 bytes)
- Created an empty file as input to the g723_1 raw demuxer.
- The demuxer's `avio_r8()` returns 0 on EOF, then `av_new_packet(pkt, frame_size[0]=24)` tries to read 23 more bytes, gets AVERROR_EOF. No packet produced.

### Approach 5: AVI file with 3-byte G.723.1 audio chunk
- 3-byte audio data with `data[0]=0x00` (dec_mode=0), but frame_size[0]=24 needs 24 bytes.
- Decoder called with size=3 packet. `buf[0]` read is valid. Size check fails: `3 < 24` → warning printed, early return. No crash.

## Root Cause Analysis: Why UNVERIFIED

The vulnerability cannot be triggered via the standard `ffmpeg` CLI due to three layers of protection in modern FFmpeg:

1. **avcodec_send_packet guard** (`decode.c:742`): Rejects packets with `size=0 && data!=NULL`:
   ```c
   if (avpkt && !avpkt->size && avpkt->data)
       return AVERROR(EINVAL);
   ```

2. **Flush packet check** (`decode.c:449-451`): Since g723_1 decoder has only `AV_CODEC_CAP_DR1` (NOT `AV_CODEC_CAP_DELAY`), flush packets (data=NULL) return AVERROR_EOF without calling the decoder:
   ```c
   if (!pkt->data && !(avctx->codec->capabilities & AV_CODEC_CAP_DELAY))
       return AVERROR_EOF;
   ```

3. **Padding allocation**: `av_new_packet(pkt, 0)` allocates `AV_INPUT_BUFFER_PADDING_SIZE` (64) bytes, so `pkt->data` is always non-NULL for packets created by demuxers. Reading `buf[0]` hits the zeroed padding area, which is within the actual allocated buffer, so ASAN does not flag it.

## Exploitability Assessment

The code flaw (CWE-125/CWE-476) at line 933 is a genuine logic error: `dec_mode` is computed from `buf[0]` before any size validation, which is incorrect design. However, it is **not exploitable via the ffmpeg CLI** in the current codebase because multiple guard layers prevent the decoder from receiving a zero-size or null-data packet.

The vulnerability would be exploitable in:
- A fuzzing harness that directly calls `g723_1_decode_frame()` with a crafted `AVPacket` having `data=malloc(0)` and `size=0` (ASAN would flag the 1-byte OOB read)
- A custom integration that bypasses `avcodec_send_packet` and calls the codec callback directly
- Older versions of FFmpeg where the `avcodec_send_packet` size guard did not exist

## Files

- `vuln_001_gen.py`: Generates all test input files
- `vuln_001_run.sh`: Runs all PoC approaches
- `vuln_001_result.txt`: Full output from all approaches
- `vuln_001_input.avi`: AVI with zero-size G.723.1 chunk
- `vuln_001_input.g723_1`: 1-byte raw G.723.1 file
- `vuln_001_input.wav`: WAV with zero-size G.723.1 data
