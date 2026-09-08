# VULN 001: decode_adpcm_ima_hvqm4 Mono Off-by-One Heap OOB Write

**CWE**: CWE-122 (Heap-based Buffer Overflow)
**File**: `libavcodec/adpcm.c`, lines 647–658
**Function**: `decode_adpcm_ima_hvqm4()`

## Vulnerability Analysis

### Root Cause

In `decode_adpcm_ima_hvqm4()`, when processing **mono** audio with `frame_format=1` or `frame_format=3`:

1. `get_nb_samples()` computes `nb_samples = (buf_size - skip) * 2` (always even, call it N)
   - For mono + ff=1: `skip = 6 + 2*1 = 8`, so `nb_samples = (buf_size - 8) * 2`
2. `ff_get_buffer()` allocates exactly **N** `int16_t` values (= N×2 bytes)
3. `decode_adpcm_ima_hvqm4()` is called with `samples_to_do = N`

### Off-by-One Logic (lines 647–658)

```c
if (frame_format == 1 || frame_format == 3) {
    for (int ch = 0; ch < avctx->ch_layout.nb_channels; ch++)
        *outbuf++ = (int16_t)c->status[st - ch].predictor;  // writes 1 sample
    samples_to_do--;  // N-1 (odd, since N is even)
}

for (int i = 0; i < samples_to_do; i += 1+(!st)) {  // stride=2 for mono (st=0)
    uint8_t nibble = bytestream2_get_byte(gb);
    *outbuf++ = ff_adpcm_ima_qt_expand_nibble(&c->status[st], nibble & 0xF);
    *outbuf++ = ff_adpcm_ima_qt_expand_nibble(&c->status[ 0], nibble >>  4);
}
```

For mono (st=0, stride=2), samples_to_do=N-1 (odd):
- Predictor loop writes **1** sample
- Main loop: `ceil((N-1)/2) = N/2` iterations × 2 samples = **N** samples
- **Total: N+1 samples written into a buffer of N** → 2-byte heap OOB write

### Triggering Conditions

- Mono audio (`channels = 1`)
- `frame_format = 1` or `frame_format = 3` (first 2 bytes of packet, big-endian)
- `buf_size > skip` (packet length > 8 for ff=1, > 9 for ff=3)

## Crafted File Structure

The PoC generates a minimal AVI file with one mono ADPCM_IMA_HVQM4 audio stream.

### Malicious Packet Layout (12 bytes, frame_format=1)

| Offset | Bytes | Purpose |
|--------|-------|---------|
| 0–1    | `00 01` | frame_format=1 (big-endian) |
| 2–5    | `00 00 00 00` | Skipped by main CASE handler |
| 6–7    | `00 00` | predictor+step_index (case 1 header read in decode function) |
| 8–11   | `00 00 00 00` | ADPCM nibble payload (4 bytes) |

### Overflow Calculation

```
buf_size = 12
nb_samples = (12 - 8) * 2 = 8
buffer allocation = 8 × sizeof(int16_t) = 16 bytes

writes:
  predictor:  1 sample  (outbuf[0])
  loop iter0: 2 samples (outbuf[1], outbuf[2])
  loop iter1: 2 samples (outbuf[3], outbuf[4])
  loop iter2: 2 samples (outbuf[5], outbuf[6])
  loop iter3: 2 samples (outbuf[7], outbuf[8])  ← OOB!

total: 9 writes, 18 bytes → 2-byte write at outbuf[8] is out of bounds
```

## Limitation

`CONFIG_ADPCM_IMA_HVQM4_DECODER=0` in the test build (`build_test/config_components.h`).
The `adpcm_ima_hvqm4` decoder is **not registered** in the test binary, so ffmpeg
cannot decode HVQM4 audio. The function `decode_adpcm_ima_hvqm4` is compiled into
`adpcm.o` (shared with other ADPCM decoders) but the codec entry point is not exposed.

Additionally, `AV_CODEC_ID_ADPCM_IMA_HVQM4` has no WAVE format tag registered in
`libavformat/riff.c`, so the AVI demuxer cannot identify it by `wFormatTag`.

To trigger this vulnerability, the build would need `CONFIG_ADPCM_IMA_HVQM4_DECODER=1`.

## External Trigger Path (if decoder were enabled)

```
ffmpeg -i vuln_001_input.avi -f null -
  → avformat_open_input()
  → avcodec_send_packet()
  → adpcm_decode_frame()
  → get_nb_samples()  [nb_samples = (buf_size-8)*2 = 8]
  → ff_get_buffer()   [allocates 8 × int16_t = 16 bytes]
  → decode_adpcm_ima_hvqm4()  [writes 9 × int16_t → 2-byte heap OOB]
```
