# VULN-001: do-while-blocks-zero OOB Heap Read in pcm_dvd S32 Encoder

## Vulnerability Details

- **File**: `libavcodec/pcm-dvdenc.c`
- **Function**: `pcm_dvd_encode_frame()`
- **Lines**: 119-165 (specifically 153-164 for the multi-channel S32 do-while)
- **CWE**: CWE-125 (Out-of-Bounds Read)

## Root Cause

In `pcm_dvd_encode_frame()`:

```c
int blocks = (pkt_size - 3) / s->block_size;
...
do {
    for (int i = s->groups_per_block; i; i--) {
        bytestream2_put_be16(&pb, src32[0] >> 16);
        bytestream2_put_be16(&pb, src32[1] >> 16);
        bytestream2_put_be16(&pb, src32[2] >> 16);
        bytestream2_put_be16(&pb, src32[3] >> 16);
        bytestream2_put_byte(&pb, (uint8_t)((*src32++) >> 8));
        bytestream2_put_byte(&pb, (uint8_t)((*src32++) >> 8));
        bytestream2_put_byte(&pb, (uint8_t)((*src32++) >> 8));
        bytestream2_put_byte(&pb, (uint8_t)((*src32++) >> 8));
    }
} while (--blocks);
```

When `frame->nb_samples < s->samples_per_block`:
- `pkt_size = (nb_samples / samples_per_block) * block_size + 3 = 0 * block_size + 3 = 3`
- `blocks = (3 - 3) / block_size = 0`

The `do { } while (--blocks)` construct **always executes the body at least once**, even when `blocks == 0`. After the first iteration, `--blocks` decrements 0 to -1 (signed integer, non-zero), so the condition is true and the loop continues. This cascades to -2, -3, ..., producing approximately 2^32 iterations (wrapping around INT_MIN eventually, all non-zero), each reading far outside the allocated frame buffer.

## Trigger Configuration

For 6-channel (5.1) S32 audio at 48kHz:
- `bits_per_coded_sample` = 24 (S32 maps to 24-bit DVD output)
- `block_size` = `4 * 6 * 24/8` = 72 bytes
- `samples_per_block` = 4
- `groups_per_block` = 6
- `frame_size` = `FFALIGN(2008/72, 4)` = `FFALIGN(27, 4)` = 28
- Bitrate = 6 * 3 * 8 * 48000 = 6,912,000 bps (within the 9,800,000 limit)

Note: 96kHz was not used because 6ch S32 at 96kHz exceeds the 9,800,000 bps bitrate limit
(`6 * 3 * 8 * 96000 = 13,824,000 bps`) and the encoder would reject the stream before
reaching the vulnerable code.

## PoC Strategy

1. **Create `vuln_001_input.wav`**: S32LE, 6 channels, 48kHz, **29 samples total**
   - 29 is chosen because `frame_size = 28`: FFmpeg will split into two frames:
     - Frame 1: 28 samples → `blocks = 28/4 = 7` → normal encoding
     - Frame 2: 1 sample  → `blocks = 1/4 = 0`  → triggers the bug

2. **Run through pcm_dvd encoder**:
   ```
   ffmpeg -i vuln_001_input.wav -c:a pcm_dvd -f vob output.vob
   ```

3. **Expected behavior** (with ASAN build):
   - On the first OOB read in the do-while body, ASAN reports `heap-buffer-overflow`
   - Without ASAN: the loop runs ~2^32 times, causing an extreme hang (near-infinite loop)
     or eventually a segfault when the OOB pointer exceeds valid mapped memory.

## Expected ASAN Output

```
=================================================================
==XXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 2 at 0x... thread T0
    #0 pcm_dvd_encode_frame libavcodec/pcm-dvdenc.c:155
    ...
```

## Files

- `vuln_001_gen.py`    — generates the crafted WAV input
- `vuln_001_run.sh`    — runs ffmpeg with the ASAN binary and captures output
- `vuln_001_input.wav` — generated 29-sample S32LE 6ch 48kHz WAV
- `vuln_001_result.txt`— combined output + ASAN log
- `vuln_001_status.txt`— VERIFIED_CRASH / VERIFIED_BEHAVIOR / UNVERIFIED / ERROR
