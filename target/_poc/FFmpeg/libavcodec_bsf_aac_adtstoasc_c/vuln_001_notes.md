# PoC: CWE-191 Integer Underflow in aac_adtstoasc_filter()

## Vulnerability

**File**: `libavcodec/bsf/aac_adtstoasc.c`, lines 82–95  
**Function**: `aac_adtstoasc_filter()`  
**CWE**: CWE-191 (Integer Underflow)

### Root Cause

When `hdr.chan_config == 0`, the BSF enters the PCE path:

```c
init_get_bits(&gb, pkt->data, pkt->size * 8);   // safe cap at pkt->size*8 + 8
...
ff_copy_pce_data(&pb, &gb);                      // reads PCE including comment
pkt->size -= get_bits_count(&gb) / 8;            // ← UNDERFLOW
pkt->data += get_bits_count(&gb) / 8;
```

Inside `ff_copy_pce_data` (`libavcodec/mpeg4audio_copy_pce.h`), after reading the
PCE structure (56 bits = 7 bytes), it reads:

```c
comment_size = ff_pce_copy_bits(pb, gb, 8);      // reads 1-byte count
for (; comment_size > 0; comment_size--)
    ff_pce_copy_bits(pb, gb, 8);                  // reads comment_size bytes
```

With `comment_size = 0xFF` (255) but only a few bytes of actual data, the safe
bitstream reader caps the internal index at `pkt->size * 8 + 8`.  Back in
`aac_adtstoasc_filter`:

```
get_bits_count(&gb) / 8 == (pkt->size * 8 + 8) / 8 == pkt->size + 1
pkt->size -= (pkt->size + 1)   →   pkt->size = -1
```

The function returns 0 (success) at line 120 with `pkt->size = -1`.

## Crafted Input

An ADTS frame with `channel_config = 0` triggers the PCE path.  The PCE
payload declares `comment_field_bytes = 0xFF` (255) but the packet contains
only 3 actual comment bytes after the comment-size field, so the safe reader
always hits its cap.

**Bit layout of the 10-byte PCE payload:**

| Bits  | Field                          | Value |
|-------|-------------------------------|-------|
| 0-2   | id_syn_ele (PCE)               | 5     |
| 3-6   | element_instance_tag           | 0     |
| 7-8   | object_type (LC)               | 1     |
| 9-12  | sampling_freq_index (48 kHz)   | 3     |
| 13-16 | num_front                      | 1     |
| 17-20 | num_side                       | 0     |
| 21-24 | num_back                       | 0     |
| 25-26 | num_lfe                        | 0     |
| 27-29 | num_assoc_data                 | 0     |
| 30-33 | num_valid_cc                   | 0     |
| 34    | mono_mixdown_present           | 0     |
| 35    | stereo_mixdown_present         | 0     |
| 36    | matrix_mixdown_idx_present     | 0     |
| 37-41 | front[0]: SCE, instance_tag=0  | 0b0\_0000 |
| 42-47 | align_get_bits padding         | 0     |
| 48-55 | comment_field_bytes            | **0xFF** ← trigger |
| 56-79 | 3 bytes actual data (not 255)  | 0x41 0x41 0x41 |

## Container Strategy

A raw `.aac` file triggers the FFmpeg AAC decoder during `avformat_find_stream_info`.
The malformed PCE causes the decoder to fail, leaving `sample_rate=0, channels=0`,
which prevents the MP4 muxer from opening its header — and therefore prevents the
BSF from ever being invoked.

To bypass this, the malicious ADTS frame is wrapped in a minimal **AVI** container.
The AVI demuxer reads `sample_rate` and `channels` directly from the `WAVEFORMATEX`
structure in the container (without decoding the audio payload), so codec-parameter
detection succeeds.  When copying to MP4, FFmpeg automatically inserts the
`aac_adtstoasc` BSF, which processes the ADTS frame and triggers the underflow.

## Observed Behaviour

```
[aac @ ...] decode_pce: Input buffer exhausted before END element found
Stream #0:0 -> #0:0 (copy)
[out] video:0KiB audio:0KiB ...
```

- The BSF is confirmed applied: `"Automatically inserted bitstream filter 'aac_adtstoasc'"`
- `pkt->size` underflows to `-1`; `pkt->data` advances 1 byte past end of heap buffer
- `avio_write(pb, pkt->data, -1)` checks `if (size <= 0) return;` and exits cleanly
- Audio data is silently dropped; no ASan/UBSan crash in this muxer path

## Status

**VERIFIED_BEHAVIOR** — The integer underflow occurs exactly as described.
`aac_adtstoasc_filter()` returns 0 (success) with `pkt->size = -1`.
The immediate downstream guard in `avio_write` prevents a crash in this test
scenario, but the corrupted packet could cause crashes in other consumers or
library callers that do not guard against negative `pkt->size`.
