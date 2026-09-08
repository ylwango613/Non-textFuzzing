# VULN 001: OOB Heap Read in joint_decode via js_subband_start

## Vulnerability

- **File**: `libavcodec/cook.c`
- **Function**: `joint_decode()`
- **Lines**: 851–855
- **Type**: CWE-125 Out-of-bounds Read

```c
for (i = 0; i < p->js_subband_start; i++) {      // line 851
    for (j = 0; j < SUBBAND_SIZE; j++) {           // line 852 (SUBBAND_SIZE=20)
        mlt_buffer_left[i  * 20 + j] = decode_buffer[i * 40 + j];        // 853
        mlt_buffer_right[i * 20 + j] = decode_buffer[i * 40 + 20 + j];   // 854
    }
}
```

With `js_subband_start = 50`, `i` runs 0..49. Maximum index into `decode_buffer`
is `49 * 40 + 20 + 19 = 1999`. The buffer is allocated based on `samples_per_channel`
(512 in our case → 512 floats per channel → 1024 floats interleaved). Max valid index
is well below 1999, so the loop reads past the end of the heap buffer.

The only guard is `js_subband_start >= 51` (line 1124), which rejects 51+ but allows
50. An attacker sets `js_subband_start = 50` to stay just under this check.

## Trigger Conditions

| Parameter | Value | Constraint |
|-----------|-------|------------|
| `cookversion` | `0x1000003` (JOINT_STEREO) | enables `js_subband_start` path |
| `nb_channels` | 2 | JOINT_STEREO requires channels == 2 |
| `js_subband_start` | 50 | must be < 51; 50 is the max trigger value |
| `subbands` | 3 | `total_subbands = 50+3 = 53 ≤ 53` (max allowed) |
| `js_vlc_bits` | 6 | must be 2..6 |
| `samples_per_frame` | 1024 | `samples_per_channel = 512` (valid: must be 256/512/1024) |

## PoC Approach

1. `vuln_001_gen.py` constructs a minimal RealMedia (`.rm`) file from scratch using
   Python's `struct` module. No external tools or libraries required.
2. The file contains:
   - Standard RMFF container chunks (RMF, PROP, MDPR, CONT, DATA)
   - An MDPR chunk with a RA version-5 header for the COOK codec
   - COOK extradata with `js_subband_start = 50`
   - Two GENR-interleaved audio packets (each 1024 bytes of null data)
3. `vuln_001_run.sh` generates the file and runs the ASAN-instrumented `ffmpeg` binary.

## Attack Vector

```
ffmpeg -i crafted.rm -f null -
  → avformat_open_input
    → rm_read_header (rmdec.c)
      → ff_rm_read_mdpr_codecdata
        → rm_read_audio_stream_info  (parses RA5 header, sets block_align, extradata)
  → avcodec_open2 (cook.c: cook_decode_init)
    → reads cookversion, js_subband_start=50 from extradata
    → validates: 50 < 51 ✓, total_subbands=53 ≤ 53 ✓
  → avcodec_send_packet / avcodec_receive_frame (cook.c: cook_decode_frame)
    → decode_subpacket → joint_decode
      → loop i=0..49: decode_buffer[i*40 + 20 + j]  ← OOB READ
```
