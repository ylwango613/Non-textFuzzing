# PoC Notes: Off-by-one OOB Write in g722_encode_trellis

## Vulnerability Summary

- **CWE**: CWE-193 (Off-by-one Error)
- **Function**: `g722_encode_trellis()` in `libavcodec/g722enc.c` (lines 311-317)

## Root Cause

When `frame->nb_samples` is even (e.g., 320, the default G.722 frame size),
`out_size = nb_samples / 2`. The final backtracking loop writes one byte to
`dst[nb_samples/2]` = `dst[out_size]`, which is exactly one byte past the
end of the `avpkt->data` heap allocation.

## PoC Approach

1. `vuln_001_gen.py` generates a valid 16kHz mono 16-bit PCM WAV file with
   3200 samples (10 G.722 frames of 320 samples each). An even sample count
   per frame is required to trigger the OOB condition.

2. `vuln_001_run.sh` feeds the WAV to the ASAN-instrumented FFmpeg binary,
   enabling G.722 encoding with trellis search (`-trellis 1`).

## Trigger Command

```bash
ffmpeg -i vuln_001_input.wav -c:a g722 -trellis 1 -f null -
```

## Expected ASAN Output

```
WRITE of size 1 at 0x... thread T0
    #0 ... in g722_encode_trellis libavcodec/g722enc.c:31x
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow ...
```
