# VULN 001 - Integer overflow in DXVA2 AV1 bitstream size accumulation

## Status: SKIPPED

## Vulnerability Summary

- **Function:** `dxva2_av1_decode_slice()` in `libavcodec/dxva2_av1.c`
- **Lines:** 329-336
- **Type:** Integer overflow leading to heap OOB write
- **Trigger path:** `ffmpeg -i <crafted_av1.mp4> -hwaccel dxva2 -f null -`

## Reason for Skipping

This vulnerability cannot be triggered by passing a crafted media file to the ffmpeg command line on this system. Two fundamental conditions make it impossible to trigger:

### 1. Windows-only Hardware Acceleration

The vulnerability resides in the DXVA2 (DirectX Video Acceleration 2) and D3D11VA code paths, which are Windows-exclusive APIs. These hardware acceleration backends are not available on Linux. The `-hwaccel dxva2` and `-hwaccel d3d11va` options do not function on Linux systems. The current test system is running Linux (kernel 6.8.0-55-generic), so the vulnerable code path is never reached.

### 2. Impractical Data Volume Requirement

The overflow requires accumulating more than 4 GB of OBU (Open Bitstream Unit) data in a single decode operation to overflow a 32-bit unsigned integer counter. Crafting a media file that triggers this condition is impractical for a proof-of-concept exploit, as it would require a multi-gigabyte input file and the hardware to process it before any overflow check.

## Conclusion

Both conditions (Windows-only DXVA2/D3D11VA driver and >4 GB data requirement) independently make it impossible to trigger this vulnerability via a crafted media file on this Linux system. No PoC files (vuln_001_gen.py, vuln_001_run.sh, vuln_001_result.txt) were generated.
