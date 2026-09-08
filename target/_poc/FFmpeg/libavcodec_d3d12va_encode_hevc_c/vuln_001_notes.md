# Skip Notes: Heap OOB Write in d3d12va_encode_hevc_init_picture_params

## Vulnerability Summary

- **File**: `libavcodec/d3d12va_encode_hevc.c`, lines 622–664
- **Function**: `d3d12va_encode_hevc_init_picture_params()`
- **CWE**: CWE-787 (Out-of-bounds Write)
- **Root cause**: `pd` is allocated with `MAX_PICTURE_REFERENCES=2` entries. When encoding B-frames with `nb_refs[0] + nb_refs[1] >= 3`, writing to `pd[2]` and beyond corrupts heap memory.

## Skip Reason

### Platform Incompatibility

The `hevc_d3d12va` encoder relies on the **DirectX 12 Video Acceleration (D3D12VA)** API, which is a **Windows-only** API. It is not available on Linux, macOS, or any non-Windows platform.

**Verification steps performed:**

1. **Platform check**: System is `Linux 6.8.0-55-generic x86_64` — not Windows.

2. **Encoder availability check**:
   ```
   /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -encoders 2>/dev/null | grep d3d12
   ```
   Output: *(empty — no d3d12 encoders present)*

### Conclusion

The `hevc_d3d12va` encoder is not compiled into or available in the target ffmpeg binary. The vulnerable code path in `d3d12va_encode_hevc_init_picture_params()` is unreachable on this Linux system, regardless of the input media file or command-line flags used. No PoC can trigger this vulnerability on this platform.

## Files Generated

- `vuln_001_status.txt` — status: SKIPPED
- `vuln_001_notes.md` — this file

## Files NOT Generated (per skip rules)

- `vuln_001_gen.py` — not applicable
- `vuln_001_run.sh` — not applicable
