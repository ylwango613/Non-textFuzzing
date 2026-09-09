# VULN 001 - Signed Integer Overflow in max_pkt_size (vulkan_encode_issue)

## Status: SKIPPED

## Reason

The vulnerability resides in the Vulkan video encoding path (`libavcodec/vulkan_encode.c`), specifically in the `vulkan_encode_issue()` function. Triggering it requires:

1. **A Vulkan-capable GPU** with hardware video encoding support (e.g., NVIDIA RTX/Quadro with NVENC via Vulkan, AMD with VCE via Vulkan, or Intel with QSV via Vulkan).
2. **Vulkan drivers** installed and functional on the system.
3. **FFmpeg built with Vulkan support** (`--enable-vulkan`).

### Environment Check Results

- `ffmpeg -encoders | grep -i vulkan`: No output (no Vulkan encoders registered).
- `ffmpeg -hwaccels`: Lists no hardware acceleration methods at all.
- The build configuration shows no Vulkan-related flags (`--enable-vulkan` is absent).

The FFmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` was built without Vulkan support, and no compatible GPU hardware is available in this environment.

## Vulnerability Details (for reference)

**File**: `libavcodec/vulkan_encode.c`
**Function**: `vulkan_encode_issue()`
**Lines**: 160-194
**CWE**: CWE-190 (Integer Overflow or Wraparound)

**Vulnerable code pattern**:
```c
int max_pkt_size;
// ...
max_pkt_size = FFALIGN(3 * ctx->base.surface_width * ctx->base.surface_height + (1 << 16), alignment);
```

When `surface_width` and `surface_height` are both `int`, and their product exceeds ~715,827,882 pixels (e.g., 26754x26754), the expression `3 * surface_width * surface_height` overflows a 32-bit signed integer (UB per C standard), potentially resulting in a small or negative `max_pkt_size`. This leads to heap underallocation and subsequent out-of-bounds write when the actual encoded bitstream is written into the undersized buffer.

## How to Test (if Vulkan hardware were available)

```bash
# Generate a crafted MP4 with extreme dimensions (e.g., 26754x26754)
python3 vuln_001_gen.py

# Run the transcoding to trigger the overflow
./vuln_001_run.sh
```

The trigger condition is: `3 * w * h > INT_MAX` => `w * h > 715,827,882`.
For square frames: `w = h = ceil(sqrt(715827883)) = 26755` would be sufficient.

## Attack Vector

A crafted media file with extreme frame dimensions (width x height > ~715M pixels) passed to ffmpeg for Vulkan-based HEVC encoding would trigger the overflow at buffer allocation time, potentially leading to a heap corruption condition.
