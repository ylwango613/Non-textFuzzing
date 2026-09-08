After completing a full two-pass read of all 487 lines of `h264qpel_lsx.c` and examining the supporting assembly macro `h264_qpel8_hv_lowpass_core_lsx` in `h264qpel.S` and the header `h264qpel_loongarch.h`, the analysis shows:

**Buffer sizing (all correct):**
- 8×8 intermediate stack buffers: `half[64]`, `halfH[64]`, `halfV[64]` — written by `put_h264_qpel8_*_lowpass_lsx` with `dstStride=8` → 8 rows × 8 bytes = 64 bytes ✓  
- Paired 8×8 temps: `temp[128]` split as `halfH=temp[0..63]` and `halfHV=temp[64..127]` ✓  
- 16×16 single intermediate: `half[256]` — written with `dstStride=16` → 16 rows × 16 bytes = 256 bytes ✓  
- Paired 16×16 temps: `temp[512]` split as `halfHV=temp[0..255]` and `halfH=temp[256..511]` — assembly macro `put_pixels16_l2_8_lsx` reads 256 bytes from each via 4× `vld/addi.d 0x40` pattern ✓

**No untrusted input:** These are pure pixel-processing kernels called from the H.264 motion-compensation path with pre-allocated, pre-validated frame buffers. No dynamic allocation, no size fields read from the bitstream, no parser logic.

**Assembly writes confirmed:** `h264_qpel8_hv_lowpass_core_lsx` uses `vstelm.d` (8-byte store) × 8 with explicit `add.d dst, dst, stride` advances — writes exactly 8 rows × 8 bytes, perfectly matching the stack buffer sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
