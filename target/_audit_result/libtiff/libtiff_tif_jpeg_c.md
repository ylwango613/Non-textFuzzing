Now I have a complete understanding of the code. Let me confirm the exact buffer overflow calculation.

For width=1, YCbCr 4:2:0 (h_samp=2, v_samp=2), 8-bit, rps=2:

- `TIFFVStripSize(2)`: w=roundup(1,2)=2, scanline=2, nrows_rounded=2, total_Y=4, extra=2 → **stripsize=6 bytes**
- `TIFFOldScanlineSize` = 1×3 = **3 bytes** (used as `bytesperline`)
- `nrows = 6/3 = 2`; image_height check: `2 > 2` = false → stays 2
- `clumps_per_line = comp_info[1].downsampled_width = ceil(1/2)=1`
- `samples_per_clump = 2×2+1×1+1×1 = 6`

**Iteration 1** (`buf = original_buf`): Y writes idx 0,1; Cb writes idx 2; Cr writes idx 3. Then `buf += 3`.

**Iteration 2** (`buf = original_buf+3`): Y writes idx 3,4; Cb writes idx 5; Cr writes idx 6. **idx 6 is 1 byte past the 6-byte buffer** → **heap overflow**.

The comment on line 1093-1094 explicitly admits: *"increment/decrement of buf and cc is still incorrect, but should not matter – TODO: resolve this"* — confirming this is a known inconsistency but the authors underestimated its impact.

## VULN: JPEGDecodeRaw Heap Buffer Overflow via Incorrect bytesperline for YCbCr Subsampled TIFF
- **漏洞类别**: memory-safety
- **函数**: JPEGDecodeRaw()
- **行号**: 984-1097
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: Application calls TIFFReadEncodedStrip() → TIFFFillStrip() → TIFFStartStrip() → JPEGPreDecode() [sets sp->bytesperline = TIFFOldScanlineSize() = width*spp*bps/8, ignoring YCbCr subsampling] → TIFFReadEncodedStrip() calls tif->tif_decodestrip = JPEGDecodeRaw() with cc=TIFFVStripSize() [rounds up correctly] → heap OOB write
- **描述**: `JPEGPreDecode()` (line 716) 将 `sp->bytesperline` 设置为 `TIFFOldScanlineSize(tif)`，该函数按公式 `ceil(bps × width × spp / 8)` 计算，不考虑 YCbCr 下采样。而调用方 `TIFFReadEncodedStrip()` 传给解码器的缓冲区大小 `cc` 来自 `TIFFVStripSize()`，后者正确对宽度向上取整（roundup to h_samp boundary）后计算。两者不一致导致 `nrows = cc / bytesperline` 偏大：在 `JPEGDecodeRaw()` 的 do-while 循环里，第二次迭代将 `buf` 指针推进了 `bytesperline` 字节后，对 Cr 分量的写入（`outptr[0] = *inptr++` 在 `clumpoffset + 3` 处）落在了原始分配缓冲区之外，发生堆越界写（1 字节）。代码注释 line 1093-1094 明确承认 "increment/decrement of buf and cc is still incorrect" 但认为无关紧要。
- **触发条件**: 构造 TIFF 文件满足：`PHOTOMETRIC_YCBCR`、`PLANARCONFIG_CONTIG`、`JPEGCOLORMODE_RAW`（默认）、`YCbCrSubSampling=(2,2)`（4:2:0）、`ImageWidth=1`（或任意小的值使得 `TIFFVStripSize / TIFFOldScanlineSize > 1`）、`RowsPerStrip=2`（或任意 ≥2 的偶数）、使用 JPEG 压缩。当宿主应用程序调用 `TIFFReadEncodedStrip()` 时触发。
- **安全影响**: 攻击者控制的 1 字节堆越界写，可破坏 glibc malloc chunk 元数据，在 heap feng-shui 条件下升级为任意代码执行（RCE）；最低后果为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
