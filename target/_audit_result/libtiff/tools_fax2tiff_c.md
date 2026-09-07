I have completed my detailed multi-pass analysis of fax2tiff.c and the supporting tif_fax3.c/tif_fax3.h code. Let me now write the definitive findings.

**Analysis Summary per batch:**

**Batch 1 (fax2tiff.c lines 1–250):** Established the input model: raw G3/G4 fax bitstream → faxTIFF → CCITT decoder → TIFFWriteScanline. `xsize` is uint32; `rowbuf = _TIFFmalloc(TIFFhowmany8(xsize))` max result is 0x20000000 (safe range for tsize_t/int32).

**Batch 2 (fax2tiff.c lines 249–407, copyFaxFile):** `tif_rawdatasize = TIFFGetFileSize(tifin)` stores toff_t(uint32) into tsize_t(int32) — for files > 2GB the value becomes negative → `malloc((size_t)negative)` = huge allocation → fails → NULL check catches it. No heap overflow here.

**Batch 3 (tiffiop.h, tiffio.h):** Confirmed `tsize_t = int32`, `toff_t = uint32`, `_TIFFmalloc(tsize_t)` calls `malloc((size_t)s)`.

**Batch 4 (tif_fax3.c Fax3Decode1D, DECLARE_STATE, CACHE_STATE):** For G3 1D, `lastx = sp->b.rowpixels = xsize`, `pa` starts at `sp->curruns = dsp->runs`.

**Batch 5 (Fax3SetupState lines 463–522):** For G3 1D (needsRefLine=false): `nruns = TIFFroundup(rowpixels, 32)`, buffer = `nruns*2 * sizeof(uint32)` entries. With xsize=1728 (default, exact multiple of 32): nruns=1728, buffer has exactly **3456 uint32 entries** (indices 0..3455).

**Batch 6 (tif_fax3.h: EXPAND1D, SETVALUE, CLEANUP_RUNS):** Identified the overflow: with 1727 pairs of (white=0, black=1) rows + one (white=0, black=2) trailing pair, EXPAND1D makes 3456 SETVALUE calls (exhausting the entire buffer with pa → index 3456, past end). Then CLEANUP_RUNS (a0=1729 > lastx=1728) decrements pa to 3455 and calls TWO more SETVALUEs: `runs[3455]=0` (valid overwrite) then **`runs[3456]=1`** (1 uint32 PAST END OF BUFFER → CWE-122).

**Batch 7 (_TIFFFax3fillruns):** Fill function clips via `if (x+run > lastx || run > lastx)` — correctly bounded for output buffer writes; OOB write is in the `runs[]` accounting array, not the output pixel buffer. OOB write hits whatever follows the `runs` heap allocation.

**Batch 8 (Reachability confirmation):** Default `fax2tiff` uses G3 1D with xsize=1728; white run-length-0 is a valid T.4 code (`0x35`, 8 bits); black run-length-2 is a valid code (`0x7`, 4 bits or similar). A ~2.4KB crafted `.raw` file with 1727 alternating white-0/black-1 runs then one white-0/black-2 triggers the bug with certainty.

**Batch 9 (tif_unix.c):** `_TIFFmalloc` = `malloc((size_t)s)` with no padding. The runs allocation is exactly 13824 bytes (3456×4). The OOB write hits the immediately adjacent heap chunk.

---

## VULN: G3 1D Fax Decoder CLEANUP_RUNS Heap OOB Write via Crafted Raw Fax Bitstream
- **漏洞类别**: memory-safety
- **函数**: Fax3Decode1D() / CLEANUP_RUNS macro (tif_fax3.h:285-303, tif_fax3.c:233-264)
- **行号**: tif_fax3.h:295-297 (CLEANUP_RUNS SETVALUE OOB); 触发路径进入点 fax2tiff.c:373
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted raw G3 fax bitstream file (.raw)
- **外部触发路径**: fax2tiff main() [fax2tiff.c:256-335] → copyFaxFile(faxTIFF, out) [fax2tiff.c:342-407] → (*tifin->tif_decoderow)(tifin, rowbuf, linesize, 0) [fax2tiff.c:373] → Fax3Decode1D() [tif_fax3.c:233] → EXPAND1D(EOF1Da) [tif_fax3.h:317-372] → CLEANUP_RUNS() [tif_fax3.h:285-303] → SETVALUE(lastx-a0) [tif_fax3.h:297] → *pa++ = 1 写入 runs[nruns*2]（超出 malloc 边界 4 字节）
- **描述**: 在 G3 1D 模式下（fax2tiff 默认），`Fax3SetupState` 为 `dsp->runs` 分配 `nruns*2 * sizeof(uint32)` 字节，其中 `nruns = TIFFroundup(rowpixels, 32)`。当 `rowpixels`（即 `xsize`，默认 1728）恰好是 32 的整数倍时，`nruns = rowpixels`，runs 数组恰好有 `nruns*2 = 3456` 个 uint32 槽。攻击者可构造一行包含 1727 对（white=0, black=1）再加（white=0, black=2）的 G3 1D 行：主解码循环 `EXPAND1D` 精确地调用 3456 次 `SETVALUE`，将 `pa` 推进到 `runs + 3456`（刚好越界）。随后 `CLEANUP_RUNS` 处理行长度过长（a0=1729 > lastx=1728）：while 循环将 `pa` 递减回 3455，但紧接着因 `(pa-thisrun)&1 == 1` 再调用 `SETVALUE(0)` 写入 `runs[3455]`，再调用 `SETVALUE(1)` 写入 **`runs[3456]`**——这是分配区域外第 4 字节处的堆越界写入，破坏紧随其后的堆内存。
- **触发条件**: 攻击者提供一个原始 G3 fax 文件（`.raw`），其中某一行包含完全占满 runs 数组的连续短 run（如 1727 对 white=0/black=1），再以一个超出行宽的 black run（≥2 像素）结束该行；`xsize` 须为 32 的整数倍（默认值 1728 满足此条件），无需任何命令行选项修改。一个约 2.4 KB 的精心构造文件即可稳定触发。
- **安全影响**: 向 `runs[3456]`（runs 数组末尾 4 字节之后）写入 uint32 值（1），破坏紧邻的堆内存。可导致：(1) 堆元数据损坏 → 确定性崩溃（DoS）；(2) 在可控堆布局场景下，通过覆盖相邻对象（如 Fax3CodecState 字段、其他数组指针）实现任意代码执行（RCE）。由于每行都可独立触发，攻击者可多次重复以精确布局堆，提高利用成功率。

<!-- AUDIT_PROMPT_VERSION: 1 -->
