Confirmed. EXPAND1D (lines 363–364 of tif_fax3.h) has the zero-run rollback `if (*(pa-1)==0 && *(pa-2)==0) pa -= 2`, but EXPAND2D has no equivalent guard. This is the key asymmetry.

**Summary of analysis across all 1626 lines:**

- **Lines 463–550 (`Fax3SetupState`)**: `nruns` and malloc properly protected by `TIFFSafeMultiply` and the `nruns==0` check. No overflow here.
- **Lines 150–175 (`Fax3PreDecode`)**: Benign setup.
- **Lines 232–318 (`Fax3Decode1D`, `Fax3Decode2D`)**: 1D path safe (rollback). 2D path vulnerable (see below).
- **Lines 366–451 (`_TIFFFax3fillruns`)**: All writes bounded by `lastx` clamping; no OOB from this function alone.
- **Lines 1426–1467 (`Fax4Decode`)**: Uses EXPAND2D — same vulnerability.
- **tif_fax3.h EXPAND2D**: S_Horiz case calls SETVALUE twice per iteration, no bounds check on `pa`, no rollback for zero-length runs.

## VULN: Heap Buffer Overflow via Unbounded pa Write in EXPAND2D (G3-2D/G4 Decoder)
- **漏洞类别**: memory-safety
- **函数**: Fax3Decode2D(), Fax4Decode() (via EXPAND2D macro in tif_fax3.h)
- **行号**: tif_fax3.h:388–530 (EXPAND2D macro), tif_fax3.c:271–318 (Fax3Decode2D), tif_fax3.c:1426–1467 (Fax4Decode)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → Fax3SetupState() [allocates dsp->runs buffer of 2*nruns uint32 entries] → TIFFReadEncodedStrip()/TIFFReadScanline() → Fax3PreDecode() → Fax4Decode()/Fax3Decode2D() → EXPAND2D macro → S_Horiz branch → SETVALUE() increments pa past end of dsp->runs
- **描述**: In the EXPAND2D macro (tif_fax3.h:388–530), called by both `Fax3Decode2D` and `Fax4Decode`, the `S_Horiz` case decodes two fax runs (white + black) by calling `SETVALUE()` twice, each of which does `*pa++ = RunLength + (x)`. There is no upper-bound check on `pa` relative to the allocated `dsp->runs` buffer. When both runs have length 0 (valid terminating codes with Param=0 exist in TIFFFaxWhiteTable and TIFFFaxBlackTable), `a0` does not advance, so the outer `while (a0 < lastx)` loop continues indefinitely until raw input data is exhausted. Each zero-run S_Horiz iteration increments `pa` by 2 without ever rolling it back. In contrast, `EXPAND1D` (tif_fax3.h:363–364) has an explicit rollback `if (*(pa-1)==0 && *(pa-2)==0) pa -= 2` for this same scenario, but `EXPAND2D` lacks it entirely. The run buffer `dsp->runs` is allocated as `2 * TIFFroundup(rowpixels, 32)` uint32 entries in `Fax3SetupState` (tif_fax3.c:512–515). An attacker embedding sufficient zero-run S_Horiz codes in the compressed strip data causes `pa` to advance far past the end of the heap allocation, writing 32-bit zero values to arbitrary heap locations adjacent to the buffer.
- **触发条件**: 攻击者构造一个 TIFF 文件，Compression 字段设为 CCITTFAX4（值 4）或 CCITTFAX3（值 3，且 Group3Options 包含 GROUP3OPT_2DENCODING），ImageWidth 设为较小值（如 32）使 runs 缓冲区较小，在对应的 strip 压缩数据中嵌入大量 S_Horiz 模式码（二进制 `001`）后接零长度白色终止码（`00110101`，8 位）和零长度黑色终止码（`0000110111`，10 位）。超过 `TIFFroundup(rowpixels,32)` 次 S_Horiz 迭代后即发生越界写。
- **安全影响**: 攻击者可通过控制后续 S_Horiz 码的数量，精确控制越界写入的字节偏移量；写入值为 0（uint32），持续覆盖 dsp->runs 后方的堆内存（可能含有 tcache/bins 指针、其他对象字段）。在 GLIBC 堆上可能利用 tcache 中毒或 fastbin 攻击实现任意写，最终达到远程代码执行（RCE）。最坏情况下进程崩溃（DoS），实际利用取决于堆布局。

<!-- AUDIT_PROMPT_VERSION: 1 -->
