I have completed my thorough multi-pass analysis of `tif_open.c` and its full call chain including `tif_dirread.c`, `tif_aux.c`, and `tif_read.c`. I have traced all malloc calls, integer arithmetic, and IFD-chain parsing logic.

**Group 1 (lines 1-300, tif_open.c):** `TIFFClientOpen` allocates the `TIFF` struct, reads the 8-byte header, validates magic/version, then calls `TIFFReadDirectory`. No arithmetic on file-supplied data in this segment; no overflow.

**Group 2 (lines 74-829, tif_dirread.c / `TIFFReadDirectory`):** IFD parsing loop. `_TIFFCheckMalloc` is used for all IFD-entry arrays and has a signed-vs-size overflow guard. `TIFFExtractData` only accessed with pre-validated TIFF type values 1-12 (within the 13-element `typemask`/`typeshift` array bounds). Strip-byte-count estimation has a `uint32×uint32` overflow in `EstimateStripByteCounts:1015` but subsequent checks in `TIFFFillStrip:309` bound the read against file size, no direct memory corruption.

**Group 3 (lines 1063-1105, `TIFFCheckDirOffset`):** Confirmed vulnerability — `tif_dirnumber` is `uint16`; after 65535 increments it wraps to 0. The realloc guard `(0 > tif_dirlistsize)` is false, so `tif_dirlist[(uint16)0 − 1]` = `tif_dirlist[−1]` writes 4 bytes before the heap buffer with an attacker-controlled IFD offset.

**Verification:** `tiffsplit` processes every IFD in a do-while loop (`tiffsplit.c:92`) calling `TIFFReadDirectory`; combined with the one call in `TIFFClientOpen`, exactly 65536 IFDs trigger the wrap. Minimum crafted file ≈ 384 KB (65536 × 6-byte IFDs + 8-byte header). No other bounds protect this path.

## VULN: uint16 Wrap-around OOB Heap Write in TIFFCheckDirOffset
- **漏洞类别**: memory-safety
- **函数**: TIFFCheckDirOffset()
- **行号**: 1082-1102 (tif_dirread.c)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFClientOpen() → TIFFReadDirectory() → TIFFCheckDirOffset() [repeated 65536 times via the do-while loop in tiffsplit main()]
- **描述**: `tif_dirnumber` 字段类型为 `uint16`（`tiffiop.h:135`），在 `TIFFCheckDirOffset`（`tif_dirread.c:1082`）中每次处理一个 IFD 时执行 `tif->tif_dirnumber++`。当处理第 65536 个 IFD 时，该字段从 65535 溢出回绕为 0（uint16 模运算）。随后，重分配守卫判断 `(0 > tif_dirlistsize)` 因 `tif_dirlistsize` 为大正数而为 false，因此不触发 realloc；最终在 `tif_dirread.c:1102` 执行 `tif->tif_dirlist[tif->tif_dirnumber - 1] = diroff`，其中 `(uint16)0 - 1` 在 C 整数提升后等于 -1，造成向 `tif_dirlist[-1]` 写入 4 字节（一个 `toff_t` 的大小），即堆缓冲区起始地址之前的 4 字节，写入值为攻击者可控的 IFD 文件偏移量。
- **触发条件**: 攻击者构造含 ≥ 65536 个不同 IFD 偏移量的 TIFF 链表文件（每个 IFD 仅需 6 字节：2 字节 dircount=0 + 4 字节 nextdiroff，最小文件约 384 KB），使 `tiffsplit` 通过 `do { … } while (TIFFReadDirectory(in))` 循环遍历所有 IFD，第 65536 次调用 `TIFFCheckDirOffset` 时触发 uint16 回绕及越界写。
- **安全影响**: 最坏情况下可在 `tif_dirlist` 前的堆内存中写入攻击者控制的 4 字节值，可能覆盖 glibc 堆块元数据（chunk size 字段等），导致后续堆操作产生任意地址写，进而实现任意代码执行（RCE）；至少可造成可重现的崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
