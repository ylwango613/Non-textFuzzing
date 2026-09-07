All types and code paths are confirmed. Here is the complete audit result.

---

## VULN: Integer Overflow in `uncompr_size` Leads to Heap Under-Allocation and OOB Memory Access
- **漏洞类别**: memory-safety
- **函数**: main()
- **行号**: 591-598, 687-694
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted BMP file
- **外部触发路径**: bmp2tiff main() → RLE decode path (iCompression == BMPC_RLE8 || BMPC_RLE4) → `uncompr_size = width * length` (line 591, uint32 overflow) → `_TIFFmalloc(uncompr_size)` under-allocates (line 598) → `TIFFWriteScanline(out, uncomprbuf + (length - row - 1) * width, row, 0)` (line 689) computes pointer far beyond allocated buffer
- **描述**: `width`（来自 `info_hdr.iWidth`，uint32，由 BMP 文件控制）与 `length`（来自 `info_hdr.iHeight`，uint32，由 BMP 文件控制）在第 591 行直接相乘：`uncompr_size = width * length`，无任何溢出校验。当乘积超过 UINT32_MAX 时，`uncompr_size` 回绕为一个远小于实际像素数的值，导致第 598 行 `_TIFFmalloc(uncompr_size)` 分配的 `uncomprbuf` 缓冲区严重不足。随后在第 689 行遍历行时，计算 `uncomprbuf + (length - row - 1) * width` 作为 `TIFFWriteScanline` 的数据源指针。当 `(length - row - 1) * width` 本身未发生溢出（或溢出结果与 `uncompr_size` 回绕值不同步）时，该指针会指向远超已分配缓冲区末尾的内存地址，导致 `TIFFWriteScanline` 从越界地址读取数据。**具体示例**：`iWidth = 65537`，`iHeight = 65537`，`iCompression = BMPC_RLE8`：`uncompr_size = 65537 × 65537 mod 2³² = 131073`，仅分配 131073 字节；当 row=1 时，`(65537 - 1 - 1) × 65537 mod 2³² = 65535 × 65537 mod 2³² = 4294967295`，指针偏移量 4,294,967,295 远超 131,073 字节缓冲区，`TIFFWriteScanline` 从该越界地址读取 `width`（65537）字节，在 64 位系统上导致 SIGSEGV；在 32 位系统上由于指针回绕，可能读写任意堆内存。
- **触发条件**: 构造一个 BMP 文件，将 `iWidth` 和 `iHeight` 设置为满足 `iWidth × iHeight > 2³²` 的值（如均设为 65537），将 `iCompression` 设为 `BMPC_RLE8`（0x01）或 `BMPC_RLE4`（0x02），并填充合法的 RLE 压缩数据体，使 `compr_size` 有效（`file_hdr.iOffBits` < 实际文件大小）。
- **安全影响**: 可靠触发崩溃（DoS，SIGSEGV）；在 32 位环境下，指针算术回绕使越界指针落入合法堆内存，`TIFFWriteScanline` 读取攻击者可能布局的堆数据并写入 TIFF 文件，可导致堆内存信息泄露；若堆布局可控，进一步可能升级为堆越界读/写，为 RCE 提供基础条件。

## VULN: Heap OOB Read in RLE8 Decompression Loop (Off-by-One on `comprbuf`)
- **漏洞类别**: memory-safety
- **函数**: main()
- **行号**: 620-622
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted BMP file
- **外部触发路径**: bmp2tiff main() → RLE8 decode path (iBitCount == 8) → outer while loop (i < compr_size) → else branch (comprbuf[i] == 0) → `i++` 使 i == compr_size → `comprbuf[i]`（第 622 行）越界读取 comprbuf[compr_size]
- **描述**: 在 RLE8 解压缩循环（第 610 行 `while(j < uncompr_size && i < compr_size)`）中，当外层循环入口时 `i == compr_size - 1` 且 `comprbuf[i] == 0`，代码进入 `else` 分支，第 621 行无条件执行 `i++`，使 `i` 变为 `compr_size`。随即第 622 行 `if (comprbuf[i] == 0)` 读取 `comprbuf[compr_size]`，即分配缓冲区末尾后一字节——堆越界读。该字节来自相邻堆内存，其值决定后续控制流：若为 0 则再次 `i++` 并继续；若为 2（"Move to"分支），则在随后可能触发 `comprbuf[i]`（`i = compr_size + 1`）和 `comprbuf[i+1]`（`i = compr_size + 2`）的进一步越界读取。RLE4 路径（第 644 行）存在相同结构缺陷。
- **触发条件**: 构造 BMP 文件，`iCompression = BMPC_RLE8`，`iBitCount = 8`，在压缩数据流末尾（最后一个字节，即 `comprbuf[compr_size - 1]`）放置值 `0x00`（编码为"转义序列"起始字节），使得解压循环在 `i == compr_size - 1` 时进入 else 分支，触发越界读。
- **安全影响**: 读取堆上 `comprbuf` 后方相邻内存内容，可造成堆内存信息泄露（如相邻 chunk 的指针或敏感数据）；若相邻内存中的字节值恰为 2（"Move to"操作码），可进一步触发额外越界读及对 `uncomprbuf[j]` 的越界写，将信息泄露升级为内存破坏。

<!-- AUDIT_PROMPT_VERSION: 1 -->
