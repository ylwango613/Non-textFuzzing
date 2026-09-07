Now I have all the information needed. Let me consolidate the findings into the required format.

## VULN: Use-After-Free in t2p_readwrite_pdf_image via REALIZE_PALETTE realloc failure
- **漏洞类别**: memory-safety
- **函数**: t2p_readwrite_pdf_image()
- **行号**: 2451-2465
- **CWE**: CWE-416 (Use After Free)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2pdf main() -> t2p_write_pdf() -> t2p_readwrite_pdf_image() -> _TIFFrealloc() -> _TIFFfree(buffer) -> t2p_sample_realize_palette(t2p, buffer) [freed pointer]
- **描述**: 当 `pdf_sample & T2P_SAMPLE_REALIZE_PALETTE` 为真时（第 2450 行），代码在第 2451-2453 行调用 `_TIFFrealloc(buffer, t2p->tiff_datasize * t2p->tiff_samplesperpixel)` 来扩展 palette 展开缓冲区。此处 `tiff_datasize`（类型为 `tsize_t` = `int32_t`）与 `tiff_samplesperpixel`（uint16，值为 3 或 4）相乘时发生有符号整数溢出（e.g. 536MB × 4 = 2.1GB 溢出 INT32_MAX）。溢出后的负值被强转为 `size_t` 传给 `realloc`，导致 realloc 失败返回 NULL。在第 2454-2460 行的 NULL 检查分支中，代码调用 `_TIFFfree(buffer)` 释放了原缓冲区，但 **未将 buffer 设为 NULL 也未 return**。随即在第 2465 行调用 `t2p_sample_realize_palette(t2p, buffer)` 对该已释放指针进行读写操作，形成 use-after-free。
- **触发条件**: 构造 TIFF：设置 PHOTOMETRIC_PALETTE + BitsPerSample=8，使用 JPEG 作为输出压缩（-j 标志），且 ImageWidth × ImageLength 使得 `tiff_datasize × 3(or 4) > INT32_MAX`（例如 CMYK 调色板：宽=23170，高=23170，总像素 ≈ 536M；RGB 调色板：宽=26754，高=26754）。
- **安全影响**: 堆上 use-after-free（读+写），在 tcache/fastbin 可被 groomed 的场景下可能达成任意代码执行（RCE）；最低造成可靠崩溃（DoS）。

## VULN: Heap Buffer Overflow in t2p_process_ojpeg_tables via JPEGDCTABLES/JPEGACTABLES
- **漏洞类别**: memory-safety
- **函数**: t2p_process_ojpeg_tables()
- **行号**: 3175-3284
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2pdf main() -> t2p_write_pdf() -> t2p_read_tiff_data() -> t2p_process_ojpeg_tables()
- **描述**: `t2p_process_ojpeg_tables` 在第 3175 行分配 2048 字节的 `ojpegdata` 缓冲区，然后将从 TIFF 标签 TIFFTAG_JPEGDCTABLES（变量 `dc`）和 TIFFTAG_JPEGACTABLES（变量 `ac`）读取的 Huffman 表内容写入其中。关键缺陷在第 3249-3261 行（DC 表）和 3272-3284 行（AC 表）：`code_count` 由攻击者控制的 16 个字节之和决定（`for(i=0;i<16;i++) code_count += ojpegdata[t2p->pdf_ojpegdatalength++]`），而后通过 `_TIFFmemcpy(&ojpegdata[t2p->pdf_ojpegdatalength], &dc[offset_table], code_count)` 写入 ojpegdata。代码仅检查了 `q_length`（量化表长度），从未检验 `dc_length`/`ac_length` 或 `code_count` 是否会导致 `pdf_ojpegdatalength + code_count > 2048`。当 SOI/SOF/DQT 标记已消耗约 300+ 字节后，只需 `code_count` 约 > 1725 即可溢出。
- **触发条件**: 构造 TIFF：设置 COMPRESSION_OJPEG，在 TIFFTAG_JPEGDCTABLES 中将前 16 字节设为使其总和 > 1725 的值（例如 7 个 0xFF = 0×255 = 1785），使 `pdf_ojpegdatalength + code_count > 2048`，即可在堆上越界写入 `ojpegdata` 分配块之后的内存。
- **安全影响**: 堆缓冲区越界写，可破坏相邻堆块元数据或指针，配合堆喷射可达到任意代码执行（RCE）；至少可造成稳定崩溃（DoS）。

## VULN: NULL Pointer Dereference in t2p_read_tiff_size for CCITT-G4 and ZIP raw strips
- **漏洞类别**: memory-safety
- **函数**: t2p_read_tiff_size()
- **行号**: 1808-1819
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2pdf main() -> t2p_write_pdf() -> t2p_read_tiff_size() -> TIFFGetField(TIFFTAG_STRIPBYTECOUNTS) [未检查返回值] -> sbc[0] [NULL 解引用]
- **描述**: 在 `t2p_read_tiff_size` 函数中，`sbc` 被初始化为 NULL（第 1799 行）。当 `pdf_compression == T2P_COMPRESS_G4`（第 1809 行）时，代码执行 `TIFFGetField(input, TIFFTAG_STRIPBYTECOUNTS, &sbc)` 但不检查其返回值，随即在第 1810 行执行 `t2p->tiff_datasize = sbc[0]`。若 TIFF 文件缺少 STRIPBYTECOUNTS 标签（libtiff 对畸形 TIFF 会返回 0 而不填充 sbc），则 `sbc` 仍为 NULL，`sbc[0]` 发生 NULL 指针解引用，导致进程崩溃。相同缺陷在第 1816-1818 行针对 ZIP/Deflate 压缩路径同样存在（`pdf_compression == T2P_COMPRESS_ZIP` 分支）。
- **触发条件**: 构造 TIFF：设置 COMPRESSION_CCITTFAX4（或 COMPRESSION_DEFLATE）但不包含 TIFFTAG_STRIPBYTECOUNTS 标签，同时确保 `pdf_transcode == T2P_TRANSCODE_RAW`（满足此条件的 CCITT G4 单条带图像或 Deflate 单条带图像）；tiff2pdf 处理该文件时进程崩溃。
- **安全影响**: 稳定的进程崩溃（DoS），可针对将 tiff2pdf 作为服务调用的场景实现拒绝服务攻击。

<!-- AUDIT_PROMPT_VERSION: 1 -->
