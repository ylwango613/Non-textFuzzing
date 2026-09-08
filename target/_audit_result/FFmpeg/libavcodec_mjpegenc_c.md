Now I have all the context needed. Let me finalize my analysis.

**Summary of findings from the complete read of mjpegenc.c (731 lines total):**

**Group 1 (lines 1–167): Encoder core — `alloc_huffman`, `mjpeg_encode_code`, `mjpeg_encode_coef`**

- `alloc_huffman` (lines 287-304): allocates `mb_num * blocks_per_mb * 64` entries. Arithmetic done as `size_t` via `av_malloc_array`; the 65500 size limit caps `mb_num` at ~16.7M, max product ~201M — on any real system this allocation simply fails with ENOMEM when huge, no overflow reaching heap. ✓
- `huff_ncode` write bound: maximum 64 codes per block mathematically proven (DC=1 + AC≤63 or AC<63+EOB=1 = 64). Tight but correct. ✓
- `table_id` ∈ {0,1,2,3}, `code` ∈ {0..255} for AC, {0..11} for DC. Array accesses bounded. ✓

**Group 2 (lines 465-529): `mjpeg_record_mb` / `mjpeg_encode_mb` — CHROMA_444 block dispatch**

- For CHROMA_444, up to 12 blocks (n≤11). `block_last_index[12]` — 12-element array, max index 11. ✓
- `blocks_per_mb[CHROMA_444]=12` matches the conditional dispatch. ✓

**Group 3 (lines 611-643): `amv_encode_picture` — frame flip arithmetic**

```c
for(i=0; i < 3; i++) {
    int vsample = i ? 2 >> chroma_v_shift : 2;
    pic->data[i] += pic->linesize[i] * (vsample * s->c.height / V_MAX - 1);
```

- `pic->linesize[i]` is `int`; `(vsample * s->c.height / V_MAX - 1)` is `int`
- For luma (vsample=2, V_MAX=2): factor = `height - 1`
- With height=65488 (= 4093 × 16, valid multiple of 16 within the 65500 limit) and linesize=65488: product = 65488 × 65487 = 4,288,180,656 **> INT_MAX (2,147,483,647)** → **signed integer overflow (UB)**
- Wrap value ≈ −6,786,640; pointer arithmetic `pic->data[0] += ~−6.8M` puts the data pointer ~6.4 MB **before** the frame buffer
- Subsequent `ff_mpv_encode_picture` reads pixel data from this invalid address → OOB heap read → crash or heap content disclosure

**Group 4 (lines 531-609, 658-730): encoder init and close — no issues found**

---

## VULN: AMV Encoder Integer Overflow in Frame Flip Pointer Arithmetic
- **漏洞类别**: memory-safety
- **函数**: amv_encode_picture()
- **行号**: 636-638
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-823 (Use of Out-of-range Pointer Offset)
- **CVSS v3.1**: 5.9 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i crafted.mkv -vcodec amv output.amv → avcodec_open2() → amv_encode_picture() → pic->data[i] += pic->linesize[i] * (vsample * s->c.height / V_MAX - 1) [integer overflow at line 637]
- **描述**: 在 `amv_encode_picture` 中，为了将帧垂直翻转（AMV 格式要求），代码通过 `pic->data[i] += pic->linesize[i] * (vsample * s->c.height / V_MAX - 1)` 计算最后一行的指针偏移量。`pic->linesize[i]`（`int`）与 `(vsample * height / V_MAX - 1)`（`int`）的乘积在高分辨率下发生有符号整数溢出（C 标准 UB）：例如 width=height=65488（65500 限制内的 16 的倍数）时，luma 乘积为 65488 × 65487 = 4,288,180,656 > INT_MAX（2,147,483,647），结果回绕为约 −6,786,640，导致 `pic->data[0]` 指向帧缓冲区起始地址前约 6.4 MB 处的堆内存。
- **触发条件**: 攻击者构造一个包含大分辨率视频流（如 width=height≥32787，且 height 为 16 的倍数，≤65500）的媒体文件（MKV/AVI/MP4 等），诱使受害者或自动化管道使用 AMV 编码器进行转码（`-vcodec amv` 或 `-c:v amv`）。`mjpeg_encode_init` 的 65500 上限检查不足以阻止溢出；height 的 `& 15` 检查仅要求是 16 的倍数，同样无法阻止。
- **安全影响**: 溢出后，编码器对无效堆指针进行像素数据读取，导致越界堆读取（OOB heap read）。最直接后果是进程崩溃（SIGSEGV，DoS）；在特定堆布局下，编码后的 AMV 输出数据中可能包含帧缓冲区之前的堆内容，造成敏感信息泄露（heap memory disclosure）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
