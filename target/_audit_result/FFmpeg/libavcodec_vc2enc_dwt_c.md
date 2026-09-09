Now I have all the context needed. Let me do the final analysis.

**Key finding in `ff_vc2enc_init_transforms` (line 266):**

```c
s->buffer = av_calloc((p_stride + slice_w)*(p_height + slice_h), sizeof(dwtcoef));
```

All four parameters are `int`. The multiplication `(p_stride + slice_w)*(p_height + slice_h)` is computed as **signed 32-bit integer arithmetic** before implicit conversion to `size_t` for `av_calloc`. This can overflow.

**Overflow threshold**: `p_stride` = `coef_stride` = `FFALIGN(dwt_width, 32)`. With `avctx->width ≈ 46340` (reachable from a crafted MKV/WebM container) and `slice_w = 1024` (max option), `slice_h = 1024`:
- `(46368 + 1024) * (46368 + 1024)` = `47392 * 47392` ≈ **2.25 × 10⁹ > INT_MAX (2.14 × 10⁹)` → wraps to a small positive integer

`av_calloc` then allocates a tiny buffer. The DWT functions (`vc2_subband_dwt_97`, `vc2_subband_dwt_53`, `dwt_haar`) subsequently iterate over the full `synth_height × synth_width = 4 * width * height` elements, writing far beyond the buffer.

No dimension bounds check exists in `vc2enc.c` — the only checks are that `slice_width/height` must be powers of 2 and not exceed the image dimensions (lines 1084–1093).

## VULN: Integer Overflow in VC2 Encoder DWT Buffer Allocation Leading to Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: ff_vc2enc_init_transforms()
- **行号**: 266-266
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (MKV/WebM with extreme resolution, transcoded to VC2)
- **外部触发路径**: ffmpeg -i crafted_large.mkv -c:v vc2 -slice_width 1024 -slice_height 1024 out.ts → avcodec_open2() → vc2_encode_init() → ff_vc2enc_init_transforms() [vc2enc_dwt.c:266: integer overflow in (p_stride+slice_w)*(p_height+slice_h)] → av_calloc() allocates undersized buffer → vc2_subband_dwt_97()/vc2_subband_dwt_53()/dwt_haar() write synth_height×synth_width elements OOB
- **描述**: 在 `ff_vc2enc_init_transforms` 的第 266 行，缓冲区大小计算 `(p_stride + slice_w)*(p_height + slice_h)` 以有符号 32 位整数运算执行，结果隐式转换为 `size_t` 传递给 `av_calloc`。当 `p_stride`（来自 `coef_stride = FFALIGN(dwt_width, 32)`）与 `p_height`（来自 `dwt_height`）足够大时（如各约 46340），乘积超过 `INT_MAX`（2,147,483,647），发生有符号整数溢出，截断为一个小正整数。`av_calloc` 据此分配严重不足的堆缓冲区。后续 `vc2_subband_dwt_97`、`vc2_subband_dwt_53` 和 `dwt_haar` 函数将 `t->buffer` 视为 `synth_height × synth_width`（= `4 × width × height`）元素的合法空间并全量写入，造成大规模堆越界写入。
- **触发条件**: 攻击者提供一个包含极大分辨率视频流（宽或高约 ≥ 46340 像素，在 MKV/WebM 等支持大分辨率的容器格式中合法）的媒体文件，并由用户（或自动化媒体处理管线）以 VC2 为目标编解码器进行转码（`-c:v vc2`）。`slice_width` 和 `slice_height` 选项值越大（最大 1024），溢出阈值越低。VC2 编码器本身不限制输入分辨率上界。
- **安全影响**: 堆越界写入可被利用以覆盖堆元数据或相邻对象，最坏情况下导致远程代码执行（RCE）。在自动化媒体转码服务（如视频平台后端）中，攻击者仅需上传一个超大分辨率视频文件即可远程触发，无需任何认证；交互式 `ffmpeg` 用户场景下需诱导用户执行特定命令。

<!-- AUDIT_PROMPT_VERSION: 1 -->
