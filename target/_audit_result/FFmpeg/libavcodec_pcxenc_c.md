Now I have enough context to analyze the vulnerability. Let me trace the key computation on line 136:

`max_pkt_size = 128 + avctx->height * 2 * line_bytes * nplanes + (pal ? 256*3 + 1 : 0);`

- All variables are `int` (32-bit signed).
- `avctx->width` and `avctx->height` are bounded to ≤ 65535 (checked at line 98–101).
- For RGB24: `nplanes=3`, `bpp=8`, `line_bytes = ((width*8+7)>>3 + 1)&~1` ≤ 65536.
- For width=22000, height=35000, nplanes=3: true product = 35000 × 2 × 22000 × 3 = 4,620,000,000 > INT_MAX (2,147,483,647), wrapping to 325,032,704 (positive).
- `max_pkt_size = 128 + 325,032,704 = 325,032,832` (~325 MB).
- `ff_alloc_packet` receives this positive `int64_t`, allocates 325 MB successfully.
- Encoder then writes the true 4.62 GB of encoded data into that 325 MB buffer → massive OOB heap write.

`ff_alloc_packet` (encode.c:64) only rejects negative sizes. When the signed overflow wraps to a positive value, it proceeds to allocate the undersize buffer.

## VULN: Integer Overflow in max_pkt_size Causes OOB Heap Write in PCX Encoder
- **漏洞类别**: memory-safety
- **函数**: pcx_encode_frame()
- **行号**: 136-173
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file / crafted raw video input routed through PCX encoder
- **外部触发路径**: `ffmpeg -s WxH -f rawvideo -pix_fmt rgb24 -i crafted.raw -vcodec pcx out.pcx` → `avcodec_send_frame()` → `pcx_encode_frame()` → `ff_alloc_packet(avctx, pkt, max_pkt_size)` → OOB write in `pcx_rle_encode()` loop
- **描述**: 在 `pcx_encode_frame()` 第 136 行，`max_pkt_size` 被声明为 `int`，计算式 `128 + avctx->height * 2 * line_bytes * nplanes` 全部在 32 位有符号整数域内进行。当 height、line_bytes、nplanes 的乘积超过 INT_MAX 时发生有符号整数溢出（C 标准下为 UB，实践中 x86 wraps）。若溢出结果为正值（如 width=22000, height=35000, RGB24 时：真实值 4,620,000,128 mod 2^32 = 325,032,832），该正值被提升为 `int64_t` 传入 `ff_alloc_packet`，后者检查通过并成功分配远小于实际所需的堆缓冲区。随后 `pcx_rle_encode()` 循环向该缓冲区写入真实大小的编码数据（约 4.62 GB），造成大范围堆越界写。
- **触发条件**: 构造分辨率落在特定溢出区间的图像（例如 RGB24 格式 width≈22000, height≈35000，或其他满足 `height * 2 * line_bytes * 3` 在 (2^32, 2^32+2^31) 区间内的组合），通过 PCX 编码器编码。攻击面包括：转码场景中解码器输出满足此尺寸的帧后直接送入 PCX 编码器。
- **安全影响**: 攻击者可控的大范围堆越界写，可覆盖 glibc 堆元数据或相邻堆块内容，最坏情形下可实现远程代码执行（RCE）；在沙箱受限环境中至少可可靠触发进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
