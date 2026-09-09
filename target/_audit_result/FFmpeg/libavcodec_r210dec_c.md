Now I have all the context needed for a complete analysis. Let me verify the arithmetic types:

- `aligned_width`: declared `int` (line 41)  
- `avctx->width` / `avctx->height`: `int` (avcodec.h line 2767-2768)  
- `avpkt->size`: `int` (packet.h line 604)  
- `FFALIGN(x,a)` = `(((x)+(a)-1)&~((a)-1))` — pure signed int arithmetic

**Analysis of line 51:**

```c
if (avpkt->size < 4 * aligned_width * avctx->height) {
```

All operands are `int`. The sub-expression `4 * aligned_width * avctx->height` is evaluated left-to-right with signed int arithmetic:

- Step 1: `4 * aligned_width` — overflows when `aligned_width > INT_MAX / 4 = 536,870,911`
- Step 2: `(overflowed_result) * avctx->height`

**Concrete overflow scenario** (width=23170, height=23170, non-R10K codec):
- `aligned_width = FFALIGN(23170, 64) = 23232`
- `4 * 23232 = 92928`
- `92928 * 23170 = 2,152,741,760 > INT_MAX (2,147,483,647)` → UB / signed overflow
- Two's complement result: `2,152,741,760 − 2^32 = −2,142,225,536` (negative)
- Check becomes: `avpkt->size < −2,142,225,536` → **always false** (avpkt->size ≥ 0)

The only guard before the decode loop is thus silently bypassed.

**In the decode loop (lines 63–92)**, for a crafted packet with just 4 bytes of data, `src` advances through `width × height × 4 = ~2.15 GB` of reads from `avpkt->data`, reading far beyond the allocated buffer — a massive **heap OOB read**.

`ff_get_buffer` at line 56 for 23170×23170 GBRP10 (2 bytes/pixel × 3 planes) ≈ 3.2 GB total. This succeeds on a workstation/server with ≥ 4 GB RAM, passing through to the OOB loop.

---

## VULN: Integer Overflow in Packet Size Check Enables Heap OOB Read in decode_frame
- **漏洞类别**: memory-safety
- **函数**: decode_frame()
- **行号**: 43-92 (核心缺陷: 第43-44行 aligned_width 计算 + 第51行 size check overflow)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (AVI/MOV/RAW containing R210, R10K, or AVRP video stream)
- **外部触发路径**: `ffmpeg -i <crafted.avi> -f null -` → `avformat_open_input()` → demuxer sets avctx->width/height from container → `avcodec_send_packet()` → `decode_frame()` in libavcodec/r210dec.c:51 (size check overflow) → decode loop at lines 63-92 (heap OOB read from avpkt->data)
- **描述**: 在 `decode_frame()` 的第51行，最小包大小校验表达式 `4 * aligned_width * avctx->height` 使用有符号 `int` 乘法计算（`aligned_width` 和 `avctx->height` 均为 `int`）。当 width/height 满足 `aligned_width × height > INT_MAX / 4`（约 536M）时，该乘积超过 `INT_MAX`，触发有符号整数溢出（C 标准未定义行为，实际上在 x86 gcc/clang 中产生负数或 0）。溢出后，比较 `avpkt->size < <负数或0>` 对任何非负 `avpkt->size` 恒为 `false`，导致该唯一尺寸守卫被完全绕过。随后第63-92行的双重循环从 `src`（即 `avpkt->data`）中逐像素读取 `width × height × 4` 字节，远超实际包数据，造成巨量堆越界读。
- **触发条件**: 攻击者构造一个 AVI 或 MOV 文件，将 R210/R10K/AVRP 视频流的宽度设置为约 23170（或满足 `aligned_width × height > 536M` 的任意组合），高度同样约为 23170，并在媒体文件中提供极小的视频帧数据（如仅 4 字节）。在内存充足（≥ 4 GB）的系统上，`ff_get_buffer()` 成功分配输出帧后，解码循环以 OOB 方式读取 `avpkt->data`。
- **安全影响**: 大范围堆越界读（可达数 GB），最坏情况导致进程崩溃（DoS）；在 ASLR 信息泄露链配合下，可泄露进程堆内存内容（包括敏感数据或指针），进而辅助构造 RCE 利用链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
