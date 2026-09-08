全体分析が完了しました。確認された脆弱性を最終レポートとして出力します。

---

## VULN: realloc_texture signed-integer overflow → memset heap OOB write
- **漏洞类别**: memory-safety
- **函数**: realloc_texture()
- **行号**: 840-861 (核心溢出：856)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 6.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (video/subtitle stream with attacker-controlled codec width/height)
- **外部触发路径**: `ffplay crafted.mkv` → `read_thread()` → `stream_component_open()` → `avcodec_parameters_to_context(avctx, codecpar)` [copies attacker-controlled codecpar->width/height] → subtitle_thread(): `sp->width = is->subdec.avctx->width; sp->height = is->subdec.avctx->height` (行2341-2342) → video_image_display(): `realloc_texture(&is->sub_texture, SDL_PIXELFORMAT_ARGB8888, sp->width, sp->height, SDL_BLENDMODE_BLEND, 1)` (行1032) → realloc_texture()内 `memset(pixels, 0, pitch * new_height)` (行856)
- **描述**: `realloc_texture()` 在 `init_texture=1` 路径（第853–857行）执行 `memset(pixels, 0, pitch * new_height)`，其中 `pitch`（`int`，由 `SDL_LockTexture` 返回）和 `new_height`（`int`，来自字幕帧宽高）均为有符号32位整数。当两者之积超过 `INT_MAX`（例如 `pitch=65536, new_height=32769` → 乘积 `2,147,549,184 > 2,147,483,647`），C语言有符号整数溢出（UB，实践中二进制补码回绕为负值 `-2,147,418,112`）。该负 `int` 被隐式转换为 `size_t`：在64位系统上变为 `0xFFFFFFFF80010000 ≈ 1.84×10¹⁹` 字节，在32位系统上变为 `2,147,549,184`（≈2GiB）。前者导致立即 SIGSEGV（DoS）；后者在32位系统上可能越界写入 SDL 纹理缓冲区之后的堆内存（潜在堆溢出）。字幕流的 `codecpar->width`/`height` 字段由攻击者在容器文件中任意设置，经由 `avcodec_parameters_to_context()` → `avctx->width/height` → `sp->width/sp->height` 不经任何上界校验直接传入 `realloc_texture()`。
- **触发条件**: 攻击者构造包含字幕流（或视频流，通过 `vp->width/vp->height` 回退路径）的媒体文件，设置字幕 codec 的 `width=16384, height=32769`（或任意满足 `pitch × height > INT_MAX` 的组合）。受害者系统 GPU 必须支持该尺寸纹理的创建（即 GPU maxTextureDim ≥ 32768，如 NVIDIA RTX 3000/4000 系列、AMD RX 6000+ 系列，VRAM ≥ 8GB 或 SDL 使用系统内存的 streaming 纹理）。用户只需执行 `ffplay crafted.mkv` 即可触发。
- **安全影响**: 最低影响为 DoS（进程崩溃/SIGSEGV）。在32位构建或特定内存布局下，`memset` 越界写入 SDL 内部堆缓冲区之后的内存区域，可能破坏堆元数据或相邻对象，在配合堆风水的条件下可进一步提升为远程代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
