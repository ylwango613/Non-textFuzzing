完成全部分析。汇总：

**`apv_metadata.c` 本体**（135 行）：仅对已解析的 `APVRawFrameHeader` 字段做 uint8_t 赋值，无任何内存分配、指针算术或 memcpy 操作。

**调用链深度审计（CBS APV 解析器）：**

1. `metadata_itu_t_t35`（line 308）：`read_size = payload_size - 1`，当 `payload_size == 0` 时产生 `size_t` 下溢 → `SIZE_MAX`，但 `av_malloc()` 有 `size > max_alloc_size`（= INT_MAX）守卫，直接返回 NULL → ENOMEM 被正确处理，无内存破坏。

2. `metadata_user_defined`（line 406）：`payload_size - 16` 当 `payload_size < 16` 时 `size_t` 下溢 → 同样被 `av_malloc` 尺寸守卫截住。

3. `cbs_apv_derive_tile_info`（tile_info 分支）：当 `frame_width = 0` 时，`min_tile_width = 0`，允许 `tile_width_in_mbs = 0`，导致除以零 SIGFPE —— 属于 DoS，非内存破坏。

4. `tile_size_in_fh[]` / `tile[]` 数组访问：`av_assert0` 始终启用，确保 `num_tiles ≤ APV_MAX_TILE_COUNT(400)`，无法绕过。

5. `cbs_apv_assemble_fragment`（write 路径）中 `size` 累加：`frag->nb_units` 受 CBS 框架控制，单元数和大小均已验证，无溢出路径。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
