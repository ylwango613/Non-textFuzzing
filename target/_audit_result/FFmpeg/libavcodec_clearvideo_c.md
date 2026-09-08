经过对 `clearvideo.c`（751行）的完整分批深读和调用链追踪，分析结论如下：

**关键检查点验证结果：**

1. **`decode_tile()` 递归 + `lev[]` 越界** — `lev[3].flags_cb`、`lev[6].flags_cb`、`lev[9].flags_cb` 均为 NULL（初始化循环中的哨兵值），保证 Y/U/V 三平面递归分别在 lev[3]、lev[6]、lev[9] 处自然终止，不会访问 `lev[10]`。

2. **`mvi_predict()` 数组越界** — 分配为 `pmb_width * 2` 元素；最大访问下标 `mb_stride + mb_x = 2*pmb_width - 1`，以及 `mb_x + 1 = pmb_width`，均在界内。

3. **`copy_block()` / `copyadd_block()`** — 均有显式边界校验，越界返回 `AVERROR_INVALIDDATA`。

4. **`extend_edges()`** — 写入范围精确在 `FFALIGN(w/h, tile_size)` 编码尺寸内，不会越出帧缓冲区。

5. **`decode_mb()` 偏移计算** — `x < mb_width`, `y < mb_height`，与对齐后的 coded_width/coded_height 一致，无越界。

6. **内存分配** — `av_calloc` 内部有溢出保护；`extradata` 访问（offset 94 for size 110，offset 134 for size 150）均有边界守卫。

7. **`bytestream2_skip((skip+1)*8)`** — `bytestream2_skip` 内部 clip 到剩余缓冲区大小，不产生越界。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
