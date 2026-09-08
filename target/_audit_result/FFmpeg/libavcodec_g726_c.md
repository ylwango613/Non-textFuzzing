**分析结论**：

逐段深读 g726.c 各函数群：

**`g726_decode_frame`（第455-486行）**：
- `out_samples = buf_size * 8 / c->code_size`：若 `buf_size ≥ 268435456`，`buf_size * 8` 会溢出变为负值，导致 `frame->nb_samples` 为负。  
- 但追踪到 `av_frame_get_buffer`（libavutil/frame.c:213）：`else if (frame->nb_samples > 0 && ...)` —— 负值条件不满足，返回 `AVERROR(EINVAL)`，`ff_get_buffer` 收到错误后提前返回，写循环 `while (out_samples--)` 永远不会执行。

**表访问（iquant/F/W，第188-259行）**：
- `I` 来自 `get_bits(&gb, c->code_size)`，范围 `[0, 2^code_size - 1]`；各表大小恰好为 `2^code_size`（tbl16:4, tbl24:8, tbl32:16, tbl40:32），越界不可达。

**`g726_reset`（第282行）**：
- `G726Tables_pool[c->code_size - 2]`，`code_size ∈ [2,5]`，索引 `[0,3]`，池有4项，安全。

**`quant` 循环（第172行）**：
- `while (c->tbls.quant[i] < INT_MAX && ...)` 以 `INT_MAX` 哨兵终止，`i` 上界由表长保证。

**`g726_encode_frame` 的 `out_size` 计算**：
- `frame->nb_samples` 由 `g726_encode_init` 设为固定值（最大4096），乘以 code_size（≤5），不会溢出。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
