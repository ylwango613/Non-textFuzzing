Now I have the complete picture. Let me verify the null-check absence in the parser loop:

The analysis is complete. Here is the confirmed finding:

`cbs_av1_read_unit()` (line 848): allocates `unit->content`, reads the OBU header, then at line 887–888 can return `AVERROR(EAGAIN)` when `operating_point_idc` filtering drops the unit. The CBS core (`cbs.c` lines 202–203) handles EAGAIN by freeing and NULLing `unit->content`, but the unit **remains in the fragment** with its original `type` (`AV1_OBU_FRAME` / `AV1_OBU_FRAME_HEADER`).

Back in `av1_parser_parse()` (lines 101–113), the loop over `td->nb_units` reads `obu = unit->content` (which is now NULL) and immediately dereferences it — without any NULL guard — at `&obu->obu.frame.header` or `&obu->obu.frame_header`, then again at `obu->header.spatial_id`.

---

## VULN: NULL Dereference in av1_parser_parse via Dropped OBU Content
- **漏洞类别**: memory-safety
- **函数**: av1_parser_parse()
- **行号**: 101-113
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted AV1 media file
- **外部触发路径**: `ffmpeg -i <crafted.av1> -f null -` → `avcodec_open2()` → `av1_parser_parse()` → `ff_cbs_read()` → `cbs_av1_read_unit()` [returns EAGAIN, sets unit->content=NULL] → `av1_parser_parse()` loop at line 102 dereferences NULL `obu`
- **描述**: 在 `cbs_av1_read_unit()`（`cbs_av1.c:848`）中，函数首先分配 `unit->content`（通过 `alloc_unit_content`），读入 OBU 头部，随后在 `operating_point_idc` 过滤逻辑（`cbs_av1.c:882-888`）中，若 OBU 的 `temporal_id` 或 `spatial_id` 不在当前 operating point 内，则返回 `AVERROR(EAGAIN)`（即 `drop_obu()`）。CBS 核心（`cbs.c:202-203`）处理 EAGAIN 时，执行 `av_refstruct_unref(&unit->content_ref); unit->content = NULL;`，但该 unit 仍保留在 fragment 的 `units[]` 数组中，其 `type` 字段仍为 `AV1_OBU_FRAME` 或 `AV1_OBU_FRAME_HEADER`。`av1_parser_parse()`（`av1_parser.c:101-113`）的遍历循环中，`obu = unit->content`（NULL），随后无任何 NULL 检查直接访问 `obu->obu.frame.header`（第 107 行）或 `obu->obu.frame_header`（第 109 行）以及 `obu->header.spatial_id`（第 113 行），触发 NULL 指针解引用。
- **触发条件**: 攻击者构造一个 AV1 bitstream，包含：(1) 一个合法的 SEQUENCE_HEADER OBU，其 `operating_point_idc[0]` 不覆盖所有 temporal/spatial layer（即某些 bit 为 0）；(2) 紧接一个 `AV1_OBU_FRAME_HEADER` 或 `AV1_OBU_FRAME` OBU，设置 `obu_extension_flag=1`，并将 `temporal_id` 或 `spatial_id` 设置为当前 operating point 未覆盖的 layer，使 CBS 触发 `drop_obu()` 路径。该文件通过 `ffmpeg -i crafted.av1` 解析即可触发。
- **安全影响**: NULL 指针解引用导致进程崩溃（SIGSEGV），构成可靠的远程/本地 DoS。在现代 Linux 默认配置下（NULL 地址未映射）不直接导致 RCE，但若在嵌入式或特殊内存布局环境中 NULL 页被映射，存在信息泄露或控制流劫持的潜在风险。

<!-- AUDIT_PROMPT_VERSION: 1 -->
