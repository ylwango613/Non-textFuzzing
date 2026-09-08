# vuln_001 — SKIPPED

## 漏洞信息

- **函数**: `realloc_section_array()` in `libavcodec/ass_split.c`（行 213-226）
- **类别**: CWE-190 → CWE-787，signed-integer-overflow 导致 OOB write
- **触发路径**: `ffmpeg -i crafted.mkv -f null -` → Matroska demuxer → `ff_ass_split(extradata)` → `ass_split()` → `ass_split_section()` → `realloc_section_array()`
- **核心缺陷**: `tmp += *count * section->size` 中 `*count`（int）乘 `section->size`（int，ASSStyle=104）发生 signed integer overflow，当 `*count` 达到约 20,648,882 时溢出为负值，导致 `memset` 写入越界地址。

## 跳过原因

1. **触发阈值极高**: 需要在 MKV 文件的 ASS 字幕流 codec extradata 中包含超过 ~20,648,882 条 `Style:` 行才能触发溢出。

2. **文件体积不可行**: 每条 `Style:` 行约 30-50 字节，~20M 条目需要构造约 600MB 至 1GB 的 extradata 块，整体 MKV 文件将达到同等量级，远超合理测试文件大小。

3. **超出时间限制**: 生成并运行如此规模的文件无法在 60 秒超时内完成（文件写入 + ffmpeg 解析 ASS 头均需大量时间）。

4. **不符合可行 PoC 条件**: 无法通过构造合理大小的媒体文件命令行方式复现，实际 PoC 不可行。

## 未生成文件

- `vuln_001_gen.py` — 未生成
- `vuln_001_run.sh` — 未生成
- `vuln_001_result.txt` — 未生成
