Both issues are confirmed. Let me write the final audit report.

## VULN: NULL Pointer Dereference in print_filter via Unlinked Filter Pad
- **漏洞类别**: memory-safety
- **函数**: print_filter()
- **行号**: 411-413, 443-446
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted filtergraph / crafted media file triggering partial graph initialization
- **外部触发路径**: `ffmpeg -i <file> -vf <complex_filtergraph> -print_graphs 1 -f null -` → `print_filtergraphs()` → `print_filtergraphs_priv()` → `print_filtergraph_single()` → `print_filter()` → NULL dereference on `link->type` at line 413 / 446
- **描述**: In `print_filter()`, both the inputs loop (line 411–413) and the outputs loop (line 443–446) retrieve a raw `AVFilterLink *` pointer from `filter->inputs[i]` / `filter->outputs[i]` and immediately dereference it (`link->type`, `link->dstpad`, `link->src->name`, `link->dst->name`) without any NULL check. The `AVFilterLink **inputs` and `**outputs` fields in `AVFilterContext` (libavfilter/avfilter.h line 281–285) are arrays of pointers; individual entries can be NULL for pads that have not yet been connected. If `print_filter` is invoked on a filtergraph that is partially initialized—or one that FFmpeg's error-recovery left with an unlinked pad—every subsequent dereference (`link->type`, `link->dstpad`, `link->srcpad`, `link->src`, `link->dst`) constitutes a NULL pointer dereference, crashing the process.
- **触发条件**: Supply a complex filter graph string (`-vf` / `-filter_complex`) whose construction fails mid-way or uses a filter with optional pads that are left unlinked, and enable graph printing (`-print_graphs 1` or `-print_graphs_format json`). When `print_filter` iterates over `filter->nb_inputs` / `filter->nb_outputs` and encounters a NULL slot, it dereferences the NULL pointer.
- **安全影响**: Controlled crash (SIGSEGV) of the ffmpeg process; Denial of Service. On glibc/musl systems the NULL dereference is not exploitable for RCE under default ASLR, but can reliably terminate the process, making it a DoS vector for any service that auto-processes user-supplied media files with graph printing enabled.

## VULN: Missing NULL Guard in print_streams Output-Stream Loop Causes NULL Pointer Dereference
- **漏洞类别**: memory-safety
- **函数**: print_streams()
- **行号**: 780-782
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file / output configuration triggering incomplete OutputStream initialization
- **外部触发路径**: `ffmpeg -i <file> -o <output> -print_graphs 1` → `print_filtergraphs()` → `print_filtergraphs_priv()` → `print_streams()` → NULL dereference on `ost->st->codecpar->codec_id` at line 782
- **描述**: In `print_streams()`, the ENCODERS block at line 716 contains the explicit guard `if (!ost || !ost->st || !ost->st->codecpar || !ost->enc) continue;` before touching any member of `ost`. The OUTPUTSTREAMS block at lines 780–782 is missing this guard entirely: it retrieves `OutputStream *ost = of->streams[i]` and immediately chains `ost->st->codecpar->codec_id` into `avcodec_descriptor_get()` without checking whether `ost`, `ost->st`, or `ost->st->codecpar` is NULL. This inconsistency means any edge-case where an `OutputFile` has a NULL stream slot (e.g., interrupted initialization, stream-group paths, or future code changes) causes a NULL pointer dereference at the codec_id load, crashing the process.
- **触发条件**: Run ffmpeg with graph printing enabled (`-print_graphs 1`) against a crafted input or output configuration that results in `of->streams[i]` being NULL, or in which `ost->st` / `ost->st->codecpar` is NULL (e.g., a muxer initialization failure that leaves a partially constructed `OutputStream`). The guard present in the ENCODERS section at line 716 makes the asymmetry between the two loops apparent and confirms the OUTPUTSTREAMS section was not hardened equivalently.
- **安全影响**: Controlled crash (SIGSEGV) of the ffmpeg process; Denial of Service. Because the missing guard only affects the graph-printing diagnostic path, exploitation requires that path to be enabled, limiting exposure to deployments using `-print_graphs` or equivalent options.

<!-- AUDIT_PROMPT_VERSION: 1 -->
