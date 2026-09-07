#!/bin/bash
# xpdf 4.06 (pdftotext) 全量安全审计脚本（仅内存安全漏洞）
#
# 用法:
#   ./xpdf_audit.sh                        # 默认 resume 模式
#   ./xpdf_audit.sh --restart              # 清除结果，从头开始
#   ./xpdf_audit.sh --restart-from 5       # 从第5个文件开始
#   ./xpdf_audit.sh --list-pending         # 列出未审计文件
#   ./xpdf_audit.sh --stats                # 统计审计结果
#   ./xpdf_audit.sh --no-poc               # 只审计，跳过 PoC
#   ./xpdf_audit.sh --poc-only             # 只跑 PoC 生成阶段
#   ./xpdf_audit.sh --restart-poc          # 清除 PoC，重新生成
#   ./xpdf_audit.sh xpdf/Stream.cc         # 审计指定文件

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="/data/ylwang/non-textfuzz/target/xpdf"
OUTDIR="/data/ylwang/non-textfuzz/target/_audit_result/xpdf"
LOGFILE="$OUTDIR/audit.log"
mkdir -p "$OUTDIR"

PROMPT_VERSION="1"
VERSION_MARKER="AUDIT_PROMPT_VERSION"

MODE="resume"
RESTART_FROM=0
RUN_AUDIT=1
RUN_POC=1
RESTART_POC=0
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --resume)       MODE="resume";        shift ;;
        --restart)      MODE="restart";       shift ;;
        --restart-from) MODE="restart-from"; RESTART_FROM="$2"; shift 2 ;;
        --list-pending) MODE="list-pending";  shift ;;
        --stats)        MODE="stats";         shift ;;
        --no-poc)       RUN_POC=0;            shift ;;
        --poc-only)     RUN_AUDIT=0;          shift ;;
        --restart-poc)  RESTART_POC=1;        shift ;;
        -h|--help)      sed -n '2,17p' "$0"; exit 0 ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

tag_for() {
    local f="$1" name dir
    name=$(basename "$f"); name="${name//./_}"
    dir=$(dirname "$f" | tr "/" "_")
    [ "$dir" = "." ] && dir=""
    [ -n "$dir" ] && echo "${dir}_${name}" || echo "$name"
}

result_is_current() {
    local result="$1"
    [ -f "$result" ] || return 1
    grep -q "^<!-- ${VERSION_MARKER}: ${PROMPT_VERSION} -->$" "$result" 2>/dev/null
}

SCAN_ROOTS=("$SOURCE_DIR/xpdf" "$SOURCE_DIR/goo" "$SOURCE_DIR/fofi")

if [ $# -gt 0 ]; then
    FILES=("$@")
else
    for root in "${SCAN_ROOTS[@]}"; do
        if [ ! -d "$root" ]; then
            echo "FATAL: scan root missing: $root" >&2; exit 2
        fi
    done
    mapfile -t FILES < <(
        for root in "${SCAN_ROOTS[@]}"; do
            find "$root" \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) \
                -not -path '*/build_test/*' | sed "s|^$SOURCE_DIR/||"
        done | sort
    )
fi

VALID_FILES=(); MISSING=0
for f in "${FILES[@]}"; do
    if [ -f "$SOURCE_DIR/$f" ]; then VALID_FILES+=("$f")
    else echo "WARNING: File not found, skipping: $f"; MISSING=$((MISSING + 1)); fi
done
FILES=("${VALID_FILES[@]}"); TOTAL=${#FILES[@]}

if [ "$MODE" = "stats" ]; then
    done_count=$(find "$OUTDIR" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' \n')
    vuln_files=$({ grep -rl --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    vuln_entries=$({ grep -rh --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    POC_BASE_STAT="/data/ylwang/non-textfuzz/target/_poc/xpdf"
    poc_total=$(find "$POC_BASE_STAT" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$POC_BASE_STAT"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    echo "=========================================="; echo " xpdf (pdftotext) Audit Statistics"
    echo " Total source files:      $TOTAL"; echo " Files audited:           $done_count"
    echo " Files remaining:         $((TOTAL - done_count))"; echo " Files with vulns:        $vuln_files"
    echo " Total vuln entries:      $vuln_entries"; echo " PoCs total / verified:   $poc_total / $poc_verified"
    echo "=========================================="; exit 0
fi

if [ "$MODE" = "list-pending" ]; then
    PENDING=(); STALE=0
    for f in "${FILES[@]}"; do
        tag=$(tag_for "$f"); result="$OUTDIR/${tag}.md"
        if ! result_is_current "$result"; then PENDING+=("$f"); [ -f "$result" ] && STALE=$((STALE + 1)); fi
    done
    echo "=========================================="; echo " Pending files: ${#PENDING[@]} / $TOTAL  (含 $STALE 个过期)"
    echo "=========================================="; for f in "${PENDING[@]}"; do echo "  $f"; done; exit 0
fi

[ "$MODE" = "restart" ] && { echo "MODE: restart — clearing ALL previous results..."; rm -f "$OUTDIR"/*.md; }
if [ "$MODE" = "restart-from" ]; then
    idx=0; for f in "${FILES[@]}"; do idx=$((idx+1)); if [ "$idx" -ge "$RESTART_FROM" ]; then tag=$(tag_for "$f"); rm -f "$OUTDIR/${tag}.md"; fi; done
fi

AUDIT_PROMPT_TEMPLATE='你是一个顶级 C++ 安全审计专家，正在对 xpdf 4.06（一个 PDF 渲染工具，pdftotext 从中提取文本）进行授权安全审计，目标是发现可提交 bug bounty 的真实内存安全漏洞。

请仔细阅读文件 __SOURCE_DIR__/__FILE__ 的完整内容。
同时用 Grep/Glob/Read 查看相关的头文件、宏定义、调用的函数实现，以理解完整上下文。

**大文件必须多遍 / 分组深读——"一遍读完就判 clean"是历史漏报根因：**
- 若文件较大（≳500 行），不要一遍扫完就下结论。用 Read 工具分批读取（每批 400-600 行），逐组分析后**在自己的输出里**记录每组的发现，全部读完后汇总成 `## VULN:` 块。**不要派发 subagent**，全部在你自己的消息里完成，这样输出才能被正确捕获。
- 每个函数群都要追到边界条件（malloc 大小、数组索引、指针算术、整数溢出后的 malloc 大小参数）。

项目背景：
- xpdf 是一个用 C++ 编写的 PDF 查看工具。pdftotext 提取 PDF 文本内容。
- 源代码核心在 xpdf/ 目录（PDF 解析）、goo/ 目录（通用工具库）、fofi/ 目录（字体解析）。
- 主要攻击面：攻击者在命令行传入精心构造的 PDF 文件给 pdftotext，触发内存安全漏洞。
  - 基本用法：pdftotext input.pdf output.txt 或 pdftotext input.pdf -（输出到 stdout）
- PDF 容器解析流程：
  - PDF header: %PDF-1.x
  - 对象：数字直接对象、字符串、名称、数组、字典、流、null
  - xref 表：交叉引用表（对象偏移量）
  - 流对象：<< /Length N >> stream...endstream（Length 来自文件）
  - 字体：Type1/TrueType/CIDFont 的 FontDescriptor 中有 FontFile/FontFile2/FontFile3 流
- 主要漏洞面：
  - Stream.cc: 流过滤器解码（LZW、Flate、JBIG2、JPX）的缓冲区溢出
  - Gfx.cc: 图形状态机处理 path/text/form 时的越界
  - fofi/ 目录：TrueType/Type1/CFF 字体解析的 OOB read/write

**重点关注以下内存安全漏洞类型（仅报告内存安全漏洞，不报告逻辑漏洞）：**

1. **流过滤器解码 OOB write**：LZWDecode/FlateDecode 解码输出缓冲区大小不足（length 字段来自文件）。
2. **堆缓冲区溢出**：GString/GList append 操作时 buf/data 未及时扩容而越界写。
3. **越界读**：xref 解析时 obj_num 超过 xref 表大小，直接数组下标访问。
4. **整数溢出**：流对象 /Length 字段（来自文件的 int）用于 malloc 时溢出。
5. **Use-After-Free**：PDF 页面对象缓存失效后被访问。
6. **字体解析 OOB**：fofi/FoFiType1C.cc 中 offset/index 字段来自字体文件，未经校验。

不报告：逻辑错误、渲染输出差异、纯假设性漏洞。

主动使用工具获取上下文：
1. grep -rn "函数名" __SOURCE_DIR__/xpdf __SOURCE_DIR__/goo --include="*.cc" --include="*.h"
2. 追踪处理外部输入（PDF 字节）的函数数据来源。
3. 对 malloc/new/gmallocn 调用，确认是否有大小校验。
4. 关注 GString::append、memcpy、GList::push 等操作。
5. 检查流对象 Length、数组/字典 count 字段是否有上界校验。

==================== 最终输出契约（极其重要，违反则结果作废）====================
你这次任务的【最终回复，也就是最后一条消息】会被原样保存为审计报告，并被自动化脚本用 grep "^## VULN:" 解析。
1. 每个漏洞独立块，以 `## VULN:` 开头（行首顶格）。
2. 最终消息里除了 `## VULN:` 块（或单独的 NO_VULN_FOUND）之外，不要有任何其它内容。
3. 没有发现漏洞时，最终消息只输出一行：NO_VULN_FOUND
==================================================================================

输出格式（每个漏洞一个块）：
## VULN: <简短英文标题>
- **漏洞类别**: memory-safety
- **函数**: xxx()
- **行号**: xxx-xxx
- **CWE**: CWE-XXX (名称)
- **CVSS v3.1**: X.X (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H 等)
- **严重程度**: Critical/High/Medium/Low
- **攻击向量**: crafted PDF file
- **外部触发路径**: <从入口到漏洞点的完整调用链>
- **描述**: xxx（说明漏洞成因——内存破坏机制）
- **触发条件**: xxx（攻击者需要构造怎样的 PDF 文件）
- **安全影响**: xxx（最坏情况下的利用后果：RCE/DoS/信息泄露/…）'

BIN="/data/ylwang/non-textfuzz/target/xpdf/build_test/bin/pdftotext"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/xpdf"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=1
if [ "$RUN_POC" = "0" ]; then POC_ENABLED=0
elif [ ! -x "$BIN" ]; then echo "WARNING: $BIN not executable — PoC phase will be skipped."; POC_ENABLED=0
else POC_ENABLED=1; fi

if [ "$POC_ENABLED" = "1" ]; then
    mkdir -p "$POC_BASE"
    [ "$RESTART_POC" = "1" ] && { echo "MODE: --restart-poc — clearing all existing PoCs..."; rm -rf "$POC_BASE"; mkdir -p "$POC_BASE"; }
fi

POC_PROMPT_TEMPLATE='你是 xpdf/pdftotext 安全研究员。基于已有的漏洞审计报告，为每个漏洞生成可实际复现的 PoC。

==================== 硬性规则（违反则 PoC 无效）====================
本项目的 __BIN__ 已经是 ASAN+UBSAN 构建。所有 PoC 必须通过这个真实二进制触发。

1. **严禁自写 harness**：
   - 不允许把漏洞函数抠出来单独编译成可执行文件
   - 不允许链接 xpdf 内部头文件写任何 C/C++ 程序
   - 不允许通过任何方式编译新的 C/C++ 代码来触发漏洞
2. **唯一合法的漏洞触发途径**（只允许以下两种方式）：
   a. 用 Python struct 模块构造精心设计的恶意 PDF 字节序列（vuln_NNN_gen.py）
   b. 用 shell 脚本直接调用 pdftotext，并通过命令行选项（-r、-f、-l、-enc、-opw、-upw 等）调整执行路径（vuln_NNN_run.sh）
   —— 让 ASAN/UBSAN 在真实执行路径中自行报错
3. 唯一可接受的辅助文件：
   - vuln_NNN_gen.py：Python 脚本，只用 struct/bytes 构造 PDF，绝不调用目标库函数
   - vuln_NNN_run.sh：Shell 脚本，调用 pdftotext [选项] 处理恶意 PDF
====================================================================

漏洞报告:   __RESULT_FILE__
源代码文件: __SOURCE_DIR__/__SOURCE_FILE__
PoC 目录:   __POC_DIR__
pdftotext 二进制: __BIN__

PDF 最小结构（用于构造 PoC）：
  %PDF-1.4\n
  1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n
  2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n
  3 0 obj\n<< /Type /Page /MediaBox [0 0 612 792] >>\nendobj\n
  xref\n0 4\n0000000000 65535 f \n...\n
  trailer\n<< /Size 4 /Root 1 0 R >>\n
  startxref\nNNN\n%%EOF

流对象构造：
  N 0 obj\n<< /Length M /Filter /FlateDecode >>\nstream\n{bytes}\nendstream\nendobj

pdftotext 调用：
  ASAN_OPTIONS="abort_on_error=0:log_path=__POC_DIR__/asan.log" \
    __BIN__ __POC_DIR__/vuln_NNN.pdf /dev/null \
    > __POC_DIR__/vuln_NNN_result.txt 2>&1 || true

步骤：
1. Read 漏洞报告，列出全部 "## VULN:" 漏洞条目。
2. **对每个漏洞并行派发一个 subagent**（subagent_type=general-purpose）。

每个 subagent：
A. 读懂 VULN，判断是否可通过 PDF 文件触发（否则 SKIPPED）。
B. 在 __POC_DIR__/ 下生成 vuln_NNN_gen.py、vuln_NNN_run.sh、vuln_NNN_notes.md。
C. chmod +x，运行：timeout 30 bash __POC_DIR__/vuln_NNN_run.sh
D. 写 vuln_NNN_status.txt（第一行：VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED）

工具白名单：Read, Write, Bash, Grep, Glob, Agent。'

POC_PIDS=(); POC_LAUNCHED=0; POC_SKIPPED=0; AUDIT_PIDS=()
poc_reap() { local alive=() pid; for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && alive+=("$pid"); done; POC_PIDS=("${alive[@]+"${alive[@]}"}"); }
poc_throttle() { while :; do poc_reap; [ "${#POC_PIDS[@]}" -lt "$POC_PARALLEL" ] && break; sleep 3; done; }
audit_reap() { local alive=() pid; for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && alive+=("$pid"); done; AUDIT_PIDS=("${alive[@]+"${alive[@]}"}"); }
audit_throttle() { while :; do drain_events; audit_reap; [ "${#AUDIT_PIDS[@]}" -lt "$AUDIT_PARALLEL" ] && break; sleep 2; done; }
jobs_cleanup() { local pid; for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}" "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null || true; done; }
trap jobs_cleanup EXIT INT TERM

launch_poc_bg() {
    local f="$1" tag="$2" result="$3" vuln_n="$4"
    [ "$POC_ENABLED" = "1" ] || return 0
    local POC_DIR="$POC_BASE/$tag"
    if [ -f "$POC_DIR/.done" ]; then POC_SKIPPED=$((POC_SKIPPED + 1)); return 0; fi
    mkdir -p "$POC_DIR"
    local prompt="${POC_PROMPT_TEMPLATE//__BIN__/$BIN}"
    prompt="${prompt//__SOURCE_DIR__/$SOURCE_DIR}"; prompt="${prompt//__RESULT_FILE__/$result}"
    prompt="${prompt//__SOURCE_FILE__/$f}"; prompt="${prompt//__POC_DIR__/$POC_DIR}"
    poc_throttle
    (
        if CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "$prompt" --model claude-sonnet-4-6 --dangerously-skip-permissions \
            --allowedTools "Read,Write,Bash,Grep,Glob,Agent" > "$POC_DIR/poc_session.log" 2>&1; then
            if grep -qE "You're out of extra usage|hit your (session|usage) limit|Background tasks still running after" "$POC_DIR/poc_session.log" 2>/dev/null; then
                echo "[$(date '+%F %T')] POC USAGE-LIMIT $f" >> "$LOGFILE"
            else
                touch "$POC_DIR/.done"
                local verified; verified=$({ grep -l "^VERIFIED" "$POC_DIR"/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
                echo "[$(date '+%F %T')] POC $f: $verified/$vuln_n verified" >> "$LOGFILE"
            fi
        else echo "[$(date '+%F %T')] POC ERR $f: claude exit $?" >> "$LOGFILE"; fi
    ) &
    POC_PIDS+=($!); POC_LAUNCHED=$((POC_LAUNCHED + 1))
    echo "  -> launched PoC (bg pid=$!, running=${#POC_PIDS[@]}/$POC_PARALLEL)"
}

COUNT=0; VULN_COUNT=0; SKIPPED=0; ERRORS=0; EVENTS_SEEN=0
: > "$EVENTS_FILE"; rm -f "$STOP_FILE"

drain_events() {
    [ -f "$EVENTS_FILE" ] || return 0
    local total_lines; total_lines=$(wc -l < "$EVENTS_FILE" | tr -d ' ')
    [ "$total_lines" -gt "$EVENTS_SEEN" ] || return 0
    local type ef etag eresult evn
    while IFS='|' read -r type ef etag eresult evn; do
        case "$type" in
            VULN) VULN_COUNT=$((VULN_COUNT + evn)); echo "  -> [$ef] FOUND $evn vulnerability(ies)!"; echo "[$(date '+%F %T')] VULN $ef: $evn findings" >> "$LOGFILE"; launch_poc_bg "$ef" "$etag" "$eresult" "$evn" ;;
            CLEAN) echo "  -> [$ef] Clean." ;;
            ERROR) ERRORS=$((ERRORS + 1)); echo "  -> [$ef] WARNING: empty result, removed" | tee -a "$LOGFILE" ;;
            ANOMALY) echo "  -> [$ef] WARNING: format anomaly" | tee -a "$LOGFILE"; echo "[$(date '+%F %T')] FORMAT-ANOMALY $ef" >> "$LOGFILE" ;;
            USAGE_LIMIT) echo ""; echo "!!! USAGE LIMIT: $ef"; echo "[$(date '+%F %T')] STOPPED: usage limit hit at $ef" >> "$LOGFILE" ;;
        esac
    done < <(tail -n "+$((EVENTS_SEEN + 1))" "$EVENTS_FILE")
    EVENTS_SEEN=$total_lines
}

audit_one() {
    local f="$1" tag="$2" result="$3"
    local prompt="${AUDIT_PROMPT_TEMPLATE//__SOURCE_DIR__/$SOURCE_DIR}"; prompt="${prompt//__FILE__/$f}"
    claude -p "$prompt" --model claude-sonnet-4-6 --dangerously-skip-permissions \
        --allowedTools "Read,Grep,Glob,Agent" > "$result" 2>&1
    if grep -qE "You're out of extra usage|hit your (session|usage) limit|Background tasks still running after" "$result" 2>/dev/null; then
        rm -f "$result"; touch "$STOP_FILE"; echo "USAGE_LIMIT|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"; return 0; fi
    if [ ! -s "$result" ]; then rm -f "$result"; echo "ERROR|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"; return 0; fi
    printf '\n<!-- %s: %s -->\n' "$VERSION_MARKER" "$PROMPT_VERSION" >> "$result"
    if grep -q "^## VULN:" "$result" 2>/dev/null; then
        local vuln_n; vuln_n=$(grep -c "^## VULN:" "$result"); echo "VULN|${f}|${tag}|${result}|${vuln_n}" >> "$EVENTS_FILE"
    elif grep -qi "NO_VULN_FOUND" "$result" 2>/dev/null; then echo "CLEAN|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    else echo "ANOMALY|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"; fi
}

echo "=========================================="; echo " xpdf (pdftotext) Full Security Audit"
echo " Mode: $MODE  (audit=$RUN_AUDIT, poc=$POC_ENABLED, audit_parallel=$AUDIT_PARALLEL, poc_parallel=$POC_PARALLEL)"
echo " Files to audit: $TOTAL (skipped $MISSING missing)"; echo " Results: $OUTDIR/   PoCs: $POC_BASE/"; echo " Log: $LOGFILE"; echo "=========================================="; echo ""

if [ "$RUN_AUDIT" = "0" ]; then
    echo "Skipping audit phase (--poc-only)..."
    for f in "${FILES[@]}"; do tag=$(tag_for "$f"); result="$OUTDIR/${tag}.md"; [ -f "$result" ] || continue; grep -q "^## VULN:" "$result" 2>/dev/null || continue; vuln_n=$(grep -c "^## VULN:" "$result"); launch_poc_bg "$f" "$tag" "$result" "$vuln_n"; done
else
for f in "${FILES[@]}"; do
    [ -f "$STOP_FILE" ] && break
    COUNT=$((COUNT + 1)); tag=$(tag_for "$f"); result="$OUTDIR/${tag}.md"
    if result_is_current "$result"; then
        SKIPPED=$((SKIPPED + 1))
        if [ "$POC_ENABLED" = "1" ] && grep -q "^## VULN:" "$result" 2>/dev/null; then vuln_n=$(grep -c "^## VULN:" "$result"); launch_poc_bg "$f" "$tag" "$result" "$vuln_n"; fi
        continue
    elif [ -f "$result" ]; then echo "[$COUNT/$TOTAL] Stale — re-auditing: $f"; rm -f "$result"
    else echo "[$COUNT/$TOTAL] Auditing: $f"; fi
    audit_throttle
    audit_one "$f" "$tag" "$result" &
    AUDIT_PIDS+=($!)
done
for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do wait "$pid" 2>/dev/null || true; done; drain_events
if [ -f "$STOP_FILE" ]; then echo ""; echo "!!! Resume with: ./xpdf_audit.sh"; wait
    echo "=========================================="; echo " Audit INTERRUPTED"; rm -f "$STOP_FILE"; exit 1; fi
echo ""; echo "=========================================="; echo " Audit Complete"
echo " Files audited: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL total"
echo " Errors: $ERRORS"; echo " Vulnerabilities found: $VULN_COUNT"; echo "=========================================="
echo "[$(date '+%F %T')] DONE: $((COUNT - SKIPPED)) new, $SKIPPED skipped, $VULN_COUNT vulns" >> "$LOGFILE"
fi

[ "$POC_ENABLED" = "1" ] && [ "${#POC_PIDS[@]}" -gt 0 ] && { echo ""; echo "Waiting for background PoC subagents..."; wait; }
if [ "$POC_ENABLED" = "1" ]; then
    poc_done=$(find "$POC_BASE" -name '.done' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$POC_BASE"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_total=$(find "$POC_BASE" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    echo "=========================================="; echo " PoC Generation Summary"
    echo " Launched: $POC_LAUNCHED  Skip: $POC_SKIPPED  Done: $poc_done  Total: $poc_total  Verified: $poc_verified"
    echo " Base: $POC_BASE/"; echo "=========================================="
fi
