#!/bin/bash
# Bento4 1.5.1-628 (mp42aac) 全量安全审计脚本（仅内存安全漏洞）
#
# 用法:
#   ./bento4_audit.sh                        # 默认 resume 模式
#   ./bento4_audit.sh --restart              # 清除结果，从头开始
#   ./bento4_audit.sh --restart-from 5       # 从第5个文件开始
#   ./bento4_audit.sh --list-pending         # 列出未审计文件
#   ./bento4_audit.sh --stats                # 统计审计结果
#   ./bento4_audit.sh --no-poc               # 只审计，跳过 PoC
#   ./bento4_audit.sh --poc-only             # 只跑 PoC 生成阶段
#   ./bento4_audit.sh --restart-poc          # 清除 PoC，重新生成
#   ./bento4_audit.sh Source/C++/Core/Ap4File.cpp  # 审计指定文件

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="/data/ylwang/non-textfuzz/target/Bento4"
OUTDIR="/data/ylwang/non-textfuzz/target/_audit_result/Bento4"
LOGFILE="$OUTDIR/audit.log"
mkdir -p "$OUTDIR"

PROMPT_VERSION="1"
VERSION_MARKER="AUDIT_PROMPT_VERSION"

# ============================================================
# 选项解析
# ============================================================
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
        --restart-from)
            MODE="restart-from"
            RESTART_FROM="$2"
            shift 2
            ;;
        --list-pending) MODE="list-pending";  shift ;;
        --stats)        MODE="stats";         shift ;;
        --no-poc)       RUN_POC=0;            shift ;;
        --poc-only)     RUN_AUDIT=0;          shift ;;
        --restart-poc)  RESTART_POC=1;        shift ;;
        -h|--help)
            sed -n '2,17p' "$0"
            exit 0
            ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

# ============================================================
# 文件名 -> 结果路径的映射
# ============================================================
tag_for() {
    local f="$1"
    local name dir
    name=$(basename "$f")
    name="${name//./_}"
    dir=$(dirname "$f" | tr "/" "_")
    [ "$dir" = "." ] && dir=""
    [ -n "$dir" ] && echo "${dir}_${name}" || echo "$name"
}

result_is_current() {
    local result="$1"
    [ -f "$result" ] || return 1
    grep -q "^<!-- ${VERSION_MARKER}: ${PROMPT_VERSION} -->$" "$result" 2>/dev/null
}

# ============================================================
# 构建文件列表
# ============================================================
SCAN_ROOT="$SOURCE_DIR/Source/C++/Core"

if [ $# -gt 0 ]; then
    FILES=("$@")
else
    if [ ! -d "$SCAN_ROOT" ]; then
        echo "FATAL: scan root missing: $SCAN_ROOT" >&2
        exit 2
    fi

    mapfile -t FILES < <(
        find "$SOURCE_DIR/Source/C++/Core" \
             "$SOURCE_DIR/Source/C++/Apps/Mp42Aac" \
             -name '*.cpp' -o -name '*.h' 2>/dev/null \
        | sed "s|^$SOURCE_DIR/||" | sort
    )
fi

VALID_FILES=()
MISSING=0
for f in "${FILES[@]}"; do
    if [ -f "$SOURCE_DIR/$f" ]; then
        VALID_FILES+=("$f")
    else
        echo "WARNING: File not found, skipping: $f"
        MISSING=$((MISSING + 1))
    fi
done
FILES=("${VALID_FILES[@]}")
TOTAL=${#FILES[@]}

if [ "$MODE" = "stats" ]; then
    done_count=$(find "$OUTDIR" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' \n')
    vuln_files=$({ grep -rl --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    vuln_entries=$({ grep -rh --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    POC_BASE="/data/ylwang/non-textfuzz/target/_poc/Bento4"
    poc_total=$(find "$POC_BASE" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$POC_BASE"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    echo "=========================================="
    echo " Bento4 (mp42aac) Audit Statistics"
    echo " Total source files:      $TOTAL"
    echo " Files audited:           $done_count"
    echo " Files remaining:         $((TOTAL - done_count))"
    echo " Files with vulns:        $vuln_files"
    echo " Total vuln entries:      $vuln_entries"
    echo " PoCs total / verified:   $poc_total / $poc_verified"
    echo "=========================================="
    exit 0
fi

if [ "$MODE" = "list-pending" ]; then
    PENDING=()
    STALE=0
    for f in "${FILES[@]}"; do
        tag=$(tag_for "$f")
        result="$OUTDIR/${tag}.md"
        if ! result_is_current "$result"; then
            PENDING+=("$f")
            [ -f "$result" ] && STALE=$((STALE + 1))
        fi
    done
    echo "=========================================="
    echo " Pending files: ${#PENDING[@]} / $TOTAL  (含 $STALE 个过期需重审)"
    echo "=========================================="
    for f in "${PENDING[@]}"; do echo "  $f"; done
    exit 0
fi

if [ "$MODE" = "restart" ]; then
    echo "MODE: restart — clearing ALL previous results..."
    rm -f "$OUTDIR"/*.md
fi

if [ "$MODE" = "restart-from" ]; then
    idx=0
    for f in "${FILES[@]}"; do
        idx=$((idx + 1))
        if [ "$idx" -ge "$RESTART_FROM" ]; then
            tag=$(tag_for "$f")
            rm -f "$OUTDIR/${tag}.md"
        fi
    done
fi

# ============================================================
# 审计 prompt 模板
# ============================================================
AUDIT_PROMPT_TEMPLATE='你是一个顶级 C++ 安全审计专家，正在对 Bento4 1.5.1-628（一个 MP4/ISOBMFF 媒体容器解析库，mp42aac 工具使用它）进行授权安全审计，目标是发现可提交 bug bounty 的真实内存安全漏洞。

请仔细阅读文件 __SOURCE_DIR__/__FILE__ 的完整内容。
同时用 Grep/Glob/Read 查看相关的头文件、宏定义、调用的函数实现，以理解完整上下文。

**大文件必须多遍 / 分组深读——"一遍读完就判 clean"是历史漏报根因：**
- 若文件较大（≳500 行），不要一遍扫完就下结论。用 Read 工具分批读取（每批 400-600 行），逐组分析后**在自己的输出里**记录每组的发现，全部读完后汇总成 `## VULN:` 块。**不要派发 subagent**，全部在你自己的消息里完成，这样输出才能被正确捕获。
- 每个函数群都要追到边界条件（malloc 大小、数组索引、指针算术、整数溢出后的 malloc 大小参数）。

项目背景：
- Bento4 是一个用 C++ 编写的 MP4/ISOBMFF 媒体容器解析库。
- mp42aac 工具读取 MP4 文件，从中提取 AAC 音频流，写入 .aac 文件。
- 源代码核心库在 Source/C++/Core/，mp42aac 工具在 Source/C++/Apps/Mp42Aac/Mp42Aac.cpp。
- 主要攻击面：攻击者在命令行传入精心构造的 MP4 文件给 mp42aac，触发内存安全漏洞。
  - 基本用法：mp42aac input.mp4 output.aac
- MP4/ISOBMFF 容器解析流程：
  - Box 结构：size(4B BE) + type(4B) + [largesize(8B)] + data（可嵌套）
  - 关键 box：ftyp, moov, trak, mdia, minf, stbl, stsd, stsz, stco, ctts, stts, elst...
  - stsd box：sample description，包含 mp4a/avc1 等编解码器信息
  - stsz box：每个 sample 的大小数组（sample_count 来自文件）
  - stco box：chunk offset 数组（chunk_count 来自文件）
  - ctts/stts box：time-to-sample 和 composition offset 表

**重点关注以下内存安全漏洞类型（仅报告内存安全漏洞，不报告逻辑漏洞）：**

1. **整数溢出 → malloc 下分配**：AP4_Size count 来自文件字段直接用于 new T[count] 或 malloc(count * size)，count 超大导致溢出。
2. **堆缓冲区溢出**：AP4_DataBuffer 或 char[] 写入时大小计算错误（写入偏移 + 数据长度超过缓冲区）。
3. **越界读**：box data 读取时使用文件字段 offset + length > 实际可用字节。
4. **Use-After-Free**：AP4_Sample 对象或 AP4_Track 对象析构后被引用。
5. **有符号/无符号截断**：AP4_UI32 被截断为 AP4_SI32 造成负数偏移。
6. **AP4_Array 越界**：GetItemCount() 来自文件，直接用于 operator[] 索引而无边界检查。
7. **空指针解引用**：GetSample()/GetTrack() 返回 NULL 时未检查直接解引用。

不报告以下情形：
- 逻辑错误（错误的 MP4 元数据解析等）——本项目只审计内存安全。
- 仅在非默认编译选项下才能触发的问题。
- 纯假设性漏洞或已知 CVE 的重复。

主动使用工具获取上下文（必须执行以下步骤，不能跳过）：
1. 用 Grep 搜索关键函数调用点：grep -rn "函数名" __SOURCE_DIR__/Source --include="*.cpp" --include="*.h"
2. 对处理外部输入（MP4 文件字节）的函数，追踪数据来源。
3. 对 new[]/malloc/AP4_Allocate 调用，确认调用处是否有大小校验。
4. 关注 memcpy、AP4_CopyMemory、Read 等函数的使用，尤其是大小参数来自文件字段。
5. 检查 box size/count 字段是否有上界校验。

⚠️ malloc/new[] 溢出判据：只要在分配前 count/size 本身可以整数溢出且来自文件，就要报告；只有当有明确的上界校验才判不可达。

==================== 最终输出契约（极其重要，违反则结果作废）====================
你这次任务的【最终回复，也就是最后一条消息】会被原样保存为审计报告，并被自动化脚本用 grep "^## VULN:" 解析来决定是否生成 PoC。因此必须严格遵守：
1. 每一个漏洞都必须是独立的块，以 `## VULN:` 开头（必须行首顶格，前面不能有任何字符），严格按下面"输出格式"逐字段输出。
2. 严禁用表格、散文段落或要点列表来"汇总"漏洞。最终消息里除了若干 `## VULN:` 块（或单独的 NO_VULN_FOUND）之外，不要有任何其它内容。
3. 没有发现任何可被外部触发的漏洞时，最终消息【只输出一行】：NO_VULN_FOUND
==================================================================================

输出格式（每个漏洞一个块）：
## VULN: <简短英文标题>
- **漏洞类别**: memory-safety
- **函数**: xxx()
- **行号**: xxx-xxx
- **CWE**: CWE-XXX (名称)
- **CVSS v3.1**: X.X (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H 等)
- **严重程度**: Critical/High/Medium/Low
- **攻击向量**: crafted MP4 file
- **外部触发路径**: <从入口到漏洞点的完整调用链>
- **描述**: xxx（说明漏洞成因——内存破坏机制）
- **触发条件**: xxx（攻击者需要构造怎样的 MP4 文件）
- **安全影响**: xxx（最坏情况下的利用后果：RCE/DoS/信息泄露/…）'

# ============================================================
# PoC 生成相关设置
# ============================================================
BIN="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/Bento4"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=1
if [ "$RUN_POC" = "0" ]; then
    POC_ENABLED=0
elif [ ! -x "$BIN" ]; then
    echo "WARNING: $BIN not executable — PoC phase will be skipped."
    POC_ENABLED=0
else
    POC_ENABLED=1
fi

if [ "$POC_ENABLED" = "1" ]; then
    mkdir -p "$POC_BASE"
    if [ "$RESTART_POC" = "1" ]; then
        echo "MODE: --restart-poc — clearing all existing PoCs..."
        rm -rf "$POC_BASE"
        mkdir -p "$POC_BASE"
    fi
fi

POC_PROMPT_TEMPLATE='你是 Bento4/mp42aac 安全研究员。基于已有的漏洞审计报告，为每个漏洞生成可实际复现的 PoC。

==================== 硬性规则（违反则 PoC 无效）====================
本项目的 __BIN__ 已经是 ASAN+UBSAN 构建。
所有 PoC 必须通过这个真实二进制触发。

1. **严禁自写 harness**：
   - 不允许把漏洞函数抠出来单独编译成可执行文件
   - 不允许链接 Bento4 内部头文件写任何 C/C++ 程序
   - 不允许通过任何方式编译新的 C/C++ 代码来触发漏洞
2. **唯一合法的漏洞触发途径**（只允许以下两种方式）：
   - 用 Python struct 模块构造精心设计的恶意 MP4 字节序列（vuln_NNN_gen.py），
   - 用 shell 脚本直接调用 mp42aac 二进制，并通过命令行参数调整执行路径（vuln_NNN_run.sh），
   - 让 ASAN/UBSAN 在真实执行路径中自行报错。
3. 唯一可接受的辅助文件：
   - vuln_NNN_gen.py：Python 脚本，只用 struct/bytes 构造 MP4，绝不调用目标库函数
   - vuln_NNN_run.sh：Shell 脚本，调用 mp42aac [选项] 处理恶意 MP4
====================================================================

漏洞报告:   __RESULT_FILE__
源代码文件: __SOURCE_DIR__/__SOURCE_FILE__
PoC 目录:   __POC_DIR__
mp42aac 二进制: __BIN__

MP4 文件基本结构（用于构造 PoC）：
- 所有 box：size(4B BE) + type(4B) + data
  - size=0 表示延伸到文件末尾；size=1 表示后面跟 8B largesize
- ftyp box：brand(4B) + version(4B) + compatible_brands(N*4B)
- moov box：包含 mvhd + trak 子 box
  - trak box：包含 tkhd + mdia 子 box
    - mdia：mdhd + hdlr + minf
      - minf：smhd/vmhd + dinf + stbl
        - stbl：stsd + stts + stsc + stsz + stco
          - stsz：sample_size(4B) + sample_count(4B) + entry_size(N*4B)
          - stco：entry_count(4B) + chunk_offset(N*4B BE)
  - udta box：user data
- mdat box：实际媒体数据

==================== PoC 生成范围限制 ====================
下列情况跳过 PoC，直接写 vuln_NNN_status.txt 第一行为 SKIPPED：
- 漏洞无法通过在命令行传入构造的 MP4 文件来触发。
==========================================================

步骤：
1. Read 漏洞报告，列出全部 "## VULN:" 漏洞条目，按顺序编号。
2. **对每个漏洞并行派发一个 subagent**（一条消息内同时发出 N 个 Agent 调用，subagent_type=general-purpose）。

每个 subagent 完成：
A. 读懂对应 VULN，判断是否命中 SKIPPED 条件。
B. 在 __POC_DIR__/ 下生成（NNN 为 3 位零填编号）：
   - vuln_NNN_gen.py  —— 构造恶意 MP4 字节序列，写入 vuln_NNN.mp4
   - vuln_NNN_run.sh  —— 可执行 shell：
       1) 运行 gen.py 生成 MP4
       2) ASAN_OPTIONS="abort_on_error=0:log_path=__POC_DIR__/asan.log" \
            __BIN__ __POC_DIR__/vuln_NNN.mp4 /dev/null \
            > __POC_DIR__/vuln_NNN_result.txt 2>&1 || true
       3) 从 asan.log.* 中 grep ASAN/UBSAN 错误追加到 result.txt
   - vuln_NNN_notes.md  —— PoC 思路和预期现象
C. chmod +x vuln_NNN_run.sh，实际运行：timeout 30 bash __POC_DIR__/vuln_NNN_run.sh
D. 写 __POC_DIR__/vuln_NNN_status.txt（第一行：VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED）

工具白名单：Read, Write, Bash, Grep, Glob, Agent。'

POC_PIDS=()
POC_LAUNCHED=0
POC_SKIPPED=0
AUDIT_PIDS=()

poc_reap() {
    local alive=() pid
    for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}"; do
        kill -0 "$pid" 2>/dev/null && alive+=("$pid")
    done
    POC_PIDS=("${alive[@]+"${alive[@]}"}")
}
poc_throttle() {
    while :; do poc_reap; [ "${#POC_PIDS[@]}" -lt "$POC_PARALLEL" ] && break; sleep 3; done
}
audit_reap() {
    local alive=() pid
    for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
        kill -0 "$pid" 2>/dev/null && alive+=("$pid")
    done
    AUDIT_PIDS=("${alive[@]+"${alive[@]}"}")
}
audit_throttle() {
    while :; do drain_events; audit_reap; [ "${#AUDIT_PIDS[@]}" -lt "$AUDIT_PARALLEL" ] && break; sleep 2; done
}
jobs_cleanup() {
    local pid
    for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}" "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
        kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null || true
    done
}
trap jobs_cleanup EXIT INT TERM

launch_poc_bg() {
    local f="$1" tag="$2" result="$3" vuln_n="$4"
    [ "$POC_ENABLED" = "1" ] || return 0
    local POC_DIR="$POC_BASE/$tag"
    if [ -f "$POC_DIR/.done" ]; then POC_SKIPPED=$((POC_SKIPPED + 1)); return 0; fi
    mkdir -p "$POC_DIR"
    local prompt="${POC_PROMPT_TEMPLATE//__BIN__/$BIN}"
    prompt="${prompt//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__RESULT_FILE__/$result}"
    prompt="${prompt//__SOURCE_FILE__/$f}"
    prompt="${prompt//__POC_DIR__/$POC_DIR}"
    poc_throttle
    (
        if CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "$prompt" \
            --model claude-sonnet-4-6 \
            --dangerously-skip-permissions \
            --allowedTools "Read,Write,Bash,Grep,Glob,Agent" \
            > "$POC_DIR/poc_session.log" 2>&1; then
            if grep -qE "You're out of extra usage|hit your (session|usage) limit|Background tasks still running after" "$POC_DIR/poc_session.log" 2>/dev/null; then
                echo "[$(date '+%F %T')] POC USAGE-LIMIT $f" >> "$LOGFILE"
            else
                touch "$POC_DIR/.done"
                local verified
                verified=$({ grep -l "^VERIFIED" "$POC_DIR"/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
                echo "[$(date '+%F %T')] POC $f: $verified/$vuln_n verified" >> "$LOGFILE"
            fi
        else
            echo "[$(date '+%F %T')] POC ERR $f: claude exit $?" >> "$LOGFILE"
        fi
    ) &
    POC_PIDS+=($!)
    POC_LAUNCHED=$((POC_LAUNCHED + 1))
    echo "  -> launched PoC (bg pid=$!, running=${#POC_PIDS[@]}/$POC_PARALLEL)"
}

COUNT=0
VULN_COUNT=0
SKIPPED=0
ERRORS=0
EVENTS_SEEN=0
: > "$EVENTS_FILE"
rm -f "$STOP_FILE"

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
            USAGE_LIMIT) echo ""; echo "!!! USAGE LIMIT REACHED while auditing: $ef"; echo "[$(date '+%F %T')] STOPPED: usage limit hit at $ef" >> "$LOGFILE" ;;
        esac
    done < <(tail -n "+$((EVENTS_SEEN + 1))" "$EVENTS_FILE")
    EVENTS_SEEN=$total_lines
}

audit_one() {
    local f="$1" tag="$2" result="$3"
    local prompt="${AUDIT_PROMPT_TEMPLATE//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__FILE__/$f}"
    claude -p "$prompt" \
        --model claude-sonnet-4-6 \
        --dangerously-skip-permissions \
        --allowedTools "Read,Grep,Glob,Agent" \
        > "$result" 2>&1
    if grep -qE "You're out of extra usage|hit your (session|usage) limit|Background tasks still running after" "$result" 2>/dev/null; then
        rm -f "$result"; touch "$STOP_FILE"
        echo "USAGE_LIMIT|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"; return 0
    fi
    if [ ! -s "$result" ]; then
        rm -f "$result"
        echo "ERROR|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"; return 0
    fi
    printf '\n<!-- %s: %s -->\n' "$VERSION_MARKER" "$PROMPT_VERSION" >> "$result"
    if grep -q "^## VULN:" "$result" 2>/dev/null; then
        local vuln_n; vuln_n=$(grep -c "^## VULN:" "$result")
        echo "VULN|${f}|${tag}|${result}|${vuln_n}" >> "$EVENTS_FILE"
    elif grep -qi "NO_VULN_FOUND" "$result" 2>/dev/null; then
        echo "CLEAN|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    else
        echo "ANOMALY|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    fi
}

echo "=========================================="
echo " Bento4 (mp42aac) Full Security Audit"
echo " Mode: $MODE  (audit=$RUN_AUDIT, poc=$POC_ENABLED, audit_parallel=$AUDIT_PARALLEL, poc_parallel=$POC_PARALLEL)"
echo " Files to audit: $TOTAL (skipped $MISSING missing)"
echo " Results: $OUTDIR/   PoCs: $POC_BASE/"
echo " Log: $LOGFILE"
echo "=========================================="
echo ""

if [ "$RUN_AUDIT" = "0" ]; then
    echo "Skipping audit phase (--poc-only)..."
    for f in "${FILES[@]}"; do
        tag=$(tag_for "$f"); result="$OUTDIR/${tag}.md"
        [ -f "$result" ] || continue
        grep -q "^## VULN:" "$result" 2>/dev/null || continue
        vuln_n=$(grep -c "^## VULN:" "$result")
        launch_poc_bg "$f" "$tag" "$result" "$vuln_n"
    done
else
for f in "${FILES[@]}"; do
    [ -f "$STOP_FILE" ] && break
    COUNT=$((COUNT + 1))
    tag=$(tag_for "$f")
    result="$OUTDIR/${tag}.md"
    if result_is_current "$result"; then
        SKIPPED=$((SKIPPED + 1))
        if [ "$POC_ENABLED" = "1" ] && grep -q "^## VULN:" "$result" 2>/dev/null; then
            vuln_n=$(grep -c "^## VULN:" "$result"); launch_poc_bg "$f" "$tag" "$result" "$vuln_n"
        fi
        continue
    elif [ -f "$result" ]; then
        echo "[$COUNT/$TOTAL] Stale — re-auditing: $f"; rm -f "$result"
    else
        echo "[$COUNT/$TOTAL] Auditing: $f"
    fi
    audit_throttle
    audit_one "$f" "$tag" "$result" &
    AUDIT_PIDS+=($!)
done

for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do wait "$pid" 2>/dev/null || true; done
drain_events

if [ -f "$STOP_FILE" ]; then
    echo ""; echo "!!! Resume with: ./bento4_audit.sh"; wait
    echo "=========================================="
    echo " Audit INTERRUPTED (usage limit)"
    echo " Completed: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL"
    echo "=========================================="
    rm -f "$STOP_FILE"; exit 1
fi

echo ""; echo "=========================================="; echo " Audit Complete"
echo " Files audited: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL total"
echo " Errors: $ERRORS"; echo " Vulnerabilities found: $VULN_COUNT"; echo " Results: $OUTDIR/"
echo "=========================================="
echo "[$(date '+%F %T')] DONE: $((COUNT - SKIPPED)) new, $SKIPPED skipped, $VULN_COUNT vulns" >> "$LOGFILE"
fi

if [ "$POC_ENABLED" = "1" ] && [ "${#POC_PIDS[@]}" -gt 0 ]; then
    echo ""; echo "Waiting for ${#POC_PIDS[@]} background PoC subagent(s) to finish..."; wait
fi

if [ "$POC_ENABLED" = "1" ]; then
    poc_done=$(find "$POC_BASE" -name '.done' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$POC_BASE"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_total=$(find "$POC_BASE" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    echo "=========================================="; echo " PoC Generation Summary"
    echo " Launched this run:   $POC_LAUNCHED"; echo " Already-done skip:   $POC_SKIPPED"
    echo " Files with .done:    $poc_done"; echo " PoCs total/verified: $poc_total / $poc_verified"
    echo " Base: $POC_BASE/"; echo "=========================================="
fi
