#!/bin/bash
# libtiff (tiffsplit) 漏洞报告生成脚本
# 从 libtiff/poc/ 里挑出真正被 ASan/UBSan 在真实 tiffsplit 二进制执行路径中
# 确认(VERIFIED_CRASH)的漏洞，让 claude 把每一条整理成 report/libtiff.md 里的条目，追加写入。
#
# 用法:
#   ./libtiff_report.sh                 # 默认: 先检查源码是否已全部审计完，完成才生成报告
#   ./libtiff_report.sh --force         # 跳过"是否已全部审计完"的检查，直接生成
#   ./libtiff_report.sh --list          # 只列出当前满足条件、尚未写入 libtiff.md 的漏洞，不调用 claude
#   ./libtiff_report.sh --stats         # 统计完成度 + 已确认漏洞数 + 已写入报告数

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="/data/ylwang/non-textfuzz/target/libtiff"
OUTDIR="/data/ylwang/non-textfuzz/target/_audit_result/libtiff"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/libtiff"
DRAFTS_DIR="$OUTDIR/report-drafts"
LOGFILE="$OUTDIR/report.log"
REPORT_DIR="/data/ylwang/non-textfuzz/target/report"
REPORT_MD="/data/ylwang/non-textfuzz/target/report/libtiff.md"
REPORT_PARALLEL="${REPORT_PARALLEL:-4}"

mkdir -p "$DRAFTS_DIR"
mkdir -p "$REPORT_DIR"
[ -f "$REPORT_MD" ] || echo "# libtiff Vulnerabilities" > "$REPORT_MD"

# ============================================================
# 选项解析
# ============================================================
MODE="run"
FORCE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)  FORCE=1;        shift ;;
        --list)   MODE="list";    shift ;;
        --stats)  MODE="stats";   shift ;;
        -h|--help)
            sed -n '2,12p' "$0"
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ============================================================
# 与 libtiff_audit.sh 一致的 tag 映射
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

SCAN_ROOTS=("$SOURCE_DIR/libtiff" "$SOURCE_DIR/tools")
mapfile -t SRC_FILES < <(
    for root in "${SCAN_ROOTS[@]}"; do
        find "$root" -name '*.c' | sed "s|^$SOURCE_DIR/||"
    done | sort
)
TOTAL_SRC=${#SRC_FILES[@]}

# ============================================================
# 完整性检查
# ============================================================
MISSING_AUDIT=0
for f in "${SRC_FILES[@]}"; do
    tag=$(tag_for "$f")
    [ -f "$OUTDIR/${tag}.md" ] || MISSING_AUDIT=$((MISSING_AUDIT + 1))
done
AUDITED=$((TOTAL_SRC - MISSING_AUDIT))

if [ "$MODE" = "stats" ]; then
    written=$(grep -c "^<!-- REPORT_SOURCE:" "$REPORT_MD" 2>/dev/null || echo 0)
    crash_total=0; behav_total=0
    if [ -d "$POC_BASE" ]; then
        crash_total=$({ grep -rl "^VERIFIED_CRASH" "$POC_BASE"/*/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
        behav_total=$({ grep -rl "^VERIFIED_BEHAVIOR" "$POC_BASE"/*/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
    fi
    echo "=========================================="
    echo " libtiff Report Statistics"
    echo " src files audited:            $AUDITED / $TOTAL_SRC"
    echo " PoC status=VERIFIED_CRASH:    $crash_total"
    echo " PoC status=VERIFIED_BEHAVIOR: $behav_total"
    echo " Entries already in $(basename "$REPORT_MD"): $written"
    echo "=========================================="
    exit 0
fi

if [ "$MODE" = "run" ] && [ "$FORCE" != "1" ] && [ "$MISSING_AUDIT" -gt 0 ]; then
    echo "Audit not yet complete: $AUDITED / $TOTAL_SRC files audited, $MISSING_AUDIT pending."
    echo "Run ./libtiff_audit.sh (or ./libtiff_audit.sh --list-pending) until it finishes, then rerun ./libtiff_report.sh."
    echo "(Use --force to generate a report from whatever has been confirmed so far.)"
    exit 1
fi

# ============================================================
# 从 libtiff/<tag>.md 里抽出第 N 个 "## VULN:" 块的原文
# ============================================================
extract_vuln_block() {
    local file="$1" n="$2"
    awk -v n="$n" '
        /^## VULN:/ { c++; if (c == n) { p = 1; print; next } else { p = 0 } ; next }
        /^<!-- AUDIT_PROMPT_VERSION:/ { p = 0 }
        p { print }
    ' "$file"
}

# ============================================================
# 收集候选: CRASH = VERIFIED_CRASH + ASan/UBSan 字符串
#           BEHAVIOR = VERIFIED_BEHAVIOR + result 文件非空
# 格式: tag|nnn|CRASH  或  tag|nnn|BEHAVIOR
# ============================================================
CANDIDATES=()
if [ -d "$POC_BASE" ]; then
    while IFS= read -r status_file; do
        dir=$(dirname "$status_file")
        tag=$(basename "$dir")
        base=$(basename "$status_file")
        nnn="${base#vuln_}"; nnn="${nnn%_status.txt}"
        result_file="$dir/vuln_${nnn}_result.txt"
        [ -f "$result_file" ] || continue

        first_line=$(head -n1 "$status_file")

        if [ "$first_line" = "VERIFIED_CRASH" ]; then
            if grep -qE "AddressSanitizer|ERROR: LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$result_file"; then
                CANDIDATES+=("${tag}|${nnn}|CRASH")
            fi
        elif [ "$first_line" = "VERIFIED_BEHAVIOR" ]; then
            [ -s "$result_file" ] || continue
            CANDIDATES+=("${tag}|${nnn}|BEHAVIOR")
        fi
    done < <(find "$POC_BASE" -name 'vuln_*_status.txt' | sort)
fi

# 过滤掉已经写进 libtiff.md 的
PENDING=()
for c in "${CANDIDATES[@]+"${CANDIDATES[@]}"}"; do
    tag="${c%%|*}"
    rest="${c#*|}"; nnn="${rest%%|*}"
    if ! grep -q "^<!-- REPORT_SOURCE: ${tag}#${nnn} -->$" "$REPORT_MD" 2>/dev/null; then
        PENDING+=("$c")
    fi
done

if [ "$MODE" = "list" ]; then
    crash_cnt=$(printf '%s\n' "${CANDIDATES[@]+"${CANDIDATES[@]}"}" | grep -c '|CRASH$' || true)
    behav_cnt=$(printf '%s\n' "${CANDIDATES[@]+"${CANDIDATES[@]}"}" | grep -c '|BEHAVIOR$' || true)
    echo "=========================================="
    echo " Findings not yet in $(basename "$REPORT_MD"): ${#PENDING[@]}"
    echo " (VERIFIED_CRASH w/ ASan: $crash_cnt  |  VERIFIED_BEHAVIOR: $behav_cnt)"
    echo "=========================================="
    for c in "${PENDING[@]+"${PENDING[@]}"}"; do
        echo "  $c"
    done
    exit 0
fi

if [ "${#PENDING[@]}" -eq 0 ]; then
    echo "No new verified findings to report. Nothing to do."
    exit 0
fi

echo "=========================================="
echo " libtiff Report Generation"
echo " src/ audited: $AUDITED / $TOTAL_SRC"
echo " New verified findings to write up: ${#PENDING[@]}"
echo " Drafts: $DRAFTS_DIR/   Target: $REPORT_MD"
echo "=========================================="

REPORT_PROMPT_TEMPLATE='你是一名安全研究员，正在把一份已经验证过的 libtiff/tiffsplit 内存安全漏洞整理成可以直接提交的漏洞报告条目。

请依次 Read 以下材料以获取完整信息:
1. 漏洞描述(已从审计报告中截取的原始 VULN 块): __VULN_BLOCK_FILE__
2. PoC 运行输出（漏洞成立的证据，含 ASAN/UBSAN 报错）: __RESULT_FILE__
3. PoC 状态判定: __STATUS_FILE__
4. PoC 说明: __NOTES_FILE__ (如果不存在就跳过)
5. 先用 Glob 列出 __POC_DIR__/ 下的全部文件，再 Read 其中的 _gen.py / _run.sh，搞清楚复现步骤。

你的任务：只写一个文件 __DRAFT_FILE__，内容严格按下面模板格式，不要多写任何内容。

==================== 硬性格式要求 ====================
输出必须严格按照以下三节结构，标题占位符写成 "## Bug0: <简短英文标题>"（"Bug0" 三个字符原样保留，外部脚本会替换编号）：

## Bug0: <简短英文标题>

### Summary

<两三句话：哪个函数/文件、什么边界条件没被校验、导致什么安全后果（内存破坏）。
英文书写，不要超过 4 句话。不要用破折号连接从句，不要用分号连接从句。>

### PoC

<一句话说明复现方式：构造恶意 TIFF 文件，通过 tiffsplit 命令处理该文件触发漏洞。>

<给完整可独立运行的 Python 脚本（用 ```python 包裹），使用 struct 模块构造恶意 TIFF 字节序列。
路径用简单名字（poc_input.tif），不要硬编码 /data/ylwang/ 绝对路径。>

<给 shell 运行步骤代码块（用 ```bash 包裹），包含：生成恶意文件、用 ASAN 构建的 tiffsplit 运行。示例：
python3 gen.py  # generates poc_input.tif
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/bin/tiffsplit poc_input.tif /tmp/out_ || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done>

### Result

<两三句话描述实际观察到的结果：ASAN/UBSAN 报错（只截取关键几行内联在此，不用单独代码块）。
不要出现审计内部路径（libtiff/poc/、vuln_NNN 等内部名）。语言：英文，简洁。>

=====================================================

完成后确认 __DRAFT_FILE__ 已写入且只包含上述结构，不要输出其它内容。

工具白名单: Read, Write, Glob。'

BEHAVIOR_PROMPT_TEMPLATE='你是一名安全研究员，正在把一份已经验证过的 libtiff/tiffsplit 内存安全异常行为整理成漏洞报告条目。

请依次 Read 以下材料：
1. 漏洞描述(VULN 块): __VULN_BLOCK_FILE__
2. 行为验证输出: __RESULT_FILE__
3. 状态判定: __STATUS_FILE__
4. PoC 说明: __NOTES_FILE__ (不存在就跳过)
5. 用 Glob 列出 __POC_DIR__/ 下全部文件，再 Read 其中的 _gen.py / _run.sh，搞清楚复现步骤。

=====================================================
筛选规则（必须严格执行，先判断再写文件）：

如果满足以下**任意一条**，只写 __DRAFT_FILE__ 第一行为 "SKIP"，其余内容一律不写：
- 漏洞没有实际危害（无内存破坏、无 DoS、无信息泄露）
- 行为异常但无安全影响
- PoC 需要特殊系统权限才能触发

如果**不满足**上述条件，则写完整报告条目（格式见下方）。
=====================================================

==================== 硬性格式要求 ====================
输出必须严格按照以下三节结构，标题写成 "## Bug0: <简短英文标题>"（Bug0 原样保留）：

## Bug0: <简短英文标题>

### Summary

<两三句话：哪个函数/文件、什么边界条件缺失、导致什么安全后果（信息泄露、DoS、内存损坏等）。
英文书写，不超过 4 句话。>

### PoC

<一句话说明复现方式：构造恶意 TIFF 文件，通过 tiffsplit 命令处理该文件触发漏洞。>

<给完整可独立运行的 Python 脚本（用 ```python 包裹），使用 struct 模块构造恶意 TIFF 字节序列。
路径用简单名字（poc_input.tif），不要硬编码绝对路径。>

<给 shell 运行步骤代码块（用 ```bash 包裹）。>

### Result

<描述实际观察到的行为：ASAN/UBSAN 输出或异常行为证据（从 result 文件里截取关键几行内联）。
不要出现 libtiff/poc/ 或 vuln_NNN 等内部路径。英文，简洁。>

=====================================================

完成后确认 __DRAFT_FILE__ 已写入，不要输出其他内容。

工具白名单: Read, Write, Glob。'

# ============================================================
# 并行派发 claude 生成草稿
# ============================================================
PIDS=()
reap() {
    local alive=() pid
    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
        kill -0 "$pid" 2>/dev/null && alive+=("$pid")
    done
    PIDS=("${alive[@]+"${alive[@]}"}")
}
throttle() {
    while :; do
        reap
        [ "${#PIDS[@]}" -lt "$REPORT_PARALLEL" ] && break
        sleep 2
    done
}
cleanup() {
    local pid
    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
        kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

for c in "${PENDING[@]}"; do
    tag="${c%%|*}"
    rest="${c#*|}"; nnn="${rest%%|*}"; kind="${rest##*|}"
    poc_dir="$POC_BASE/$tag"
    vuln_block_file="$DRAFTS_DIR/${tag}__${nnn}.vuln_block.txt"
    draft_file="$DRAFTS_DIR/${tag}__${nnn}.md"

    extract_vuln_block "$OUTDIR/${tag}.md" "$nnn" > "$vuln_block_file"
    if [ ! -s "$vuln_block_file" ]; then
        echo "WARNING: could not extract VULN block #$nnn from ${tag}.md, skipping" | tee -a "$LOGFILE"
        continue
    fi

    # Dedup: skip if same function+CWE already in report
    _dedup_func=$(grep -oE '\*\*函数\*\*: [^()]+' "$vuln_block_file" 2>/dev/null | head -1 | sed 's/.*: //' | tr -d ' ')
    _dedup_cwe=$(grep -oE 'CWE-[0-9]+' "$vuln_block_file" 2>/dev/null | head -1)
    _dedup_key="${_dedup_func}::${_dedup_cwe}"
    if [ -n "$_dedup_func" ] && [ -n "$_dedup_cwe" ] && grep -qF "<!-- DEDUP: ${_dedup_key} -->" "$REPORT_MD" 2>/dev/null; then
        echo "[$(date '+%F %T')] DEDUP-SKIP ${tag}#${nnn} (key=$_dedup_key)" >> "$LOGFILE"
        echo "  [DEDUP] skipped ${tag}#${nnn} (same func+CWE: $_dedup_key)"
        continue
    fi
    cur_dedup_key="$_dedup_key"

    if [ "$kind" = "BEHAVIOR" ]; then
        tmpl="$BEHAVIOR_PROMPT_TEMPLATE"
    else
        tmpl="$REPORT_PROMPT_TEMPLATE"
    fi

    prompt="${tmpl//__VULN_BLOCK_FILE__/$vuln_block_file}"
    prompt="${prompt//__RESULT_FILE__/$poc_dir/vuln_${nnn}_result.txt}"
    prompt="${prompt//__STATUS_FILE__/$poc_dir/vuln_${nnn}_status.txt}"
    prompt="${prompt//__NOTES_FILE__/$poc_dir/vuln_${nnn}_notes.md}"
    prompt="${prompt//__POC_DIR__/$poc_dir}"
    prompt="${prompt//__DRAFT_FILE__/$draft_file}"

    throttle
    echo "-> drafting report for $tag #$nnn [$kind]"
    # 每个子进程完成后立即加锁写入 libtiff.md（动态落盘）
    (
        local_tag="$tag" local_nnn="$nnn" local_kind="$kind"
        local_draft="$draft_file" local_lock="$DRAFTS_DIR/.report.lock"
        rm -f "$local_draft"
        if claude -p "$prompt" \
            --model claude-sonnet-4-6 \
            --dangerously-skip-permissions \
            --allowedTools "Read,Write,Glob" \
            > "$DRAFTS_DIR/${local_tag}__${local_nnn}.session.log" 2>&1; then
            if [ -s "$local_draft" ] && grep -q "^## Bug0:" "$local_draft"; then
                # 获取排他锁后追加到 libtiff.md
                (
                    flock -x 9
                    if grep -q "^<!-- REPORT_SOURCE: ${local_tag}#${local_nnn} -->$" "$REPORT_MD" 2>/dev/null; then
                        echo "[$(date '+%F %T')] SKIP_DUP $local_tag#$local_nnn" >> "$LOGFILE"
                    else
                        next_n=$(( $(grep -oE '^## Bug[0-9]+:' "$REPORT_MD" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1 || echo 0) + 1 ))
                        {
                            echo ""
                            sed "s/^## Bug0:/## Bug${next_n}:/" "$local_draft"
                            echo ""
                            echo "<!-- REPORT_SOURCE: ${local_tag}#${local_nnn} -->"
                            [ -n "${cur_dedup_key:-}" ] && echo "<!-- DEDUP: ${cur_dedup_key} -->"
                        } >> "$REPORT_MD"
                        echo "  + Bug${next_n} <- ${local_tag}#${local_nnn} [$local_kind]"
                        echo "[$(date '+%F %T')] WRITTEN Bug${next_n} <- ${local_tag}#${local_nnn} [$local_kind]" >> "$LOGFILE"
                    fi
                ) 9>"$local_lock"
            elif [ -s "$local_draft" ] && [ "$(head -n1 "$local_draft")" = "SKIP" ]; then
                echo "[$(date '+%F %T')] DRAFT SKIP $local_tag#$local_nnn (no-impact)" >> "$LOGFILE"
                rm -f "$local_draft"
            else
                echo "[$(date '+%F %T')] DRAFT MALFORMED $local_tag#$local_nnn" >> "$LOGFILE"
                rm -f "$local_draft"
            fi
        else
            echo "[$(date '+%F %T')] DRAFT ERR $local_tag#$local_nnn: claude exit $?" >> "$LOGFILE"
        fi
    ) &
    PIDS+=($!)
done

wait
trap - EXIT INT TERM

written=$(grep -c "^\[.*\] WRITTEN " "$LOGFILE" 2>/dev/null || echo 0)
skip=$(grep -c "^\[.*\] DRAFT SKIP " "$LOGFILE" 2>/dev/null || echo 0)
echo ""
echo "=========================================="
echo " Report Generation Complete"
echo " Written:  $written"
echo " Skipped:  $skip (no-impact/malformed)"
echo " Report:   $REPORT_MD"
echo "=========================================="
