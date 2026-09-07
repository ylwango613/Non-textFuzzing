#!/bin/bash
# jasper (imginfo) 漏洞报告生成脚本
#
# 用法:
#   ./jasper_report.sh          # 默认: 检查审计完整性，生成报告
#   ./jasper_report.sh --force  # 跳过完整性检查，直接生成
#   ./jasper_report.sh --list   # 只列出待写入漏洞，不调用 claude
#   ./jasper_report.sh --stats  # 统计完成度

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="/data/ylwang/non-textfuzz/target/jasper"
OUTDIR="/data/ylwang/non-textfuzz/target/_audit_result/jasper"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/jasper"
DRAFTS_DIR="$OUTDIR/report-drafts"
LOGFILE="$OUTDIR/report.log"
REPORT_DIR="/data/ylwang/non-textfuzz/target/report"
REPORT_MD="$REPORT_DIR/jasper.md"
REPORT_PARALLEL="${REPORT_PARALLEL:-4}"

mkdir -p "$DRAFTS_DIR"
mkdir -p "$REPORT_DIR"
[ -f "$REPORT_MD" ] || echo "# jasper (imginfo) Vulnerabilities" > "$REPORT_MD"

MODE="run"
FORCE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)  FORCE=1;        shift ;;
        --list)   MODE="list";    shift ;;
        --stats)  MODE="stats";   shift ;;
        -h|--help)
            sed -n '2,8p' "$0"
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

tag_for() {
    local f="$1" name dir
    name=$(basename "$f")
    name="${name//./_}"
    dir=$(dirname "$f" | tr '/' '_')
    [ "$dir" = "." ] && dir=""
    [ -n "$dir" ] && echo "${dir}_${name}" || echo "$name"
}

mapfile -t SRC_FILES < <(
    for root in "$SOURCE_DIR/src/libjasper" "$SOURCE_DIR/src/appl"; do
        find "$root" -name '*.c' | sed "s|^$SOURCE_DIR/||"
    done | sort
)
TOTAL_SRC=${#SRC_FILES[@]}

MISSING_AUDIT=0
for f in "${SRC_FILES[@]}"; do
    tag=$(tag_for "$f")
    [ -f "$OUTDIR/${tag}.md" ] || MISSING_AUDIT=$((MISSING_AUDIT + 1))
done
AUDITED=$((TOTAL_SRC - MISSING_AUDIT))

if [ "$MODE" = "stats" ]; then
    written=$(grep -c "^<!-- REPORT_SOURCE:" "$REPORT_MD" 2>/dev/null || echo 0)
    crash_total=0
    if [ -d "$POC_BASE" ]; then
        crash_total=$({ grep -rl "^VERIFIED_CRASH" "$POC_BASE"/*/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
    fi
    echo "=========================================="
    echo " jasper Report Statistics"
    echo " src files audited:            $AUDITED / $TOTAL_SRC"
    echo " PoC status=VERIFIED_CRASH:    $crash_total"
    echo " Entries already in $(basename "$REPORT_MD"): $written"
    echo "=========================================="
    exit 0
fi

if [ "$MODE" = "run" ] && [ "$FORCE" != "1" ] && [ "$MISSING_AUDIT" -gt 0 ]; then
    echo "Audit not yet complete: $AUDITED / $TOTAL_SRC files audited, $MISSING_AUDIT pending."
    echo "Run ./jasper_audit.sh then rerun ./jasper_report.sh."
    echo "(Use --force to generate from confirmed findings so far.)"
    exit 1
fi

# Extract Nth VULN block from an audit result file
extract_vuln_block() {
    local result_file="$1" n="$2"
    awk -v n="$n" '
        /^## VULN:/ { block++; if(block==n) printing=1; else printing=0 }
        printing { print }
        printing && /^<!-- / { printing=0 }
    ' "$result_file" | grep -v "^<!-- "
}

REPORT_PIDS=()

write_one_entry() {
    local result="$1" tag="$2" vuln_idx="$3" poc_dir="$4"
    local anchor="${tag}_v${vuln_idx}"
    if grep -q "^<!-- REPORT_SOURCE: ${anchor} -->$" "$REPORT_MD" 2>/dev/null; then
        return 0
    fi

    local vuln_block
    vuln_block=$(extract_vuln_block "$result" "$vuln_idx")
    [ -z "$vuln_block" ] && return 0

    local poc_status="UNVERIFIED"
    local status_file="$poc_dir/vuln_$(printf '%03d' "$vuln_idx")_status.txt"
    [ -f "$status_file" ] && poc_status=$(head -1 "$status_file")
    [ "$poc_status" = "VERIFIED_CRASH" ] || [ "$poc_status" = "VERIFIED_BEHAVIOR" ] || return 0
    # Dedup: skip if same function+CWE already reported
    local func_name cwe_id dedup_key
    func_name=$(printf '%s\n' "$vuln_block" | grep -oE '\*\*函数\*\*: [^()]+' | head -1 | sed 's/.*: //' | tr -d ' ')
    cwe_id=$(printf '%s\n' "$vuln_block" | grep -oE 'CWE-[0-9]+' | head -1)
    dedup_key="${func_name}::${cwe_id}"
    if [ -n "$func_name" ] && [ -n "$cwe_id" ] && grep -qF "<!-- DEDUP: ${dedup_key} -->" "$REPORT_MD" 2>/dev/null; then
        echo "[$(date '+%F %T')] DEDUP-SKIP $anchor (key=$dedup_key)" >> "$LOGFILE"
        return 0
    fi


    local draft_file="$DRAFTS_DIR/${anchor}.md"
    local prompt
    prompt="你是一名安全报告撰写员。下面是对 JasPer imginfo 的一个已确认漏洞的审计记录和 PoC 状态。

审计结果块：
${vuln_block}

PoC 状态：${poc_status}
PoC 目录：${poc_dir}
PoC 编号：$(printf '%03d' "$vuln_idx")

请用中英双语写一份简洁的漏洞条目，包含：
1. 漏洞标题（英文）
2. 严重程度 + CWE + CVSS
3. 漏洞描述（中文，2-3 句）
4. 触发方式（imginfo 命令行用法）
5. PoC 验证状态

输出为 Markdown，以 '### ' 开头漏洞标题。"

    claude -p "$prompt" \
        --model claude-sonnet-4-6 \
        --dangerously-skip-permissions \
        --allowedTools "Read,Bash" \
        > "$draft_file" 2>&1

    {
        echo ""
        echo "<!-- REPORT_SOURCE: ${anchor} -->"
        [ -n "$dedup_key" ] && echo "<!-- DEDUP: ${dedup_key} -->"
        cat "$draft_file"
    } >> "$REPORT_MD"
    echo "[$(date '+%F %T')] wrote $anchor" >> "$LOGFILE"
}

if [ "$MODE" = "list" ]; then
    echo "Confirmed vulnerabilities not yet in report:"
    for f in "${SRC_FILES[@]}"; do
        tag=$(tag_for "$f")
        result="$OUTDIR/${tag}.md"
        [ -f "$result" ] || continue
        grep -q "^## VULN:" "$result" 2>/dev/null || continue
        vuln_n=$(grep -c "^## VULN:" "$result")
        poc_dir="$POC_BASE/$tag"
        for i in $(seq 1 "$vuln_n"); do
            anchor="${tag}_v${i}"
            grep -q "^<!-- REPORT_SOURCE: ${anchor} -->$" "$REPORT_MD" 2>/dev/null && continue
            status_file="$poc_dir/vuln_$(printf '%03d' "$i")_status.txt"
            poc_status="UNVERIFIED"
            [ -f "$status_file" ] && poc_status=$(head -1 "$status_file")
            echo "  $f  vuln#$i  poc=$poc_status"
        done
    done
    exit 0
fi

echo "Generating jasper vulnerability report..."
for f in "${SRC_FILES[@]}"; do
    tag=$(tag_for "$f")
    result="$OUTDIR/${tag}.md"
    [ -f "$result" ] || continue
    grep -q "^## VULN:" "$result" 2>/dev/null || continue
    vuln_n=$(grep -c "^## VULN:" "$result")
    poc_dir="$POC_BASE/$tag"
    for i in $(seq 1 "$vuln_n"); do
        write_one_entry "$result" "$tag" "$i" "$poc_dir" &
        REPORT_PIDS+=($!)
        while [ "${#REPORT_PIDS[@]}" -ge "$REPORT_PARALLEL" ]; do
            wait "${REPORT_PIDS[0]}" 2>/dev/null || true
            REPORT_PIDS=("${REPORT_PIDS[@]:1}")
        done
    done
done

for pid in "${REPORT_PIDS[@]+"${REPORT_PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
done

written=$(grep -c "^<!-- REPORT_SOURCE:" "$REPORT_MD" 2>/dev/null || echo 0)
echo "=========================================="
echo " Report written: $REPORT_MD"
echo " Total entries:  $written"
echo "=========================================="
