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

SOURCE_DIR="/data/ylwang/non-textfuzz/target/jasper"
OUTDIR="/data/ylwang/non-textfuzz/target/_audit_result/jasper"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/jasper"
DRAFTS_DIR="$OUTDIR/report-drafts"
LOGFILE="$OUTDIR/report.log"
REPORT_DIR="/data/ylwang/non-textfuzz/target/report"
REPORT_MD="$REPORT_DIR/jasper.md"
REPORT_PARALLEL="${REPORT_PARALLEL:-4}"

mkdir -p "$DRAFTS_DIR" "$REPORT_DIR"
[ -f "$REPORT_MD" ] || echo "# jasper (imginfo) Vulnerabilities" > "$REPORT_MD"

MODE="run"
FORCE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)  FORCE=1;       shift ;;
        --list)   MODE="list";   shift ;;
        --stats)  MODE="stats";  shift ;;
        -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

tag_for() {
    local f="$1" name dir
    name=$(basename "$f"); name="${name//./_}"
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
    crash_total=0; behav_total=0
    if [ -d "$POC_BASE" ]; then
        crash_total=$({ grep -rl "^VERIFIED_CRASH" "$POC_BASE"/*/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
        behav_total=$({ grep -rl "^VERIFIED_BEHAVIOR" "$POC_BASE"/*/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
    fi
    echo "=========================================="
    echo " jasper Report Statistics"
    echo " src files audited:            $AUDITED / $TOTAL_SRC"
    echo " PoC status=VERIFIED_CRASH:    $crash_total"
    echo " PoC status=VERIFIED_BEHAVIOR: $behav_total"
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

extract_vuln_block() {
    local file="$1" n="$2"
    awk -v n="$n" '
        /^## VULN:/ { c++; if (c == n) { p = 1; print; next } else { p = 0 } ; next }
        /^<!-- AUDIT_PROMPT_VERSION:/ { p = 0 }
        p { print }
    ' "$file"
}

REPORT_PROMPT_TEMPLATE='You are a security researcher writing a concise vulnerability report entry for a confirmed jasper (imginfo) memory safety bug.

Read the following materials in order:
1. Vulnerability description (VULN block extracted from the audit report): __VULN_BLOCK_FILE__
2. PoC run output (evidence the bug is real, contains ASAN or UBSAN output): __RESULT_FILE__
3. PoC status verdict: __STATUS_FILE__
4. PoC notes: __NOTES_FILE__ (skip if the file does not exist)
5. Run Glob to list all files under __POC_DIR__/ then Read the _gen.py and _run.sh files to understand the exact reproduction steps and copy the actual file-generation logic.

Your task: write exactly one file __DRAFT_FILE__ following the strict format below. Write nothing else.

==================== STRICT FORMAT ====================
Use "## Bug0: <short English title>" as the first line (keep "Bug0" literally; an external script replaces the number).

## Bug0: <short English title>

<One sentence in English: which function and file, what boundary check is absent, and what memory safety consequence results. Do not use a dash to join clauses. Do not use a semicolon to join clauses.>

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
<Complete self-contained Python script. Copy the actual generation logic from the existing _gen.py file. Use the struct module to build the malicious JP2 byte sequence. Include every byte of the malicious file construction inline so the script runs with no external dependencies. Use a simple filename such as poc_input.jp2. Do not hardcode absolute paths containing /data/ylwang/.>
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** <Copy the key lines from the ASAN or UBSAN output in the result file that confirm the crash: the error type line (e.g. "heap-buffer-overflow on address ..."), the READ or WRITE size line, and the first two frames of the stack trace. Inline them here as plain text with no extra code block. Do not include internal paths like /data/ylwang/ or vuln_NNN. Do not use a dash to join clauses. Do not use a semicolon to join clauses.>

### Impact

<Two or three sentences in English describing what an attacker can achieve (heap corruption, out-of-bounds read or write, use-after-free, information disclosure, denial of service, or arbitrary code execution), which attack surface is exposed (any imginfo invocation on an untrusted JP2 file), and any notable constraints. Do not use a dash to join clauses. Do not use a semicolon to join clauses.>

=====================================================

After writing the file confirm __DRAFT_FILE__ is written and contains only the above structure. Do not output anything else.

Allowed tools: Read, Write, Glob.'

BEHAVIOR_PROMPT_TEMPLATE='You are a security researcher writing a vulnerability report entry for a confirmed jasper (imginfo) behavioral anomaly.

Read the following materials in order:
1. Vulnerability description (VULN block): __VULN_BLOCK_FILE__
2. Behavioral verification output: __RESULT_FILE__
3. Status verdict: __STATUS_FILE__
4. PoC notes: __NOTES_FILE__ (skip if the file does not exist)
5. Run Glob to list all files under __POC_DIR__/ then Read the _gen.py and _run.sh files to understand the reproduction steps and copy the actual file-generation logic.

=====================================================
FILTER RULE (evaluate first before writing anything):

If any of the following conditions is met write only "SKIP" as the first and only line of __DRAFT_FILE__ and nothing else:
- The finding has no actual security impact (no memory corruption, no DoS, no information disclosure)
- The behavior is anomalous but carries no security consequence
- The PoC requires special system privileges to trigger

If none of those conditions apply write the full report entry using the format below.
=====================================================

==================== STRICT FORMAT ====================
Use "## Bug0: <short English title>" as the first line (keep "Bug0" literally).

## Bug0: <short English title>

<One sentence in English: which function and file, what boundary check is absent, and what security consequence results. Do not use a dash to join clauses. Do not use a semicolon to join clauses.>

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
<Complete self-contained Python script. Copy the actual generation logic from the existing _gen.py file. Use the struct module to build the malicious byte sequence. Include every byte of the malicious file construction inline. Use a simple filename such as poc_input.jp2. Do not hardcode absolute paths containing /data/ylwang/.>
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** <Copy the key lines from the ASAN or UBSAN output in the result file. Inline them as plain text with no extra code block. Do not include internal paths like /data/ylwang/ or vuln_NNN. Do not use a dash to join clauses. Do not use a semicolon to join clauses.>

### Impact

<Two or three sentences in English describing what an attacker can achieve, which attack surface is exposed, and any notable constraints. Do not use a dash to join clauses. Do not use a semicolon to join clauses.>

=====================================================

After writing the file confirm __DRAFT_FILE__ is written. Do not output anything else.

Allowed tools: Read, Write, Glob.'

CANDIDATES=()
if [ -d "$POC_BASE" ]; then
    while IFS= read -r status_file; do
        dir=$(dirname "$status_file")
        tag=$(basename "$dir")
        [[ "$tag" == ._* ]] && continue
        base=$(basename "$status_file")
        nnn="${base#vuln_}"; nnn="${nnn%_status.txt}"
        result_file="$dir/vuln_${nnn}_result.txt"
        [ -f "$result_file" ] || continue
        first_line=$(head -n1 "$status_file")
        if [ "$first_line" = "VERIFIED_CRASH" ]; then
            if grep -qE "AddressSanitizer|ERROR: LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$result_file"; then
                if ! grep -qE "requested allocation size|allocator is out of memory|exceeds maximum supported size|allocation of [0-9]+ bytes exceeds" "$result_file"; then
                    CANDIDATES+=("${tag}|${nnn}|CRASH")
                fi
            fi
        elif [ "$first_line" = "VERIFIED_BEHAVIOR" ]; then
            [ -s "$result_file" ] || continue
            CANDIDATES+=("${tag}|${nnn}|BEHAVIOR")
        fi
    done < <(find "$POC_BASE" -name 'vuln_*_status.txt' | sort)
fi

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
    for c in "${PENDING[@]+"${PENDING[@]}"}"; do echo "  $c"; done
    exit 0
fi

if [ "${#PENDING[@]}" -eq 0 ]; then
    echo "No new verified findings to report. Nothing to do."
    exit 0
fi

echo "=========================================="
echo " jasper Report Generation"
echo " src/ audited: $AUDITED / $TOTAL_SRC"
echo " New verified findings to write up: ${#PENDING[@]}"
echo " Drafts: $DRAFTS_DIR/   Target: $REPORT_MD"
echo "=========================================="

PIDS=()
reap() { local alive=() pid; for pid in "${PIDS[@]+"${PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && alive+=("$pid"); done; PIDS=("${alive[@]+"${alive[@]}"}"); }
throttle() { while :; do reap; [ "${#PIDS[@]}" -lt "$REPORT_PARALLEL" ] && break; sleep 2; done; }
cleanup() { local pid; for pid in "${PIDS[@]+"${PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null || true; done; }
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

    _dedup_func=$(grep -oP '(?<=\*\*函数\*\*: |\*\*function\*\*: )[^()]+' "$vuln_block_file" 2>/dev/null | head -1 | tr -d ' ' || true)
    _dedup_cwe=$(grep -oE 'CWE-[0-9]+' "$vuln_block_file" 2>/dev/null | head -1) || true
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
                (
                    flock -x 9
                    if grep -q "^<!-- REPORT_SOURCE: ${local_tag}#${local_nnn} -->$" "$REPORT_MD" 2>/dev/null; then
                        echo "[$(date '+%F %T')] SKIP_DUP $local_tag#$local_nnn" >> "$LOGFILE"
                    elif [ -n "${cur_dedup_key:-}" ] && grep -qF "<!-- DEDUP: ${cur_dedup_key} -->" "$REPORT_MD" 2>/dev/null; then
                        echo "[$(date '+%F %T')] DEDUP-SKIP $local_tag#$local_nnn (parallel, key=${cur_dedup_key})" >> "$LOGFILE"
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
