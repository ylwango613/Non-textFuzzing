#!/bin/bash
# mp3rgain vulnerability report generation script
# Picks VERIFIED_CRASH PoCs from the poc/ directory and asks Claude to
# write each one up as a Bug entry appended to report/mp3rgain.md.
#
# Usage:
#   ./mp3rgain_report.sh                 # check audit completeness first, then generate
#   ./mp3rgain_report.sh --force         # skip completeness check, generate from whatever is confirmed
#   ./mp3rgain_report.sh --list          # list verified findings not yet written to mp3rgain.md
#   ./mp3rgain_report.sh --stats         # statistics: audited files, confirmed vulns, written entries

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

SOURCE_DIR="/data/ylwang/non-textfuzz/target/mp3rgain"
OUTDIR="$SOURCE_DIR/mp3rgain"
POC_BASE="$OUTDIR/poc"
DRAFTS_DIR="$OUTDIR/report-drafts"
LOGFILE="$OUTDIR/report.log"
REPORT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/report"
REPORT_MD="$REPORT_DIR/mp3rgain.md"
REPORT_PARALLEL="${REPORT_PARALLEL:-4}"

mkdir -p "$DRAFTS_DIR"
mkdir -p "$REPORT_DIR"
[ -f "$REPORT_MD" ] || touch "$REPORT_MD"

# ============================================================
# Option parsing
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
# tag mapping consistent with mp3rgain_audit.sh
# ============================================================
tag_for() {
    local f="$1" name dir
    name=$(basename "$f")
    name="${name//./_}"
    dir=$(dirname "$f" | tr '/' '_')
    echo "${dir}_${name}"
}

mapfile -t SRC_FILES < <(
    find "$SOURCE_DIR/src" \
        -name '*.rs' \
        | sed "s|^$SOURCE_DIR/||" | sort
)
TOTAL_SRC=${#SRC_FILES[@]}

# ============================================================
# Completeness check
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
    echo " mp3rgain Report Statistics"
    echo " src/ files audited:           $AUDITED / $TOTAL_SRC"
    echo " PoC status=VERIFIED_CRASH:    $crash_total"
    echo " PoC status=VERIFIED_BEHAVIOR: $behav_total"
    echo " Entries already in $(basename "$REPORT_MD"): $written"
    echo "=========================================="
    exit 0
fi

if [ "$MODE" = "run" ] && [ "$FORCE" != "1" ] && [ "$MISSING_AUDIT" -gt 0 ]; then
    echo "src/ audit not yet complete: $AUDITED / $TOTAL_SRC files audited, $MISSING_AUDIT pending."
    echo "Run ./mp3rgain_audit.sh (or ./mp3rgain_audit.sh --list-pending) until it finishes, then rerun ./mp3rgain_report.sh."
    echo "(Use --force to generate a report from whatever has been confirmed so far.)"
    exit 1
fi

# ============================================================
# Extract the Nth "## VULN:" block from an audit result file
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
# Collect candidates: CRASH = VERIFIED_CRASH + ASan/UBSan string
#                     BEHAVIOR = VERIFIED_BEHAVIOR + non-empty result
# Format: tag|nnn|CRASH  or  tag|nnn|BEHAVIOR
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
            if grep -qE "AddressSanitizer|ERROR: LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:|attempt to|index out of bounds" "$result_file"; then
                CANDIDATES+=("${tag}|${nnn}|CRASH")
            fi
        elif [ "$first_line" = "VERIFIED_BEHAVIOR" ]; then
            [ -s "$result_file" ] || continue
            CANDIDATES+=("${tag}|${nnn}|BEHAVIOR")
        fi
    done < <(find "$POC_BASE" -name 'vuln_*_status.txt' | sort)
fi

# Filter out entries already written to mp3rgain.md
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
echo " mp3rgain Report Generation"
echo " src/ audited: $AUDITED / $TOTAL_SRC"
echo " New verified findings to write up: ${#PENDING[@]}"
echo " Drafts: $DRAFTS_DIR/   Target: $REPORT_MD"
echo "=========================================="

REPORT_PROMPT_TEMPLATE='You are a security researcher writing up a confirmed mp3rgain vulnerability as a bug report entry.

Please Read the following materials for full context:
1. Vulnerability description (raw VULN block from the audit report): __VULN_BLOCK_FILE__
2. PoC run output or diff result (evidence the vulnerability exists): __RESULT_FILE__
3. PoC status verdict: __STATUS_FILE__
4. PoC notes: __NOTES_FILE__ (skip if not found)
5. Use Glob to list all files under __POC_DIR__/, then Read the .py / _run.sh files to understand the reproduction steps.

Your task: write exactly one file __DRAFT_FILE__ with the content strictly following the template below. Do not write anything else.

==================== Hard format requirements ====================
Output must follow this exact three-section structure. The title placeholder must be written as "## Bug0: <short English title>" (keep "Bug0" literally — the script replaces the number):

## Bug0: <short English title>

### Summary

<Two to three sentences: which function/file, what boundary condition was unchecked, what the security consequence is (memory corruption or safety invariant broken). Write in English. Do not exceed 4 sentences. No em-dashes joining clauses; no semicolons joining clauses.>

### PoC

<One sentence describing the reproduction method: crafted MP3 file fed to the mp3rgain binary.>

<Provide the complete Python script (```python block) that generates the crafted MP3 file.
Use only stdlib (struct, bytes). Use simple filenames (poc.mp3) — do not hardcode /data/ylwang/ paths.
Reference the binary as ./build_test/mp3rgain relative to the project root.>

<Provide a shell steps block (```bash) showing:
  python3 gen.py
  ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
    ./build_test/mp3rgain poc.mp3 || true
>

### Result

<Two to three sentences describing the actual observed result: ASAN/UBSAN error (inline the key line(s) here, no separate code block) or a Rust panic message. Do not expose internal paths like /data/ylwang/ or audit-results/ or vuln_NNN names. Write in English, concise.>

=================================================================

After writing, confirm __DRAFT_FILE__ exists and contains only the above structure. Do not output anything else.

Tool whitelist: Read, Write, Glob.'

BEHAVIOR_PROMPT_TEMPLATE='You are a security researcher writing up a confirmed mp3rgain behavioral anomaly as a bug report entry.

Please Read the following materials:
1. Vulnerability description (VULN block): __VULN_BLOCK_FILE__
2. Behavioral verification output: __RESULT_FILE__
3. Status verdict: __STATUS_FILE__
4. PoC notes: __NOTES_FILE__ (skip if not found)
5. Use Glob to list all files under __POC_DIR__/, then Read the .py / _run.sh files.

=================================================================
Filtering rule (enforce strictly — check first, then write):

If ANY of the following apply, write only "SKIP" as the first line of __DRAFT_FILE__ and nothing else:
- The vulnerability has no real security impact (no information leak, no privilege escalation, no DoS, no data corruption).
- Triggering it requires a non-crafted-file attack surface not available remotely.
- The anomaly is a benign edge-case with no downstream security consequence.

If NONE of the above apply, write the full report entry (format below).
=================================================================

==================== Hard format requirements ====================
## Bug0: <short English title>

### Summary

<Two to three sentences: function/file, what check is missing, what the security consequence is. English, max 4 sentences.>

### PoC

<One sentence: reproduction method.>

<Python script (```python) or shell block (```bash) to reproduce. Simple filenames; no hardcoded /data/ylwang/ paths.>

### Result

<Observed behavior vs expected behavior; key evidence inlined (no separate code block). No internal paths. English, concise.>

=================================================================

After writing, confirm __DRAFT_FILE__ exists. Do not output anything else.

Tool whitelist: Read, Write, Glob.'

# ============================================================
# Parallel Claude draft generation
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

    if [ "$kind" = "BEHAVIOR" ]; then
        tmpl="$BEHAVIOR_PROMPT_TEMPLATE"
    else
        tmpl="$REPORT_PROMPT_TEMPLATE"
    fi

    prompt="${tmpl//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__VULN_BLOCK_FILE__/$vuln_block_file}"
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
                    else
                        next_n=$(( $(grep -oE '^## Bug[0-9]+:' "$REPORT_MD" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1 || echo 0) + 1 ))
                        {
                            echo ""
                            sed "s/^## Bug0:/## Bug${next_n}:/" "$local_draft"
                            echo ""
                            echo "<!-- REPORT_SOURCE: ${local_tag}#${local_nnn} -->"
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
