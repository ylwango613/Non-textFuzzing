#!/bin/bash
# mp3rgain Full Security Audit Script (Rust source under src/)
#
# Usage:
#   ./mp3rgain_audit.sh                        # default resume mode (audit + PoC)
#   ./mp3rgain_audit.sh --restart              # clear results, start fresh
#   ./mp3rgain_audit.sh --restart-from 50      # restart from file #50
#   ./mp3rgain_audit.sh --list-pending         # list unaudited files
#   ./mp3rgain_audit.sh --stats                # statistics on existing results
#   ./mp3rgain_audit.sh --no-poc               # audit only, skip PoC generation
#   ./mp3rgain_audit.sh --poc-only             # only run PoC phase (skip audit)
#   ./mp3rgain_audit.sh --restart-poc          # clear existing PoCs, regenerate
#   ./mp3rgain_audit.sh src/main.rs            # audit a specific file

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

SOURCE_DIR="/data/ylwang/non-textfuzz/target/mp3rgain"
OUTDIR="$SOURCE_DIR/mp3rgain"
LOGFILE="$OUTDIR/audit.log"
mkdir -p "$OUTDIR"

PROMPT_VERSION="1"
VERSION_MARKER="AUDIT_PROMPT_VERSION"

# ============================================================
# Option parsing
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
# filename -> result path mapping
# ============================================================
tag_for() {
    local f="$1"
    local name dir
    name=$(basename "$f")
    name="${name//./_}"
    dir=$(dirname "$f" | tr '/' '_')
    echo "${dir}_${name}"
}

result_is_current() {
    local result="$1"
    [ -f "$result" ] || return 1
    grep -q "^<!-- ${VERSION_MARKER}: ${PROMPT_VERSION} -->$" "$result" 2>/dev/null
}

# ============================================================
# Build file list
# ============================================================
if [ $# -gt 0 ]; then
    FILES=("$@")
else
    SCAN_ROOT="$SOURCE_DIR/src"

    if [ ! -d "$SCAN_ROOT" ]; then
        echo "FATAL: scan root missing: $SCAN_ROOT" >&2
        exit 2
    fi
    if [ -z "$(find "$SCAN_ROOT" -name '*.rs' -print -quit)" ]; then
        echo "FATAL: scan root has no .rs files: $SCAN_ROOT" >&2
        exit 2
    fi

    mapfile -t FILES < <(
        find "$SCAN_ROOT" \
            -name '*.rs' \
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

# ============================================================
# --stats mode
# ============================================================
if [ "$MODE" = "stats" ]; then
    mkdir -p "$OUTDIR/poc"
    done_count=$(find "$OUTDIR" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' \n')
    vuln_files=$({ grep -rl --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | { grep -v '/poc/' || true; } | wc -l | tr -d ' \n')
    vuln_entries=$({ grep -rh --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_files=$(find "$OUTDIR/poc" -name '.done' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$OUTDIR/poc"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_total=$(find "$OUTDIR/poc" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    echo "=========================================="
    echo " mp3rgain Audit Statistics"
    echo " Total source files:      $TOTAL"
    echo " Files audited:           $done_count"
    echo " Files remaining:         $((TOTAL - done_count))"
    echo " Files with vulns:        $vuln_files"
    echo " Total vuln entries:      $vuln_entries"
    echo " Files with PoCs done:    $poc_files"
    echo " PoCs total / verified:   $poc_total / $poc_verified"
    echo "=========================================="
    exit 0
fi

# ============================================================
# --list-pending mode
# ============================================================
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
    echo " Pending files: ${#PENDING[@]} / $TOTAL  ($STALE stale prompt-v$PROMPT_VERSION need re-audit)"
    echo "=========================================="
    for f in "${PENDING[@]}"; do
        echo "  $f"
    done
    exit 0
fi

# ============================================================
# --restart / --restart-from
# ============================================================
if [ "$MODE" = "restart" ]; then
    echo "MODE: restart — clearing ALL previous results..."
    rm -f "$OUTDIR"/*.md
fi

if [ "$MODE" = "restart-from" ]; then
    echo "MODE: restart-from $RESTART_FROM — clearing results from file #$RESTART_FROM onwards..."
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
# Audit prompt template
# ============================================================
AUDIT_PROMPT_TEMPLATE='You are a top-tier Rust security auditor conducting an authorized security audit of mp3rgain, a Rust CLI tool that reads MP3 files to compute and adjust ReplayGain tags.

Please carefully read the file __SOURCE_DIR__/__FILE__ in its entirety.
Also use Grep/Glob/Read to examine related modules, trait impls, and callers for full context.

**Large files must be read in multiple passes — "clean after one scan" is a historic false-negative root cause.**
For larger files (>500 lines), split by function groups and dispatch parallel subagents (one message with N Agent calls, subagent_type=general-purpose), each deeply analyzing one function group; then consolidate all findings into `## VULN:` blocks in your final message.

**Cross-module interactions must be checked:**
- Bytes/slices produced by one module and consumed by another without re-validation.
- Unsafe blocks that trust length/pointer values computed in safe code upstream.

Project background:
- mp3rgain is a Rust CLI tool that analyzes/adjusts MP3 ReplayGain tags.
- It reads MP3 frame headers, ID3v1/v2 tags, and analyzes audio sample data for volume.
- Attack surface: crafted MP3 files passed to `mp3rgain <file.mp3>`.

**Focus on memory bugs ONLY (Rust-focused). Look for:**

1. **unsafe blocks**: Any `unsafe { }` section performing raw pointer arithmetic, slice indexing without bounds check, or FFI calls. Audit every pointer offset computation, length argument, and memory region accessed.
2. **Integer overflow in MP3 frame length**: MP3 frame size = 144 * bitrate / sample_rate + padding. If bitrate or sample_rate is crafted from the header to cause integer overflow, the resulting (small/zero/wrapped) frame size is used for slice indexing, causing OOB read/write.
3. **Panic as DoS**: index-out-of-bounds, integer overflow (in release mode Rust may wrap; wrapping that yields a wrong length used for allocation/slicing becomes memory corruption). Check every array/slice index derived from parsed MP3 data.
4. **slice::from_raw_parts with user-controlled length or pointer**: if frame header parsing yields an arbitrary length that is passed to an unsafe slice construction, the attacker controls the slice bounds.
5. **Incorrect ID3v2 syncsafe integer decoding**: ID3v2 tag size uses 7-bit-per-byte syncsafe encoding. If decoded incorrectly (treated as raw 32-bit big-endian), the computed size overflows or is wildly large, causing OOB read when seeking past the tag.
6. **Symphonia library (used internally)**: known parsing bugs in its MP3/AAC demuxer triggered by crafted frames (malformed Xing/VBRI headers, truncated frame data, invalid channel/bitrate combos).
7. **Iterator/slice boundary confusion**: a loop advancing a byte index by a frame-header-derived increment where that increment can be zero (infinite loop) or overflow-wrapped (OOB jump).

Do NOT report:
- Purely hypothetical issues with no external trigger in a crafted MP3 file.
- Panics reachable only in debug mode if release mode is provably safe.
- Pure resource-exhaustion DoS without a clear memory-corruption angle, unless amplification is extreme.

Actively use tools for context (do not skip):
1. grep -rn "unsafe" __SOURCE_DIR__/src/ to find all unsafe blocks.
2. grep -rn "from_raw_parts\|as_ptr\|offset\|wrapping_\|unchecked" __SOURCE_DIR__/src/ for raw pointer ops.
3. For every frame-length computation, trace where bitrate/sample_rate values come from.
4. grep -rn "id3\|symphonia\|Tag\|Frame\|Header" __SOURCE_DIR__/src/ for library usage.
5. For slice indexing with externally-derived indices, verify that bounds are checked before the index.

Only report high-confidence, externally triggerable vulnerabilities.
Evaluate each with CVSS v3.1 and a CWE number.
Severity reference: Critical(9.0-10.0) / High(7.0-8.9) / Medium(4.0-6.9) / Low(0.1-3.9).
If no externally triggerable vulnerability is found, output exactly: NO_VULN_FOUND

==================== Output Contract (strictly enforced) ====================
Your final reply will be saved as the audit report and parsed by `grep "^## VULN:"`.
1. Each vulnerability must be an independent block starting with `## VULN:` at the very beginning of a line (no leading characters).
2. Do NOT use tables, prose summaries, or bullet lists to enumerate findings. No preamble, no "I found N vulns", no "Final Summary".
3. If you used subagents, consolidate ALL their findings into complete `## VULN:` blocks in your final message. Never paste a subagent table or one-liner.
4. If no externally triggerable vulnerability is found, output exactly one line: NO_VULN_FOUND
=============================================================================

Output format (one block per vulnerability):
## VULN: <short English title>
- **漏洞类别**: memory-safety
- **函数**: xxx()
- **行号**: xxx-xxx
- **CWE**: CWE-XXX (name)
- **CVSS v3.1**: X.X (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **严重程度**: Critical/High/Medium/Low
- **攻击向量**: crafted MP3 file
- **外部触发路径**: <full call chain from binary entry point to the vulnerable point>
- **描述**: xxx (memory corruption mechanism or safety invariant broken)
- **触发条件**: xxx (what the attacker must craft in the MP3 file)
- **安全影响**: xxx (worst-case: crash / OOB read / OOB write / potential RCE)'

# ============================================================
# PoC generation settings
# ============================================================
BIN="$SOURCE_DIR/build_test/mp3rgain"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/mp3rgain"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=1
if [ "$RUN_POC" = "0" ]; then
    POC_ENABLED=0
elif [ ! -x "$BIN" ]; then
    echo "WARNING: $BIN not executable — PoC phase will be skipped."
    echo "         Build mp3rgain with ASAN first:"
    echo "           cd $SOURCE_DIR && cargo build --release"
    echo "           (or build with RUSTFLAGS='-Z sanitizer=address' on nightly)"
    echo "         Then rerun with --poc-only."
    POC_ENABLED=0
fi

if [ "$POC_ENABLED" = "1" ]; then
    mkdir -p "$POC_BASE"
    if [ "$RESTART_POC" = "1" ]; then
        echo "MODE: --restart-poc — clearing all existing PoCs..."
        rm -rf "$POC_BASE"
        mkdir -p "$POC_BASE"
    fi
fi

POC_PROMPT_TEMPLATE='You are a security researcher. Based on the vulnerability audit report, generate a working PoC for each reported mp3rgain vulnerability.

==================== Hard Rules ====================
Binary under test: __SOURCE_DIR__/build_test/mp3rgain (expected to be built with AddressSanitizer or UBSAN).
Attack surface: crafted MP3 files passed directly to the binary on the command line.

1. Generate a minimal crafted MP3 file (using Python struct/bytes) that exercises the vulnerable code path.
2. Run the binary:
     ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
       __SOURCE_DIR__/build_test/mp3rgain vuln_NNN.mp3 \
       > vuln_NNN_result.txt 2>&1 || true
3. Check for AddressSanitizer output, "runtime error" (UBSAN), or Rust "attempt to" / "index out of bounds" / "overflow" panic messages.
4. Do NOT write a custom linker harness or link internal library symbols. Only invoke the binary.
====================================================

Vulnerability report:  __RESULT_FILE__
Source file:           __SOURCE_DIR__/__SOURCE_FILE__
PoC directory:         __POC_DIR__
Binary:                __SOURCE_DIR__/build_test/mp3rgain

Steps for each VULN entry (numbered 001, 002, ...):
A. Read the VULN block — understand function/line/trigger condition.
   If the vulnerability requires a special build or is not reproducible via a crafted file alone,
   write SKIPPED as first line of vuln_NNN_status.txt and explain in vuln_NNN_notes.md.

B. In __POC_DIR__/ generate:
   - vuln_NNN_gen.py  — Python script using struct/bytes to build the crafted MP3 (vuln_NNN.mp3).
     Use only stdlib. Construct minimal valid MP3 framing then embed the malformed field.
   - vuln_NNN_run.sh  — executable shell script:
       #!/bin/bash
       set -euo pipefail
       cd "$(dirname "$0")"
       python3 vuln_NNN_gen.py
       ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
         __SOURCE_DIR__/build_test/mp3rgain vuln_NNN.mp3 \
         > vuln_NNN_result.txt 2>&1 || true
       grep -E "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|attempt to|index out of bounds|SIGSEGV|SIGABRT" \
         vuln_NNN_result.txt asan.log 2>/dev/null || true
   - vuln_NNN_notes.md — brief explanation: PoC approach, trigger path, expected output.

C. chmod +x vuln_NNN_run.sh, then actually run it:
       timeout 60 bash __POC_DIR__/vuln_NNN_run.sh > __POC_DIR__/vuln_NNN_result.txt 2>&1
       echo "EXIT=$?" >> __POC_DIR__/vuln_NNN_result.txt

D. Write __POC_DIR__/vuln_NNN_status.txt with first line exactly one of:
     VERIFIED_CRASH     — ASAN/UBSAN/Rust panic visible in result output
     UNVERIFIED         — ran without any crash or error indicator
     ERROR              — PoC script or binary invocation itself errored

E. Do NOT modify source files or files outside __POC_DIR__/.

After all subagents complete, output one summary line per VULN: number + status.

Tool whitelist: Read, Write, Bash, Grep, Glob, Agent.'

POC_PIDS=()
POC_LAUNCHED=0
POC_SKIPPED=0
AUDIT_PIDS=()

poc_reap() {
    local alive=() pid
    for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}"; do
        if kill -0 "$pid" 2>/dev/null; then
            alive+=("$pid")
        fi
    done
    POC_PIDS=("${alive[@]+"${alive[@]}"}")
}

poc_throttle() {
    while :; do
        poc_reap
        [ "${#POC_PIDS[@]}" -lt "$POC_PARALLEL" ] && break
        sleep 3
    done
}

audit_reap() {
    local alive=() pid
    for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
        if kill -0 "$pid" 2>/dev/null; then
            alive+=("$pid")
        fi
    done
    AUDIT_PIDS=("${alive[@]+"${alive[@]}"}")
}

audit_throttle() {
    while :; do
        drain_events
        audit_reap
        [ "${#AUDIT_PIDS[@]}" -lt "$AUDIT_PARALLEL" ] && break
        sleep 2
    done
}

jobs_cleanup() {
    local pid
    for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}" "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
}
trap jobs_cleanup EXIT INT TERM

launch_poc_bg() {
    local f="$1" tag="$2" result="$3" vuln_n="$4"
    [ "$POC_ENABLED" = "1" ] || return 0

    local POC_DIR="$POC_BASE/$tag"
    if [ -f "$POC_DIR/.done" ]; then
        POC_SKIPPED=$((POC_SKIPPED + 1))
        return 0
    fi
    mkdir -p "$POC_DIR"

    local prompt="${POC_PROMPT_TEMPLATE//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__RESULT_FILE__/$result}"
    prompt="${prompt//__SOURCE_FILE__/$f}"
    prompt="${prompt//__POC_DIR__/$POC_DIR}"

    poc_throttle

    (
        if claude -p "$prompt" \
            --model claude-sonnet-4-6 \
            --dangerously-skip-permissions \
            --allowedTools "Read,Write,Bash,Grep,Glob,Agent" \
            > "$POC_DIR/poc_session.log" 2>&1; then
            if grep -qE "You're out of extra usage|hit your (session|usage) limit" "$POC_DIR/poc_session.log" 2>/dev/null; then
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
    local total_lines
    total_lines=$(wc -l < "$EVENTS_FILE" | tr -d ' ')
    [ "$total_lines" -gt "$EVENTS_SEEN" ] || return 0

    local type ef etag eresult evn
    while IFS='|' read -r type ef etag eresult evn; do
        case "$type" in
            VULN)
                VULN_COUNT=$((VULN_COUNT + evn))
                echo "  -> [$ef] FOUND $evn vulnerability(ies)!"
                echo "[$(date '+%F %T')] VULN $ef: $evn findings" >> "$LOGFILE"
                launch_poc_bg "$ef" "$etag" "$eresult" "$evn"
                ;;
            CLEAN)
                echo "  -> [$ef] Clean."
                ;;
            ERROR)
                ERRORS=$((ERRORS + 1))
                echo "  -> [$ef] WARNING: empty result, removed" | tee -a "$LOGFILE"
                ;;
            ANOMALY)
                echo "  -> [$ef] WARNING: format anomaly (no '## VULN:' and no NO_VULN_FOUND) — flagged for review" | tee -a "$LOGFILE"
                echo "[$(date '+%F %T')] FORMAT-ANOMALY $ef" >> "$LOGFILE"
                ;;
            USAGE_LIMIT)
                echo ""
                echo "!!! USAGE LIMIT REACHED while auditing: $ef"
                echo "[$(date '+%F %T')] STOPPED: usage limit hit at $ef" >> "$LOGFILE"
                ;;
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

    if grep -qE "You're out of extra usage|hit your (session|usage) limit" "$result" 2>/dev/null; then
        rm -f "$result"
        touch "$STOP_FILE"
        echo "USAGE_LIMIT|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
        return 0
    fi

    if [ ! -s "$result" ]; then
        rm -f "$result"
        echo "ERROR|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
        return 0
    fi

    printf '\n<!-- %s: %s -->\n' "$VERSION_MARKER" "$PROMPT_VERSION" >> "$result"

    if grep -q "^## VULN:" "$result" 2>/dev/null; then
        local vuln_n
        vuln_n=$(grep -c "^## VULN:" "$result")
        echo "VULN|${f}|${tag}|${result}|${vuln_n}" >> "$EVENTS_FILE"
    elif grep -qi "NO_VULN_FOUND" "$result" 2>/dev/null; then
        echo "CLEAN|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    else
        echo "ANOMALY|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    fi
}

echo "=========================================="
echo " mp3rgain Full Security Audit"
echo " Mode: $MODE  (audit=$RUN_AUDIT, poc=$POC_ENABLED, audit_parallel=$AUDIT_PARALLEL, poc_parallel=$POC_PARALLEL)"
echo " Files to audit: $TOTAL (skipped $MISSING missing)"
echo " Results: $OUTDIR/   PoCs: $POC_BASE/"
echo " Log: $LOGFILE"
echo "=========================================="
echo ""

if [ "$RUN_AUDIT" = "0" ]; then
    echo "Skipping audit phase (--poc-only) — scanning existing results for PoC launch..."
    for f in "${FILES[@]}"; do
        tag=$(tag_for "$f")
        result="$OUTDIR/${tag}.md"
        [ -f "$result" ] || continue
        grep -q "^## VULN:" "$result" 2>/dev/null || continue
        vuln_n=$(grep -c "^## VULN:" "$result")
        echo "[poc-only] $f ($vuln_n vuln)"
        launch_poc_bg "$f" "$tag" "$result" "$vuln_n"
    done
else
for f in "${FILES[@]}"; do
    if [ -f "$STOP_FILE" ]; then
        break
    fi

    COUNT=$((COUNT + 1))
    tag=$(tag_for "$f")
    result="$OUTDIR/${tag}.md"

    if result_is_current "$result"; then
        SKIPPED=$((SKIPPED + 1))
        if [ "$POC_ENABLED" = "1" ] && grep -q "^## VULN:" "$result" 2>/dev/null; then
            vuln_n=$(grep -c "^## VULN:" "$result")
            launch_poc_bg "$f" "$tag" "$result" "$vuln_n"
        fi
        continue
    elif [ -f "$result" ]; then
        echo "[$COUNT/$TOTAL] Stale (prompt-v$PROMPT_VERSION) re-auditing: $f"
        rm -f "$result"
    else
        echo "[$COUNT/$TOTAL] Auditing: $f"
    fi

    audit_throttle
    audit_one "$f" "$tag" "$result" &
    AUDIT_PIDS+=($!)
done

for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
done
drain_events

if [ -f "$STOP_FILE" ]; then
    echo ""
    echo "!!! Resume with: ./mp3rgain_audit.sh"
    echo ""
    echo "Waiting for in-flight PoC subagents to finish..."
    wait
    echo "=========================================="
    echo " Audit INTERRUPTED (usage limit)"
    echo " Completed: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL"
    echo " Vulnerabilities: $VULN_COUNT"
    echo " PoCs launched: $POC_LAUNCHED"
    echo " Resume: ./mp3rgain_audit.sh"
    echo "=========================================="
    rm -f "$STOP_FILE"
    exit 1
fi

echo ""
echo "=========================================="
echo " Audit Complete"
echo " Files audited: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL total"
echo " Errors: $ERRORS"
echo " Vulnerabilities found: $VULN_COUNT"
echo " Results: $OUTDIR/"
echo "=========================================="
echo "[$(date '+%F %T')] DONE: $((COUNT - SKIPPED)) new, $SKIPPED skipped, $VULN_COUNT vulns" >> "$LOGFILE"
fi

# ============================================================
# Wait for all background PoC tasks to finish
# ============================================================
if [ "$POC_ENABLED" = "1" ] && [ "${#POC_PIDS[@]}" -gt 0 ]; then
    echo ""
    echo "Waiting for ${#POC_PIDS[@]} background PoC subagent(s) to finish..."
    wait
fi

if [ "$POC_ENABLED" = "1" ]; then
    poc_done=$(find "$POC_BASE" -name '.done' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$POC_BASE"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_total=$(find "$POC_BASE" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    echo "=========================================="
    echo " PoC Generation Summary"
    echo " Launched this run:   $POC_LAUNCHED"
    echo " Already-done skip:   $POC_SKIPPED"
    echo " Files with .done:    $poc_done"
    echo " PoCs total/verified: $poc_total / $poc_verified"
    echo " Base: $POC_BASE/"
    echo "=========================================="
fi
