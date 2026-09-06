#!/bin/bash
# GDK (Green Dragon Kit) Full Security Audit Script (C++ source under src/)
#
# Usage:
#   ./gdk_audit.sh                        # default resume mode (audit only; PoC requires custom harness)
#   ./gdk_audit.sh --restart              # clear results, start fresh
#   ./gdk_audit.sh --restart-from 50      # restart from file #50
#   ./gdk_audit.sh --list-pending         # list unaudited files
#   ./gdk_audit.sh --stats                # statistics on existing results
#   ./gdk_audit.sh --no-poc               # audit only, skip PoC generation (same as default)
#   ./gdk_audit.sh --poc-only             # only run PoC phase (skip audit; requires harness)
#   ./gdk_audit.sh --restart-poc          # clear existing PoCs, regenerate
#   ./gdk_audit.sh src/session.cpp        # audit a specific file

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

SOURCE_DIR="/data/ylwang/non-textfuzz/target/gdk"
OUTDIR="$SOURCE_DIR/gdk"
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
    if [ -z "$(find "$SCAN_ROOT" \( -name '*.cpp' -o -name '*.hpp' \) -print -quit)" ]; then
        echo "FATAL: scan root has no .cpp/.hpp files: $SCAN_ROOT" >&2
        exit 2
    fi

    mapfile -t FILES < <(
        find "$SCAN_ROOT" \
            \( -name '*.cpp' -o -name '*.hpp' \) \
            ! -path '*/build_test/*' \
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
    echo " GDK Audit Statistics"
    echo " Total source files:      $TOTAL"
    echo " Files audited:           $done_count"
    echo " Files remaining:         $((TOTAL - done_count))"
    echo " Files with vulns:        $vuln_files"
    echo " Total vuln entries:      $vuln_entries"
    echo " Files with PoCs done:    $poc_files"
    echo " PoCs total / verified:   $poc_total / $poc_verified"
    echo " NOTE: PoC requires a custom C++ harness (HARNESS_AVAILABLE=0 by default)"
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
AUDIT_PROMPT_TEMPLATE='You are a top-tier C++ security auditor conducting an authorized security audit of Green Dragon Kit (GDK), a C++ Bitcoin/Liquid wallet SDK by Blockstream.

Please carefully read the file __SOURCE_DIR__/__FILE__ in its entirety.
Also use Grep/Glob/Read to examine related headers, called functions, and dependencies for full context.

**Large files must be read in multiple passes — "clean after one scan" is a historic false-negative root cause.**
For larger files (>500 lines), split by function groups and dispatch parallel subagents (one message with N Agent calls, subagent_type=general-purpose), each deeply analyzing one function group; then consolidate all findings into `## VULN:` blocks in your final message.

**Cross-file interactions must be checked:**
- Data parsed by one module and trusted by another without re-validation.
- Attacker-controlled length/count fields that flow into allocation or loop bounds downstream.

Project background:
- GDK is a C++ library (libgreen_gdk_full.a) that processes:
  * JSON RPC responses from Blockstream servers
  * PSBT (Partially Signed Bitcoin Transactions) binary format
  * BIP32 HD key derivation
  * base58check / bech32 address encoding/decoding
  * Liquid confidential transactions (Pedersen commitments, range proofs)
  * TOR hidden service connections
- Attack surface: crafted JSON from network (MITM on Blockstream server or self-hosted node),
  malformed PSBT blobs passed to GDK API functions.

**Focus on memory bugs ONLY (C++). Look for:**

1. **JSON parsing (nlohmann::json)**:
   - Deeply nested JSON causing stack overflow in the recursive descent parser.
   - JSON string with embedded NUL byte causing string length mismatch leading to OOB read.
   - Unchecked .at() / operator[] access on objects where the key may be absent (throws, but if caught and swallowed leads to undefined state).

2. **PSBT parsing (binary format)**:
   - Input/output count read from file, then malloc(count * sizeof_entry) without overflow check
     → heap under-allocation → OOB write when populating entries.
   - Truncated PSBT with a length field pointing past the end of the buffer → OOB read.

3. **base58check decoding**:
   - Decoded length computed before output buffer is allocated; if input has only whitespace or
     invalid chars, computed length can be 0 or underflow → OOB write on first byte stored.

4. **bech32 decode**:
   - Output buffer allocated based on input length via an incorrect length formula
     → heap overflow when writing decoded bytes.

5. **BIP32 HD path parsing**:
   - Path string like "m/0'"'"'/0'"'"'/999999999'"'"'/..." parsed with sscanf or strtoul into a
     uint32_t array of fixed size → stack/heap overflow if path has more segments than the array.

6. **Script/witness parsing**:
   - Push data length read from script bytes; if script is truncated, the stated length points past
     the buffer end → OOB read when copying the push data.

7. **Confidential transaction (Liquid)**:
   - Range proof / Pedersen commitment blobs passed to secp256k1_pedersen_verify or
     secp256k1_rangeproof_verify with attacker-controlled length → OOB in libsecp256k1.

8. **Websocket/Autobahn frame parsing**:
   - Frame length field (uint64) from network used directly for heap allocation without checking
     a MAX_MESSAGE_SIZE cap → OOM or OOB write on reception.

9. **Integer overflow before allocation**:
   - Any malloc/new/vector::resize/reserve where the size argument involves attacker-controlled
     data multiplied by a type size without overflow check → under-allocation → OOB.

10. **Use-after-free in async callbacks**:
    - Any asio/boost async callback that captures a reference/raw pointer to a stack-allocated or
      already-freed object (e.g., lambda capturing `this` of a destroyed session object).

Do NOT report:
- Issues reachable only with local filesystem access and not exposed over network.
- Purely hypothetical issues with no plausible external trigger.
- Pure resource-exhaustion DoS without a clear memory-safety angle.

Actively use tools for context (do not skip):
1. grep -rn "malloc\|new\|resize\|reserve\|memcpy\|memmove" __SOURCE_DIR__/src/ --include="*.cpp" for allocation sites.
2. grep -rn "json\[.*\]\|\.at(\|get<\|dump(" __SOURCE_DIR__/src/ --include="*.cpp" for JSON access.
3. grep -rn "base58\|bech32\|psbt\|PSBT\|script\|witness" __SOURCE_DIR__/src/ --include="*.cpp" for parsing entry points.
4. grep -rn "secp256k1\|pedersen\|rangeproof" __SOURCE_DIR__/src/ --include="*.cpp" for crypto blob handling.
5. For every attacker-controlled length/count field, trace whether it is bounds-checked before use.

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
- **攻击向量**: crafted JSON from network / malformed PSBT / malicious API input
- **外部触发路径**: <full call chain from API/network entry point to the vulnerable point>
- **描述**: xxx (memory corruption mechanism)
- **触发条件**: xxx (what the attacker must craft)
- **安全影响**: xxx (worst-case: crash / OOB read / OOB write / heap corruption)'

# ============================================================
# PoC generation settings
# GDK is a library — no standalone binary exists.
# PoC requires a custom C++ harness compiled against libgreen_gdk_full.a.
# HARNESS_AVAILABLE=0: PoC phase is disabled by default.
# Set HARNESS_AVAILABLE=1 (or pass --poc-only) once a harness build is ready.
# ============================================================
HARNESS_AVAILABLE=0   # PoC requires custom C++ harness; set to 1 when ready
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/gdk"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=0   # Disabled: no standalone binary; PoC requires custom harness
if [ "$RUN_POC" = "0" ]; then
    POC_ENABLED=0
elif [ "$HARNESS_AVAILABLE" = "0" ]; then
    echo "WARNING: HARNESS_AVAILABLE=0 — PoC phase will be skipped."
    echo "         GDK is a library (libgreen_gdk_full.a) with no standalone CLI."
    echo "         PoC generation requires a custom C++ harness."
    echo "         Set HARNESS_AVAILABLE=1 and rerun with --poc-only once harness is ready."
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

# POC_PROMPT_TEMPLATE: Claude will write a minimal C++ harness for each vulnerability,
# compile it against libgreen_gdk_full.a with ASAN, run it, and check for ASAN output.
POC_PROMPT_TEMPLATE='You are a security researcher. Based on the vulnerability audit report, generate a PoC for each reported GDK vulnerability.

==================== Hard Rules ====================
GDK is a library (libgreen_gdk_full.a), not a standalone binary.
Each PoC must use a minimal self-contained C++ harness that exercises the vulnerable function directly.

Compilation command for each harness:
  g++ -fsanitize=address,undefined -g0 \
      vuln_NNN_harness.cpp \
      -I__SOURCE_DIR__/include \
      -L__SOURCE_DIR__/build_test/cmake_build \
      -lgreen_gdk_full \
      -L/data/ylwang/non-textfuzz/target/gdk/build_test/deps/lib \
      -lssl -lcrypto -lboost_thread -lboost_system -lboost_filesystem \
      -lsqlite3 -lpthread -ldl \
      -Wl,-rpath,__SOURCE_DIR__/build_test/cmake_build \
      -Wl,-rpath,/data/ylwang/non-textfuzz/target/gdk/build_test/deps/lib \
      -o vuln_NNN_harness

Run it:
  ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
    ./vuln_NNN_harness > vuln_NNN_result.txt 2>&1 || true

Check for:
  grep -E "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|SIGSEGV|SIGABRT" \
    vuln_NNN_result.txt asan.log 2>/dev/null || true

Do NOT spin up network connections, TOR, or external services in the harness.
Do NOT modify GDK source files.
====================================================

Vulnerability report:  __RESULT_FILE__
Source file:           __SOURCE_DIR__/__SOURCE_FILE__
PoC directory:         __POC_DIR__
GDK include path:      __SOURCE_DIR__/include/
GDK library:           __SOURCE_DIR__/build_test/cmake_build/libgreen_gdk_full.a
Deps library path:     /data/ylwang/non-textfuzz/target/gdk/build_test/deps/lib

Steps for each VULN entry (numbered 001, 002, ...):
A. Read the VULN block — understand function/line/trigger condition.
   Read the relevant GDK header(s) from __SOURCE_DIR__/include/ to determine the correct API call.
   If the vulnerability requires live network, specific TOR config, or complex session state that
   cannot be minimally exercised in a harness, write SKIPPED as first line of vuln_NNN_status.txt
   and explain in vuln_NNN_notes.md.

B. In __POC_DIR__/ generate:
   - vuln_NNN_harness.cpp — minimal C++ harness:
       #include <relevant_gdk_header.hpp>
       int main() {
           // construct crafted input (raw bytes / JSON string / PSBT buffer)
           // call the vulnerable GDK function directly
           return 0;
       }
     Keep the harness self-contained; do not require a running GDK session unless unavoidable.
   - vuln_NNN_run.sh — executable shell script:
       #!/bin/bash
       set -euo pipefail
       cd "$(dirname "$0")"
       g++ -fsanitize=address,undefined -g0 \
           vuln_NNN_harness.cpp \
           -I__SOURCE_DIR__/include \
           -L__SOURCE_DIR__/build_test/cmake_build \
           -lgreen_gdk_full \
           -L/data/ylwang/non-textfuzz/target/gdk/build_test/deps/lib \
           -lssl -lcrypto -lboost_thread -lboost_system -lboost_filesystem \
           -lsqlite3 -lpthread -ldl \
           -Wl,-rpath,__SOURCE_DIR__/build_test/cmake_build \
           -Wl,-rpath,/data/ylwang/non-textfuzz/target/gdk/build_test/deps/lib \
           -o vuln_NNN_harness
       ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
         ./vuln_NNN_harness > vuln_NNN_result.txt 2>&1 || true
       grep -E "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|SIGSEGV|SIGABRT" \
         vuln_NNN_result.txt asan.log 2>/dev/null || true
   - vuln_NNN_notes.md — brief explanation: PoC approach, trigger path, expected output.

C. chmod +x vuln_NNN_run.sh, then actually run it:
       timeout 120 bash __POC_DIR__/vuln_NNN_run.sh > __POC_DIR__/vuln_NNN_result.txt 2>&1
       echo "EXIT=$?" >> __POC_DIR__/vuln_NNN_result.txt

D. Write __POC_DIR__/vuln_NNN_status.txt with first line exactly one of:
     VERIFIED_CRASH     — ASAN/UBSAN triggered in harness execution
     UNVERIFIED         — harness ran without crash or error
     ERROR              — compilation or harness execution itself errored

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
echo " GDK Full Security Audit"
echo " Mode: $MODE  (audit=$RUN_AUDIT, poc=$POC_ENABLED, audit_parallel=$AUDIT_PARALLEL, poc_parallel=$POC_PARALLEL)"
echo " Files to audit: $TOTAL (skipped $MISSING missing)"
echo " Results: $OUTDIR/   PoCs: $POC_BASE/"
echo " Log: $LOGFILE"
echo " NOTE: PoC disabled (HARNESS_AVAILABLE=$HARNESS_AVAILABLE); enable after building a harness."
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
    echo "!!! Resume with: ./gdk_audit.sh"
    echo ""
    echo "Waiting for in-flight PoC subagents to finish..."
    wait
    echo "=========================================="
    echo " Audit INTERRUPTED (usage limit)"
    echo " Completed: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL"
    echo " Vulnerabilities: $VULN_COUNT"
    echo " PoCs launched: $POC_LAUNCHED"
    echo " Resume: ./gdk_audit.sh"
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
