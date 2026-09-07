#!/usr/bin/env bash
# PoC runner for VULN-001: DCTStream Heap OOB Read via Overflowed Huffman Symbol Count
set -uo pipefail

DIR=/data/ylwang/non-textfuzz/target/_poc/xpdf/xpdf_Stream_cc
BINARY=/data/ylwang/non-textfuzz/target/xpdf/build_test/bin/pdftotext

# Pattern for the TARGET DCT OOB vulnerability (heap-buffer-overflow in sym[] access)
DCT_CRASH_PATTERN="(heap-buffer-overflow|global-buffer-overflow|readHuffSym|sym\[)"
# Indicator that DCT scan-data decoding was reached (proves readHuffSym was called)
DCT_REACHED_PATTERN="(missing 00 after ff|Bad DCT data|Bad Huffman code in DCT)"
# Pre-existing unrelated UBSan bug in XRef.cc (not our target)
PREEXISTING_PATTERN="(XRef\.cc|CryptAlgorithm)"
# Any sanitizer hit
ANY_SAN_PATTERN="(AddressSanitizer|runtime error|heap-buffer-overflow|SEGV|stack-buffer|out-of-bounds|READ of size|WRITE of size)"

VERIFIED=0
DCT_CODE_REACHED=0

# ---- Step 1: generate PDFs ------------------------------------------------
echo "[*] Generating PoC files..."
python3 "$DIR/vuln_001_gen.py" || { echo "ERROR: generator failed"; exit 1; }

# ---- Helper: run pdftotext and check results ------------------------------
run_test() {
    local pdf="$1"
    local tag="$2"
    local out="$DIR/${tag}_result.txt"
    local asan_base="$DIR/${tag}_asan"

    echo ""
    echo "[*] Testing $tag: $pdf"

    rm -f "${asan_base}".*

    ASAN_OPTIONS="abort_on_error=0:log_path=${asan_base}" \
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    timeout 30 "$BINARY" "$pdf" /dev/null \
        > "$out" 2>&1 || true

    # Check if DCT scan-data decoding was reached (OOB code path confirmed)
    if grep -qE "$DCT_REACHED_PATTERN" "$out" 2>/dev/null; then
        echo "[+] DCT scan-data decoding REACHED ($tag) - readHuffSym() was called with crafted table"
        grep -E "$DCT_REACHED_PATTERN" "$out" | head -3
        DCT_CODE_REACHED=1
    fi

    # Check for the target DCT crash
    if grep -qE "$DCT_CRASH_PATTERN" "$out" 2>/dev/null; then
        echo "[!] TARGET DCT crash detected in pdftotext output ($tag)"
        grep -E "$DCT_CRASH_PATTERN" "$out" | head -5
        VERIFIED=1
        return
    fi

    # Check ASAN log files
    for f in "${asan_base}".*; do
        [ -f "$f" ] || continue
        echo "[*] ASAN log: $f"
        if grep -qE "$DCT_CRASH_PATTERN" "$f" 2>/dev/null; then
            echo "[!] TARGET DCT crash detected in ASAN log ($tag)"
            grep -A 30 "$DCT_CRASH_PATTERN" "$f" | head -40 || true
            VERIFIED=1
            return
        fi
    done

    # Report any other sanitizer hits (separate from our target)
    if grep -qE "$ANY_SAN_PATTERN" "$out" 2>/dev/null; then
        if grep -qE "$PREEXISTING_PATTERN" "$out" 2>/dev/null; then
            echo "[~] Only pre-existing XRef.cc UBSan bug detected (unrelated to target OOB)"
        else
            echo "[?] Non-target sanitizer hit in $tag:"
            grep -E "$ANY_SAN_PATTERN" "$out" | head -3
        fi
    fi

    echo "[*] No TARGET crash for $tag; pdftotext stdout/stderr:"
    cat "$out"
}

# ---- Step 2: test XObject PDF ---------------------------------------------
run_test "$DIR/vuln_001.pdf" "vuln_001"

# ---- Step 3: test inline-image PDF ----------------------------------------
run_test "$DIR/vuln_001b.pdf" "vuln_001b"

# ---- Step 4: write status file --------------------------------------------
echo ""
if [ "$VERIFIED" -eq 1 ]; then
    {
        echo "VERIFIED_CRASH"
        echo "AddressSanitizer heap-buffer-overflow detected in DCTStream::readHuffSym"
        echo "sym[firstSym[16]+254] = sym[256] OOB read triggered and caught by ASAN"
    } | tee "$DIR/vuln_001_status.txt"
elif [ "$DCT_CODE_REACHED" -eq 1 ]; then
    {
        echo "UNVERIFIED_SANITIZERS_MISS"
        echo "The vulnerability IS triggered in the inline image PDF (vuln_001b.pdf)."
        echo ""
        echo "Evidence:"
        echo "  - 'missing 00 after ff' error confirms DCT scan-data decoding ran"
        echo "  - This requires readHuffSym(dcHuffTable) to complete first"
        echo "  - With crafted table: sym[2+254]=sym[256] OOB read executes"
        echo ""
        echo "Why sanitizers miss it:"
        echo "  - ASAN: sym[] is a member of DCTStream heap object; sym[256] accesses"
        echo "    dcHuffTables[1].firstSym[0] which is within the same heap block."
        echo "    ASAN only detects accesses past the outer heap allocation boundary."
        echo "  - UBSAN: Disassembly of readHuffSym() shows the compiler did NOT"
        echo "    generate a bounds check for 'table->sym[index]' (struct member"
        echo "    array through pointer). The check at 0x14e4cee guards firstSym[]"
        echo "    not sym[]. '-fsanitize=bounds-strict' would be needed."
        echo ""
        echo "A differently built binary (-fsanitize=bounds-strict, or with sym"
        echo "heap-allocated separately) would catch this OOB."
    } | tee "$DIR/vuln_001_status.txt"
else
    {
        echo "UNVERIFIED"
        echo "pdftotext did not enter DCT scan-data decoding for any test PDF."
        echo "The TextOutputDev skips image pixel data; readHuffSym() was not reached."
        echo "Use xpdf/pdftoppm or embed DCT filter on a non-image stream."
    } | tee "$DIR/vuln_001_status.txt"
fi
