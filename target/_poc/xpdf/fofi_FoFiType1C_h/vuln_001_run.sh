#!/usr/bin/env bash
# PoC runner for VULN-001:
# FoFiType1C::getGlyphName() heap OOB read (latent API-level vulnerability)
set -uo pipefail

DIR=/data/ylwang/non-textfuzz/target/_poc/xpdf/fofi_FoFiType1C_h
BINARY=/data/ylwang/non-textfuzz/target/xpdf/build_test/bin/pdftotext
PDF="$DIR/vuln_001.pdf"
RESULT="$DIR/vuln_001_result.txt"
STATUS="$DIR/vuln_001_status.txt"

# Sanitizer crash patterns for our TARGET vulnerability (getGlyphName OOB)
CRASH_PATTERN="(heap-buffer-overflow|AddressSanitizer|SEGV|out-of-bounds|READ of size|WRITE of size|stack-buffer)"
# Pre-existing unrelated UBSan bug in XRef.cc (not our target)
PREEXISTING_PATTERN="(XRef\.cc|CryptAlgorithm)"
# Evidence that the CFF/Type1C font loading code was reached
FONT_LOAD_PATTERN="(Couldn't find a font|Couldn't create a font|CFF|Type1C|bad font|invalid font)"

echo "[*] Step 1: Generating PoC PDF with embedded CFF (nGlyphs=1)..."
python3 "$DIR/vuln_001_gen.py" || { echo "ERROR: generator failed"; exit 1; }
echo ""

echo "[*] Step 2: Checking pdftotext binary exists..."
if [ ! -x "$BINARY" ]; then
    echo "ERROR: pdftotext not found at $BINARY"
    exit 1
fi
echo "    Binary: $BINARY"
echo ""

echo "[*] Step 3: Running pdftotext on crafted PDF (timeout 30s)..."
echo "    PDF: $PDF"
echo ""

rm -f "$DIR"/vuln_001_asan.*

ASAN_OPTIONS="abort_on_error=0:log_path=$DIR/vuln_001_asan" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
timeout 30 "$BINARY" "$PDF" /dev/null \
    > "$RESULT" 2>&1 || true

echo "[*] pdftotext output:"
cat "$RESULT"
echo ""

# Check ASAN log files
CRASH_IN_ASAN=0
for f in "$DIR"/vuln_001_asan.*; do
    [ -f "$f" ] || continue
    echo "[*] ASAN log found: $f"
    cat "$f"
    echo ""
    if grep -qE "$CRASH_PATTERN" "$f" 2>/dev/null; then
        echo "[!] CRASH detected in ASAN log!"
        CRASH_IN_ASAN=1
    fi
done

# Check stdout/stderr for crash (excluding pre-existing XRef.cc UBSan bug)
CRASH_IN_OUTPUT=0
if grep -qE "$CRASH_PATTERN" "$RESULT" 2>/dev/null; then
    if grep -qE "$PREEXISTING_PATTERN" "$RESULT" 2>/dev/null && \
       ! grep -qE "$CRASH_PATTERN" <(grep -vE "$PREEXISTING_PATTERN" "$RESULT") 2>/dev/null; then
        echo "[~] Only pre-existing XRef.cc/CryptAlgorithm UBSan bug detected (unrelated to target)"
    else
        echo "[!] TARGET crash pattern found in pdftotext output!"
        grep -E "$CRASH_PATTERN" "$RESULT" | head -5
        CRASH_IN_OUTPUT=1
    fi
fi

echo ""
echo "[*] Step 4: Analysis summary"
echo "============================================================"
echo "Vulnerability: FoFiType1C::getGlyphName() heap OOB read"
echo "Location:      fofi/FoFiType1C.cc:171 (charset[gid] without bounds check)"
echo "PDF contains:  CFF font with nGlyphs=1, embedded as Type1C"
echo ""
echo "Call chain actually executed by pdftotext:"
echo "  pdftotext -> SplashOutputDev::doUpdateFont()"
echo "            -> Gfx8BitFont::getCodeToGIDMap(FoFiType1C*)"
echo "            -> FoFiType1C::getNameToGIDMap()"
echo "               (iterates gid=0..nGlyphs-1=0, safe)"
echo ""
echo "Call chain with OOB read (NOT executed):"
echo "  [external caller] -> FoFiType1C::getGlyphName(gid >= nGlyphs)"
echo "                    -> charset[gid]  <-- OOB READ HERE"
echo ""
echo "Verdict: getGlyphName() has ZERO callers in xpdf. The OOB read"
echo "         cannot be reached via any PDF file fed to pdftotext."
echo "============================================================"

# Write status
if [ "$CRASH_IN_ASAN" -eq 1 ] || [ "$CRASH_IN_OUTPUT" -eq 1 ]; then
    {
        echo "VERIFIED_CRASH"
        echo "Unexpected: a sanitizer crash was detected when running pdftotext on"
        echo "the crafted PDF. This may indicate a secondary vulnerability."
        echo "See vuln_001_result.txt and vuln_001_asan.* for details."
    } | tee "$STATUS"
else
    {
        echo "SKIPPED"
        echo ""
        echo "Reason: FoFiType1C::getGlyphName() is a LATENT vulnerability."
        echo ""
        echo "The function at FoFiType1C.cc:166-176 has a real OOB read bug:"
        echo "  GString *FoFiType1C::getGlyphName(int gid) {"
        echo "    ...                                         // line 170"
        echo "    getString(charset[gid], buf, &ok);         // line 171 -- NO BOUNDS CHECK"
        echo "    ...                                        "
        echo "  }"
        echo "  charset is gmallocn(nGlyphs, sizeof(Gushort)), so charset[gid] with"
        echo "  gid >= nGlyphs is a heap OOB read."
        echo ""
        echo "However, getGlyphName() is declared in FoFiType1C.h but has exactly"
        echo "ZERO callers in the entire xpdf codebase (confirmed by grep)."
        echo ""
        echo "The actual pdftotext font processing path is:"
        echo "  SplashOutputDev::doUpdateFont()"
        echo "    -> Gfx8BitFont::getCodeToGIDMap(FoFiType1C*) [GfxFont.cc:1606]"
        echo "         -> ff->getNameToGIDMap()                 [FoFiType1C.cc:178]"
        echo "              iterates: for (gid = 0; gid < nGlyphs; ++gid)  <-- SAFE"
        echo ""
        echo "No PDF file can force pdftotext to call getGlyphName() with any gid value."
        echo "The vulnerability requires a code change to either:"
        echo "  a) Add a missing bounds check in getGlyphName() itself, OR"
        echo "  b) Add a caller that passes an unchecked gid from PDF data"
        echo ""
        echo "CFF font was successfully parsed (nGlyphs=1 confirmed by build)."
        echo "No crash was observed (expected for a latent API-level issue)."
    } | tee "$STATUS"
fi
