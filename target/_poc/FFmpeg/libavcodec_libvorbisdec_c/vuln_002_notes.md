# VULN 002: Heap OOB Read in oggvorbis_decode_init() — Xiph Lacing Parser

## Vulnerability

- **File**: `libavcodec/libvorbisdec.c`
- **Function**: `oggvorbis_decode_init()`
- **Lines**: 72–82
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

The Xiph-lacing branch (entered when `extradata[0] == 0x02`) parses continuation
bytes in a while loop:

```c
p++;   // line 71: p now points to extradata[1]
for (i = 0; i < 2; i++) {
    hsizes[i] = 0;
    while ((*p == 0xFF) && (sizesum < avccontext->extradata_size)) {  // line 74
        hsizes[i] += 0xFF;
        offset++;
        sizesum += 1 + 0xFF;
        p++;                   // line 78: can advance p past end of buffer
    }
    hsizes[i] += *p;           // line 80: OOB read if p is past end
    ...
}
```

With `extradata = [0x02, 0xFF]` (size = 2):
1. `p` starts at `extradata[1]` (= `0xFF`), `sizesum = 1`
2. While condition: `*p == 0xFF` ✓ and `sizesum (1) < extradata_size (2)` ✓ → enter loop
3. Loop body: `p++` advances to `extradata[2]` — **one byte past the allocation**
4. `sizesum` becomes `1 + 1 + 255 = 257`
5. While condition re-check: `*p` dereferences `extradata[2]` → **OOB READ #1**
   (Note: `*p == 0xFF` is evaluated before `sizesum < extradata_size` due to left-to-right
   evaluation — C short-circuits only if the first operand is false)
6. The condition is false (257 >= 2), loop exits
7. Line 80: `hsizes[i] += *p` dereferences `extradata[2]` again → **OOB READ #2**

## Attack Vector

Craft a Matroska (MKV/WebM) file with an audio track using codec `A_VORBIS`
and set `CodecPrivate` to `[0x02, 0xFF]`. The MKV demuxer passes `codec_priv`
data directly as `extradata` to the codec (see `matroskadec.c` lines 3334–3340).

Command to trigger:
```
ffmpeg -i vuln_002_input.mkv -f null -
```

## PoC Files

- `vuln_002_gen.py`: Generates the malicious MKV file
- `vuln_002_input.mkv`: The crafted MKV (output of the generator)
- `vuln_002_run.sh`: Runs ffmpeg under ASAN to capture the bug
- `vuln_002_result.txt`: Output/ASAN report
- `vuln_002_status.txt`: Verification verdict

## Fix Suggestion

Add a bounds check before the while-loop re-dereference. After `p++` inside the
loop body, the guard should also verify `p < extradata + extradata_size` before
the next `*p` access in the while condition.
