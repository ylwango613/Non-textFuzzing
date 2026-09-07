# VULN 002 - NULL Pointer Dereference in print_streams() - PoC Notes

## Status: VERIFIED_CRASH

ASAN output (from vuln_002_result.txt):
```
src/fftools/graph/graphprint.c:782:81: runtime error: member access within null pointer of type 'struct AVStream'
AddressSanitizer: SEGV on unknown address 0x000000000010
  #0 print_streams      graphprint.c:782
  #1 print_filtergraphs_priv
  #2 print_filtergraphs
  #3 ffmpeg_cleanup
  #4 main
```

---

## Trigger Command

```bash
ffmpeg -print_graphs -i vuln_002_input.wav -streamid 0:abc -f wav /dev/null
```

- `-print_graphs` is an `OPT_TYPE_BOOL` option (no argument); do NOT pass `1` after it.
- `-streamid 0:abc` is the key trigger: the value "abc" is non-numeric, causing the crash.

---

## Root Cause: Missing NULL Guard in OUTPUTSTREAMS Block

### Vulnerable code (fftools/graph/graphprint.c, lines 780-782):
```c
for (int i = 0; i < of->nb_streams; i++) {
    OutputStream *ost = of->streams[i];
    const AVCodecDescriptor *codec_desc = avcodec_descriptor_get(ost->st->codecpar->codec_id);  // BUG: no NULL check
```

### Guarded code in ENCODERS block (line 716) — the fix pattern:
```c
if (!ost || !ost->st || !ost->st->codecpar || !ost->enc)
    continue;
```

The ENCODERS block has this guard. The OUTPUTSTREAMS block does not.

---

## Why ost->st is NULL: Early Return in new_output_stream()

In `fftools/ffmpeg_mux_init.c`:

```c
st = avformat_new_stream(oc, NULL);   // line 1154: allocates AVStream
ms = mux_stream_alloc(mux, type);     // line 1158: increments of->nb_streams; ost->st still NULL

// scheduler setup... (lines 1164-1175)

ost = &ms->ost;

if (o->streamid) {
    e = av_dict_get(o->streamid, "0", NULL, 0);  // finds "abc"
    if (e) {
        st->id = strtol("abc", &p, 0);  // returns 0; *p = 'a'
        if (!e->value[0] || *p) {       // *p != '\0' -> true
            return AVERROR(EINVAL);     // LINE 1190: returns BEFORE ost->st = st
        }
    }
}

// ...
ost->st = st;   // LINE 1201: NEVER REACHED when streamid is invalid
```

So `of->nb_streams` is incremented by `mux_stream_alloc` but `ost->st` is never set.

---

## Why print_filtergraphs Runs on a Partially Initialized File

In `fftools/ffmpeg_mux_init.c`, `of_open()`:

```c
mux = mux_alloc();    // STEP 1: mux added to output_files immediately; nb_output_files++
...
mux->fc = oc;         // STEP 2: set before create_streams()
...
create_streams(mux, o);  // STEP 3: fails partway through; of->nb_streams=1, ost->st=NULL
return err;           // mux still in output_files with mux->fc != NULL
```

In `fftools/ffmpeg.c`, `ffmpeg_cleanup()`:

```c
if ((print_graphs || print_graphs_file) && nb_output_files > 0)
    print_filtergraphs(...);  // called because nb_output_files=1
```

In `print_streams()`, the OUTPUTFILES loop has:
```c
if (!muxer->fc)
    continue;   // skipped because mux->fc != NULL
```

So the file is NOT skipped, and the loop reaches `of->streams[0]->st` which is NULL.

---

## PoC Files

| File | Purpose |
|------|---------|
| vuln_002_gen.py | Creates a minimal 16 KB WAV file (PCM 16-bit, 8 kHz, 1 second, mono) |
| vuln_002_run.sh | Runs the trigger command and collects output/ASAN logs |
| vuln_002_input.wav | Generated minimal WAV input (valid, ffmpeg-parseable) |
| vuln_002_result.txt | Full ffmpeg output including ASAN crash report |

---

## CWE and Impact

- **CWE-476**: NULL Pointer Dereference
- **Impact**: Process crash (SIGABRT via ASAN / SIGSEGV without ASAN) when `-print_graphs` is used and any output stream fails initialization after `mux_stream_alloc()` but before `ost->st = st`.
- **Conditions**: Requires `-print_graphs` (or `-print_graphs_file`) to be enabled alongside an output configuration that partially initializes an OutputStream.
