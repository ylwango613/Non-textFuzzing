# VULN 001 — Integer Overflow in fastaudio_decode (libavcodec/fastaudio.c)

## Vulnerability

**File:** `libavcodec/fastaudio.c`, line 173  
**Function:** `fastaudio_decode()`

```c
// Line 115
subframes = pkt->size / (40 * avctx->ch_layout.nb_channels);

// Line 116 — guard only rejects subframes > INT_MAX/256 = 8388607
if (subframes <= 0 || subframes > INT_MAX / 256)
    return AVERROR_INVALIDDATA;

// Line 173 — VULNERABLE: 1024 * subframe overflows signed int32 when subframe >= 2097152
memcpy(frame->extended_data[channel] + 1024 * subframe, result, 256 * sizeof(float));
```

The guard rejects values above `INT_MAX / 256 = 8,388,607` but not above `INT_MAX / 1024 = 2,097,151`. Values in the range `[2,097,152 – 8,388,607]` pass the check yet cause signed-integer overflow (C UB) in `1024 * subframe` on the first iteration where `subframe == 2,097,152`. The overflowed offset is `−2,147,483,648`, causing `memcpy` to write 1 KB approximately 2 GB **before** the allocated frame buffer.

## Trigger Conditions (1 channel)

| Parameter | Value |
|-----------|-------|
| `pkt->size` threshold | > 83,886,080 bytes |
| `subframes` produced | > 2,097,152 |
| Overflow at iteration | `subframe = 2,097,152` |
| Effective memcpy dst | `frame_buf − 2 GB` |

## PoC Strategy

The MOFLEX demuxer (`libavformat/moflex.c`) accumulates audio packet data across multiple blocks via `av_append_packet()`, flushing to the decoder only when the `endframe` bit is set in the chunk header.

We generate **10,240 non-endframe blocks** (each contributing 8,192 bytes) followed by **1 endframe block** (8,192 bytes), producing a total accumulated packet of `10,241 × 8,192 = 83,890,176 bytes`, which gives `subframes = 83,890,176 / 40 = 2,097,254 > 2,097,152`.

## File Structure

Each MOFLEX block (8,220 bytes for non-endframe, 8,224 bytes for endframe):

```
[14 bytes] Sync header: magic 0x4C32, 2-byte pad, 8-byte ts, 2-byte size_field
[10 bytes] Stream descriptor: audio type=2 (FASTAUDIO, 1 ch, 44100 Hz)
[ 1 byte ] flags = 0x00
[ 2 or 6 bytes] Bit-packed chunk header (stream=0, endframe=0/1, pkt_size=8192)
[8192 bytes] Chunk payload (zeros)
[ 1 byte ] 0x00 terminator (exits inner while loop in moflex_read_packet)
```

## Observed Behavior

```
[fastaudio @ ...] get_buffer() failed
Error submitting packet to decoder: Invalid argument
1 packets read (83894272 bytes)   <-- packet accumulation confirmed correct
```

The packet is successfully accumulated and delivered to `fastaudio_decode`. However,
the buffer allocation fails before the OOB write can occur. Root cause of the
allocation failure:

### Interaction with `av_malloc` size cap

`libavutil/mem.c` line 74 sets:
```c
static atomic_size_t max_alloc_size = INT_MAX;  // 2,147,483,647
```

The minimum allocation required to let subframe reach 2,097,152 (the overflow point)
is `subframes_min × 256 × 4 = 2,097,153 × 256 × 4 = 2,147,484,672 bytes` — exactly
**1,025 bytes over INT_MAX**. `av_malloc` returns NULL, causing `ff_get_buffer` to
return `AVERROR(EINVAL)`.

### Why the guard is still wrong

The correct guard for preventing `1024 * subframe` overflow should be:
```c
subframes > INT_MAX / 1024   // = 2,097,151 — CORRECT
```
The actual guard is:
```c
subframes > INT_MAX / 256    // = 8,388,607 — WRONG (off by 4×)
```
The gap [2,097,152 – 8,388,607] would cause signed-integer overflow in `1024 * subframe`.
On this FFmpeg build the `av_malloc` cap happens to prevent exploitation, but the
logical error remains.

## Reproduction

```bash
chmod +x vuln_001_run.sh
bash vuln_001_run.sh
```

Generated file: `vuln_001_input.moflex` (~80 MB)  
FFmpeg binary: `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`
