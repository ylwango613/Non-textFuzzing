# VULN 001 – OOB Read via Empty tref/hint Track ID Array

## Summary

| Field | Value |
|-------|-------|
| ID | VULN-001 |
| CWE | CWE-125 (Out-of-bounds Read) |
| File | `Source/C++/Core/Ap4HintTrackReader.cpp` |
| Line | 66 |
| Binary | `build_test/bin/mp42aac` (see Limitation below) |

---

## Root Cause

`AP4_HintTrackReader::AP4_HintTrackReader()` (line 62–71):

```cpp
AP4_TrakAtom* hint_trak_atom = hint_track.UseTrakAtom();
AP4_Atom* atom = hint_trak_atom->FindChild("tref/hint");
if (atom != NULL) {
    // LINE 66 — OOB READ:
    AP4_UI32 media_track_id =
        AP4_DYNAMIC_CAST(AP4_TrefTypeAtom, atom)->GetTrackIds()[0];
    m_MediaTrack = movie.GetTrack(media_track_id);
    ...
}
```

`AP4_TrefTypeAtom` is constructed by parsing:

```cpp
AP4_TrefTypeAtom(type, size, stream):
    AP4_Size data_size = size - 8;
    while (data_size >= 4) {   // loops over track IDs
        stream.ReadUI32(track_id);
        m_TrackIds.Append(track_id);
        data_size -= 4;
    }
```

When `size == 8` (header-only, no payload), `data_size == 0`, the loop never
runs, and `m_TrackIds` stays empty (`m_Items == nullptr`).

`AP4_Array<T>::operator[]` is an unchecked raw pointer dereference:

```cpp
T& operator[](unsigned long idx) { return m_Items[idx]; }
```

With `m_Items == nullptr` and `idx == 0`, this is `nullptr[0]`, a **NULL
dereference / out-of-bounds read**, detected by ASAN as a heap/global-OOB or
SIGSEGV.

---

## Trigger Condition

Craft an MP4 where the hint track's `tref` box contains a `hint` sub-box with
`size = 8` (the 8-byte box header only, no track-ID payload):

```
moov/trak[hint]/tref/hint:  00 00 00 08  68 69 6E 74
                             ─────size──  ──'hint'──
```

---

## Exploitability

* **Impact**: Read from address 0x0 (or nearby out-of-bounds heap address if
  m_Items is initialized elsewhere). Can lead to information disclosure or
  crash.
* **CVSS vector (tentative)**: AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H

---

## File Structure (vuln_001.mp4)

```
ftyp  (mp42)
moov
├── mvhd  (timescale=1000, next_track_id=3)
├── trak  [track_id=1, handler='soun'] — audio track for mp42aac to process
│   └── mdia / minf / stbl
│         └── stsd → mp4a (AAC-LC 44100Hz 2ch, valid esds)
│             (no samples — empty stts/stsc/stsz/stco)
└── trak  [track_id=2, handler='hint'] — TRIGGER
    ├── tref
    │   └── hint  size=8  ← EMPTY (no track IDs)
    └── mdia / minf / stbl (all empty)
```

---

## Limitation: mp42aac Binary

Static inspection (`nm mp42aac | grep -i HintTrackReader`) confirms that the
compiled `mp42aac` binary **does not link `AP4_HintTrackReader`**. Therefore,
the exact crash at line 66 cannot be reached via mp42aac.

The correct trigger binary for this vulnerability is one that calls
`AP4_HintTrackReader::Create()` on hint tracks found in the movie, e.g.:
* `mp4rtphintinfo`
* `mp4info` (with --full)
* A custom tool that iterates tracks and creates HintTrackReader objects

The MP4 file `vuln_001.mp4` is nonetheless correctly structured to trigger the
vulnerability in any such binary.
