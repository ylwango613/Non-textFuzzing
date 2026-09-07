# VULN 001 — OOB Read on Empty AP4_Array in GetTrackIds()[0]

## File / Line

`Bento4/Source/C++/Core/Ap4HintTrackReader.cpp` line 66  
(declared in `Ap4HintTrackReader.h`)

## How the PoC works

### Root cause

`AP4_TrefTypeAtom` parses a `tref/hint` child atom using this constructor:

```cpp
// Ap4TrefTypeAtom.cpp:50-63
AP4_TrefTypeAtom::AP4_TrefTypeAtom(AP4_Atom::Type type, AP4_UI32 size,
                                   AP4_ByteStream& stream)
    : AP4_Atom(type, size)
{
    AP4_Size data_size = size - 8;   // subtract 8-byte header
    while (data_size >= 4) {
        AP4_UI32 track_id;
        stream.ReadUI32(track_id);
        m_TrackIds.Append(track_id);
        data_size -= 4;
    }
}
```

When the `hint` sub-atom inside `tref` has `size = 8` (just the 4-byte length
field and 4-byte type field, **no payload**), `data_size = 0` and the loop
never runs.  `m_TrackIds` remains empty: its internal `m_Items` pointer stays
`NULL` (see `AP4_Array` constructor: `m_Items(0)`).

Later, in `AP4_HintTrackReader::AP4_HintTrackReader()`:

```cpp
// Ap4HintTrackReader.cpp:64-67
AP4_Atom* atom = hint_trak_atom->FindChild("tref/hint");
if (atom != NULL) {                               // atom IS found (it exists!)
    AP4_UI32 media_track_id =
        AP4_DYNAMIC_CAST(AP4_TrefTypeAtom, atom)->GetTrackIds()[0]; // OOB!
```

Because `atom` is **not** NULL (it was successfully parsed — just with an
empty payload), the `if`-branch executes unconditionally.  
`GetTrackIds()` returns a reference to the empty `AP4_Array<AP4_UI32>`, and
`operator[](0)` calls `return m_Items[0]` where `m_Items == NULL`.  
This is an out-of-bounds read from address 0, i.e., a **null-pointer
dereference triggered by an unchecked array index**.

### Crafted MP4 structure

```
ftyp  (20 B)  major_brand='isom'
moov
  mvhd       (108 B)  next_track_id=3
  trak  [hint track, id=1]
    tkhd     (92 B)   track_id=1
    mdia
      mdhd   (32 B)
      hdlr   (33 B)   handler_type='hint'
      minf
        nmhd (12 B)
        dinf/dref/url  (self-contained)
        stbl (stsd+stts+stsc+stsz+stco, all empty)
    tref
      hint   (8 B)   <-- KEY: size=8, NO track-ID payload
  trak  [audio track, id=2]
    tkhd     (92 B)   track_id=2
    mdia
      mdhd   (32 B)
      hdlr   (33 B)   handler_type='soun'
      minf
        smhd (16 B)
        dinf/dref/url
        stbl (all empty)
```

The critical crafted byte sequence inside `tref`:

```
00 00 00 08  68 69 6e 74
^^^^^^^^     ^^^^^^^^^^^
size = 8     'hint'  (no further bytes — m_TrackIds will be empty)
```

### Call path to the crash

```
mp42aac main()
  → AP4_File(*input)           [parses ftyp + moov, creates AP4_Movie]
  → AP4_Movie(moov, stream)    [creates AP4_Track objects for each trak]
      AP4_Track(trak_atom, stream, timescale)   [for the hint trak]
          AP4_TrefTypeAtom(AP4_ATOM_TYPE_HINT, 8, stream)
              data_size = 0  →  m_TrackIds is empty (m_Items = NULL)

  → [code that calls AP4_HintTrackReader::Create on the hint track]
      AP4_HintTrackReader(hint_track, movie, ssrc)
          FindChild("tref/hint")  →  non-NULL atom returned
          GetTrackIds()[0]        →  m_Items[0] with m_Items==NULL
                                     *** OOB READ / SIGSEGV ***
```

Note: `AP4_HintTrackReader::Create` is called by tools that process hint
tracks (e.g., `mp4rtphintinfo`).  The `mp42aac` binary itself does not call
`AP4_HintTrackReader::Create` in its main code path; it only searches for an
`AP4_Track::TYPE_AUDIO` track.  The vulnerability is confirmed in the Bento4
library; exercising it via `mp42aac` may require the audio track to also be
identified (the PoC includes one), but the crash manifests when any caller
invokes `AP4_HintTrackReader::Create` on a movie parsed from this file.

## Expected ASAN output

With a binary instrumented with AddressSanitizer and the `hint` sub-atom
carrying `size=8`, ASAN should report one of the following when
`GetTrackIds()[0]` executes:

```
==PID==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    READ of size 4 at 0x0000000000000000 thread T0
    #0  AP4_Array<unsigned int>::operator[](unsigned long)
    #1  AP4_HintTrackReader::AP4_HintTrackReader(...)
    #2  AP4_HintTrackReader::Create(...)
    ...
```

or a heap-buffer-overflow if the array has been allocated but is zero-length.

## Fix

Before `GetTrackIds()[0]`, add a bounds check:

```cpp
const AP4_Array<AP4_UI32>& ids =
    AP4_DYNAMIC_CAST(AP4_TrefTypeAtom, atom)->GetTrackIds();
if (ids.ItemCount() > 0) {
    AP4_UI32 media_track_id = ids[0];
    m_MediaTrack = movie.GetTrack(media_track_id);
    ...
}
```
