# VULN 002 – NULL Pointer Dereference via Unvalidated GetTrack() Return

## Vulnerability location

**File:** `Source/C++/Core/Ap4HintTrackReader.cpp`, lines 62-70  
**Header:** `Source/C++/Core/Ap4HintTrackReader.h`  
**CWE:** CWE-476 (NULL Pointer Dereference)

## Vulnerable code

```cpp
// get the media track
AP4_TrakAtom* hint_trak_atom = hint_track.UseTrakAtom();
AP4_Atom* atom = hint_trak_atom->FindChild("tref/hint");
if (atom != NULL) {
    AP4_UI32 media_track_id = AP4_DYNAMIC_CAST(AP4_TrefTypeAtom, atom)->GetTrackIds()[0];
    m_MediaTrack = movie.GetTrack(media_track_id);   // <-- can return NULL

    // get the media time scale
    m_MediaTimeScale = m_MediaTrack->GetMediaTimeScale();  // <-- NULL dereference!
}
```

`movie.GetTrack()` returns `NULL` when the requested track ID does not exist in the movie.
The code does **not** check this return value before dereferencing `m_MediaTrack`.

## How the PoC works

1. `vuln_002_gen.py` constructs a minimal MP4 with:
   - A valid `ftyp` box (brand `isom`).
   - A `moov` box containing exactly **one** track (hint track, `track_id = 1`).
   - The hint track has a `tref` box whose `hint` child references track ID
     `0xDEADBEEF` — a track that does not exist in the movie.
   - The `mdia/hdlr` uses handler type `hint`.

2. Intended call path:
   ```
   (binary calling AP4_HintTrackReader::Create)
    -> AP4_HintTrackReader::AP4_HintTrackReader(...)
       -> FindChild("tref/hint")  -- succeeds, returns the hint child atom
       -> GetTrackIds()[0]        -- returns 0xDEADBEEF
       -> movie.GetTrack(0xDEADBEEF) -- returns NULL (track doesn't exist)
       -> m_MediaTrack->GetMediaTimeScale()  -- NULL POINTER DEREFERENCE
   ```

## Binary limitation

The stated trigger path via `mp42aac` could **not** be verified because the
`mp42aac` binary does **not** call `AP4_HintTrackReader::Create()`. Its code path is:

```
mp42aac main()
 -> AP4_File(*input)       -- parses moov, creates AP4_Track objects (no HintTrackReader)
 -> movie->GetTrack(TYPE_AUDIO) -- returns NULL (only a hint track is present)
 -> prints "ERROR: no audio track found" and exits cleanly
```

The only binary that calls `AP4_HintTrackReader::Create()` in this source tree is
`Mp4RtpHintInfo` (`Source/C++/Apps/Mp4RtpHintInfo/Mp4RtpHintInfo.cpp`, line 139),
which is not present in the build at `build_test/bin/`.

The crafted MP4 is correct — feeding it to a binary that does call
`AP4_HintTrackReader::Create()` (such as a rebuilt `mp4rtphintinfo`) would
reproduce the NULL dereference at `m_MediaTrack->GetMediaTimeScale()`.

## Expected crash (when triggered by correct binary)

- **Signal:** SIGSEGV (segmentation fault) or SIGABRT under ASAN
- **ASAN report type:** `AddressSanitizer: SEGV on unknown address 0x0...`
  with the crashing instruction inside `AP4_Track::GetMediaTimeScale()`.
- **Root cause:** Missing NULL check after `movie.GetTrack()` at line 67 of the
  constructor, before the dereference at line 70.

## Fix recommendation

Add a NULL guard after `movie.GetTrack()`:

```cpp
m_MediaTrack = movie.GetTrack(media_track_id);
if (m_MediaTrack != NULL) {
    m_MediaTimeScale = m_MediaTrack->GetMediaTimeScale();
}
```
