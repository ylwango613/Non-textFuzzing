After exhaustively analyzing all code paths in `io-xbm.c`:

**Group 1 (lines 1-278, `read_bitmap_file_data`):**
- `size = bytes_per_line * hh` overflow check at line 238 is mathematically sound: truncated/wrapped product divided by `bytes_per_line` will always differ from `hh`.
- version10p write loop: `bytes_per_line` is provably always even for version10p=1 (ww%16∈{1..8}→padding=1 making odd+(1)=even; ww%16∈{9..15,0}→padding=0 and (ww+7)/8 is even), so size is even and loop writes exactly `size` bytes — no OOB.
- Non-version10p loop: straightforward byte-by-byte write of exactly `size` bytes.
- sscanf targets: `name_and_type[255]`, line bounded to 254 chars by `fgets(line, MAX_SIZE=255, …)` and strlen check — no overflow.

**Group 2 (lines 282-361, `gdk_pixbuf__xbm_image_load_real`):**
- Pixel write loop `pixels[x*3+0]`: gdk_pixbuf_new (gdk-pixbuf.c:449–450) guards `rowstride = width*channels` with `rowstride/channels != width || rowstride+3 < 0` → returns NULL if overflow. NULL is checked at line 308. For any non-NULL pixbuf, width ≤ ~715827881, so max `x*3 = 2147483640 < INT_MAX` — no signed overflow in the index.
- `ptr` reads at most `h * ceil(w/8) ≤ h * bytes_per_line = size` bytes from `data` — always within bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
