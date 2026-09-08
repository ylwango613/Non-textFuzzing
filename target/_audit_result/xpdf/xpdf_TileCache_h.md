`TileCache` is confirmed to be a GUI-only viewer component — not reachable from `pdftotext`. Now let me summarize my full analysis of the file.

**Analysis summary of TileCache.h / TileCache.cc:**

**Batch 1 (lines 1–200):** Class declarations and OS-threading wrappers. `TileCacheThreadPool` allocates `threads` via `gmallocn(nThreads, sizeof(GThreadID))`. `gmallocn` has complete overflow protection (`nObjs >= INT_MAX / objSize` check). `nWorkerThreads` comes from application configuration, not PDF data.

**Batch 2 (lines 200–330):** Thread pool worker loop and `setActiveTileList`. State transitions use the mutex correctly. The only unsynchronized reads of `ct->state` are in the abort check callback (`abortCheckCbk`) — this is an intentional cancellation-flag pattern.

**Batch 3 (lines 330–559):** `getTileBitmap`, `flushCache`, `removeTile`, `rasterizeTile`. There is a data race: `rasterizeTile` reads `ct->state` at line 537 without the mutex, while the main thread can write `cachedTileCanceled` with the mutex held. The practical outcome is state inconsistency (tile ends up as `cachedTileFinished` instead of being removed), but no pointer misuse, double-free, or OOB write occurs. Memory lifecycle is sound: `CachedTileDesc` is only freed by the worker's own `removeTile`, or by `cache->del` under the mutex in `setActiveTileList` / `flushCache` / `cleanCache`. Destructor sequence (`flushCache(gFalse)` → `delete threadPool` (joins all workers) → `delete cache`) is correct.

**Reachability:** `TileCache` is a GUI tile-rendering cache used only by the xpdf viewer. pdftotext contains no reference to `TileCache` or `DisplayState`. No PDF-controlled data flows into any allocation path in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
