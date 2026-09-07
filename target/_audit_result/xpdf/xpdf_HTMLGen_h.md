Line 874 confirms that `TextWord::font = ch->font` — the word takes its font from the first char. This means form field words (with `formFieldFont`) are caught by the check at line 697, and regular words always have fonts in `TextPage::fonts` (added via `updateFont()`). The `fontScales[i]` OOB has no reachable exploit path from a crafted PDF.

After comprehensive analysis of HTMLGen.h and HTMLGen.cc:

- **`fontScales[i]` OOB**: Latent missing bounds check, but unreachable from crafted PDF — form field words are always caught before font search, regular words always have fonts in the list.
- **Bitmap erase**: Double→int overflow guarded by subsequent range checks that prevent memset execution.
- **Base64 encoder**: All array indices bounded by `& 0x3f` (max 63), array size 65 — safe.
- **Private Unicode map**: Index range `[0, 262]`, array size 263 — safe.
- **substFonts array**: Max index 11, array size 16 — safe.
- **Metadata injection**: All metadata values routed through `appendUTF8` which does no allocation without proper GString growth.
- **NULL pointer via formFieldFont**: `convertFormFields && getFontInfo()==NULL` path — `convertFormFields` is AND'd first (short-circuit), and `addSpecialChar` only fires when `form != NULL`, meaning `formFieldFont != NULL` is guaranteed in that branch.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
