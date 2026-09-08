Line 428 confirms `tp->setStart(pData() + idx)` IS called — the conversation summary was incorrect. The null pointer dereference I was about to report does not exist.

After verifying the complete `addElement` implementation:
- `setStart()` is called at line 428, so `pStart_` is a valid pointer when `visitBinaryElement` reads it
- `setData()` is also called, so `pData_` and `size_` are both valid
- All other bounds checks (readTiffEntry, visitDirectory, visitSubIfd, setStrips) were confirmed correct in prior analysis

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
