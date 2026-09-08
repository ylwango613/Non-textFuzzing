All four valid input combinations produce writes within the allocated buffer. The extradata writes max at offset 63 (within 144 bytes). Dimension validation on line 31 correctly uses C operator precedence (`&&` before `||`) to allow only 720×486 and 720×576.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
