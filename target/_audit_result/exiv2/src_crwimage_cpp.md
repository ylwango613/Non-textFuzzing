再帰パスを完全に確認しました。深度制限が存在しないことが確認できます。最終的な分析を行います。

**再帰パスの検証まとめ：**

`CiffHeader::read` (line 166) → `pRootDir_->readDirectory(pData+offset_, size-offset_, byteOrder_)` →
`CiffDirectory::readDirectory` (line 226): エントリをループし、`CiffDirectory` 型なら `m->read(pData, size, o, byteOrder)` →
`CiffDirectory::doRead` (line 212): `CiffComponent::doRead` 呼び出し後、**`readDirectory(pData + offset(), this->size(), byteOrder)`** を再帰的に呼び出す

保護された条件（`CiffComponent::doRead` line 189-197）：
- `offset_ < start` の場合: `size_ <= start - offset_` を強制 → 子サイズ ≤ `start` ≤ `parent_size - 10`
- 結果: 各再帰レベルで **`size` が少なくとも 10 バイト減少**

**無限再帰は防止済みだが、深い有限再帰（スタック枯渇）は防止されていない。**

再帰深度の上限: `initial_size / 10`
- 400KB ファイル → 最大 40,000 レベル × ~300 バイト/フレーム ≈ 12MB → 8MB スタックを超過

開発者は line 184-197 のコメントで「infinite recursion」のみを認識して対処しているが、深い有限再帰によるスタック枯渇は対処されていない。

## VULN: Stack Exhaustion via Deep Recursive CIFF Directory Parsing
- **漏洞类别**: memory-safety
- **函数**: CiffDirectory::readDirectory() / CiffDirectory::doRead()
- **行号**: 212-224 (doRead), 226-252 (readDirectory), 166-167 (CiffHeader::read entry)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr \<file\> → CrwImage::readMetadata() → CrwParser::decode() → CiffHeader::read() → CiffDirectory::readDirectory() → [per directory entry] CiffDirectory::doRead() → CiffDirectory::readDirectory() [递归, 无深度限制]
- **描述**: `CiffDirectory::readDirectory()` 与 `CiffDirectory::doRead()` 构成相互递归调用链。`CiffComponent::doRead()` 中的防护措施（第 189-197 行）仅阻止子目录数据区域与当前 10 字节目录项重叠（开发者注释明确说明只防"infinite recursion"），但未限制递归调用深度。对于 `DataLocId::valueData` 类型的子目录，当满足 `offset_ < start` 时，子目录 size 的约束为 `size_child ≤ start - offset_`，最大值为 `start ≤ parent_size - 10`。因此每一层递归只保证 `size` 至少减少 10 字节，对于足够大的文件，可在堆栈溢出前发生数万次递归。`CiffDirectory::doRead` 额外的检查 `this->offset() + this->size() > size` 亦无法阻止此路径。
- **触发条件**: 攻击者构造一个 ≥300KB 的畸形 CRW 文件，其 CIFF 目录结构深度嵌套：每个目录只有一个子目录条目（`dataLocation == valueData`），子目录的 `offset_=0`、`size_` 接近 `start`（即父目录大小减去约 10 字节），使得递归调用链可达到 `file_size/10` 的深度（例如 400KB 文件约 40,000 层）。系统默认栈为 8MB，每帧约 250-400 字节，从而触发栈溢出（SIGSEGV）。
- **安全影响**: 通过 SIGSEGV 导致 exiv2 进程崩溃（DoS）。若 exiv2 作为图像处理库嵌入 Web 服务，攻击者上传恶意 CRW 文件即可导致远程服务崩溃。在极端情况下，栈溢出可能覆盖相邻内存，造成潜在的内存破坏，但在有防护页的现代 Linux 系统上通常仅触发崩溃而非 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
