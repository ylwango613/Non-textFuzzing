# VULN 001 — Analysis Notes

## 漏洞原理

**函数**: `gdk_pixbuf_apply_embedded_orientation()` in `gdk-pixbuf/gdk-pixbuf-util.c`

**漏洞位置**: Lines 327-337 (case 5 and case 7 of the switch statement)

```c
case 5:
    temp = gdk_pixbuf_rotate_simple (src, GDK_PIXBUF_ROTATE_CLOCKWISE);
    dest = gdk_pixbuf_flip (temp, TRUE);   // <-- temp may be NULL
    g_object_unref (temp);                 // <-- crash: unref of NULL
    break;
case 7:
    temp = gdk_pixbuf_rotate_simple (src, GDK_PIXBUF_ROTATE_CLOCKWISE);
    dest = gdk_pixbuf_flip (temp, FALSE);  // <-- temp may be NULL
    g_object_unref (temp);                 // <-- crash: unref of NULL
    break;
```

`gdk_pixbuf_rotate_simple()` calls `g_try_malloc()` internally; when the
image is large enough to exhaust available memory, it returns NULL instead of
a valid GdkPixbuf pointer. The return value is never checked before it is
passed to `gdk_pixbuf_flip()`. Inside `gdk_pixbuf_flip()`, the very first
operation is:

```c
g_return_val_if_fail (GDK_IS_PIXBUF (src), NULL);
```

`GDK_IS_PIXBUF(NULL)` is false, so with assertions enabled this returns NULL
silently. Without assertions (production build), the macro expands to a
GObject type check that dereferences `src->colorspace`, triggering a NULL
pointer dereference (SIGSEGV). Additionally, `g_object_unref(NULL)` itself is
undefined behavior and will typically crash.

**CWE**: CWE-476 (NULL Pointer Dereference)

---

## 为什么无法通过 gdk-pixbuf-pixdata 触发

`gdk-pixbuf-pixdata` 的 `main()` 函数（`gdk-pixbuf-pixdata.c`）只做以下
操作：

```c
pixbuf = gdk_pixbuf_new_from_file (infilename, &error);
...
free_me = gdk_pixdata_from_pixbuf (&pixdata, pixbuf, use_rle);
data = gdk_pixdata_serialize (&pixdata, &data_len);
g_file_set_contents (outfilename, (char *)data, data_len, &error);
```

调用链中 **完全没有** `gdk_pixbuf_apply_embedded_orientation()`。

JPEG loader (`io-jpeg.c`) 在解码时读取 EXIF 数据，但只将 orientation
值存储到 pixbuf 的元数据键 `"orientation"` 中：

```c
gdk_pixbuf_set_option (pixbuf, "orientation", buf);
```

实际的旋转/翻转变换只有应用程序显式调用
`gdk_pixbuf_apply_embedded_orientation()` 时才会发生。`gdk-pixbuf-pixdata`
从不进行这一调用，因此 EXIF orientation 字段对它完全透明，漏洞代码路径
永远不会被执行。

---

## 真实触发条件

要在真实环境中触发该漏洞，需要同时满足以下条件：

1. **应用程序必须调用 `gdk_pixbuf_apply_embedded_orientation()`**。
   该函数是公共 API，但并非所有程序都会调用它。

2. **图像 EXIF orientation 必须是 5 或 7**（转置类变换，需要先旋转再翻转）。
   Orientation 1-4 和 6/8 只触发单步操作，不经过 `temp` 中间指针路径。

3. **图像必须足够大以耗尽内存**，使 `gdk_pixbuf_rotate_simple()` 内部的
   `g_try_malloc()` 失败并返回 NULL。
   在 64-bit 系统上可通过 `ulimit -v` 限制虚拟内存来模拟此条件。

4. **构建时未启用 GLib 的断言终止**（即非 debug 构建），否则
   `g_return_val_if_fail` 会以警告返回 NULL 而非崩溃（但 `g_object_unref`
   仍会崩溃）。

---

## 真实触发场景举例

| 应用程序 | 相关行为 |
|----------|----------|
| **Nautilus (GNOME Files)** | 生成缩略图时调用 `gdk_pixbuf_apply_embedded_orientation()` 对图像进行校正，攻击者只需将恶意 JPEG 放入文件夹，Nautilus 自动预览即触发。 |
| **Eye of GNOME (eog)** | 打开图片时在显示前调用该函数处理 EXIF orientation，直接打开大图即触发。 |
| **GIMP** (老版本) | 通过 gdk-pixbuf 加载图像时可能调用此函数。 |
| **GTK+ 应用通用** | 任何使用 `gtk_image_new_from_file()` + `gdk_pixbuf_apply_embedded_orientation()` 的 GTK3 应用均受影响。 |

### 实验室复现方法（不使用 gdk-pixbuf-pixdata）

1. 编写一个最小 C 程序：
   ```c
   #include <gdk-pixbuf/gdk-pixbuf.h>
   int main(int argc, char *argv[]) {
       GdkPixbuf *pb = gdk_pixbuf_new_from_file(argv[1], NULL);
       GdkPixbuf *out = gdk_pixbuf_apply_embedded_orientation(pb);
       g_object_unref(pb);
       g_object_unref(out);
       return 0;
   }
   ```
2. 用 `ulimit -v 65536` 限制内存。
3. 传入包含 orientation=5 的大尺寸 JPEG。
4. 程序在 `gdk_pixbuf_flip(NULL, ...)` 处崩溃（SIGSEGV）。

---

## 总结

该漏洞是一个经典的未检查返回值缺陷（missing null-check after allocation）。
修复方案：在 `case 5` 和 `case 7` 中，在使用 `temp` 之前检查其是否为 NULL，
若为 NULL 则直接返回 NULL 或引用原始 src：

```c
case 5:
    temp = gdk_pixbuf_rotate_simple (src, GDK_PIXBUF_ROTATE_CLOCKWISE);
    if (temp == NULL) { dest = NULL; break; }   // fix
    dest = gdk_pixbuf_flip (temp, TRUE);
    g_object_unref (temp);
    break;
```
