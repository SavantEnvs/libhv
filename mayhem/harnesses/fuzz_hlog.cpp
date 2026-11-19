// hlog formatting (base/hlog.c logger_print): the custom-format directive switch, the default
// snprintf path (empty format) and the max_bufsize truncation of a long message.
// Input:
//   bytes 0-1  extra buffer size (0..1023) on top of the format's own minimum (below)
//   byte 2     bit 0 color, bits 1.. level (DEBUG..FATAL)
//   byte 3     0xFF: keep the default format; else N = byte % 64 format tokens follow
//   N bytes    format tokens: 0..11 -> one of hlog's documented directives (hlog.h:90-104),
//              any other byte -> that literal byte ('%' is rejected: a lone '%' is not a directive)
//   rest       the message, printed through "%s"
//
// Buffer size precondition: logger_print writes the color prefix and every directive except %s
// without a bounds check (hlog.c:452-506 checks `len >= bufsize` only after each directive), so a
// bufsize smaller than the format's own fixed expansion is a misconfiguration, not a message
// problem. The buffer is therefore at least color prefix + fixed expansion + 1; everything past
// that, including the %s message and whatever follows it, is fuzzed.
#include <stdint.h>
#include <string.h>
#include <string>
#include "hlog.h"

static int g_len;
static void sink(int, const char*, int len) { g_len += len; }

struct Directive { const char* text; int width; };
static const Directive kDirectives[] = {
    {"%y", 4}, {"%m", 2}, {"%d", 2}, {"%H", 2}, {"%M", 2}, {"%S", 2},
    {"%z", 3}, {"%Z", 6}, {"%l", 1}, {"%L", 5}, {"%s", 0}, {"%%", 1},
};
static const int kNumDirectives = sizeof(kDirectives) / sizeof(kDirectives[0]);
static const int kMaxColor = 8;     // longest LOG_LEVEL_MAP color, "\033[41;37m"
static const size_t kMaxFormat = 63; // logger_set_format keeps sizeof(format)-1 = 63 chars

// fixed (non-%s) output width of a format made of hlog directives and literals
static int fixed_width(const char* f) {
    int w = 0;
    for (; *f; ++f) {
        if (*f != '%') { ++w; continue; }
        ++f;
        for (int i = 0; i < kNumDirectives; ++i)
            if (kDirectives[i].text[1] == *f) { w += kDirectives[i].width; break; }
    }
    return w;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return -1;
    unsigned int extra = ((unsigned)data[0] << 8 | data[1]) % 1024;
    int color = data[2] & 1;
    int level = LOG_LEVEL_DEBUG + ((data[2] >> 1) % 5);
    bool keep_default = data[3] == 0xFF;
    size_t ntok = keep_default ? 0 : data[3] % 64;
    size_t off = 4;
    std::string format;
    if (!keep_default) {
        if (size < off + ntok) return -1;
        for (size_t i = 0; i < ntok; ++i) {
            uint8_t b = data[off + i];
            if (b == '%') return -1;
            std::string tok = b < kNumDirectives ? std::string(kDirectives[b].text)
                                                 : std::string(1, (char)b);
            if (format.size() + tok.size() > kMaxFormat) break;
            format += tok;
        }
        off += ntok;
    }
    std::string msg((const char*)data + off, size - off);

    logger_t* l = logger_create();
    logger_set_handler(l, sink);
    logger_set_level(l, LOG_LEVEL_DEBUG);
    if (!keep_default) logger_set_format(l, format.c_str());
    // default format = hlog.c DEFAULT_LOG_FORMAT
    int fixed = fixed_width(keep_default ? "%y-%m-%d %H:%M:%S.%z %L %s" : format.c_str());
    if (!keep_default && format.empty()) fixed = 30; // "%04d-%02d-%02d %02d:%02d:%02d.%03d %s "
    logger_set_max_bufsize(l, kMaxColor + fixed + 1 + extra);
    logger_enable_color(l, color);
    logger_print(l, level, "%s", msg.c_str());
    logger_destroy(l);
    return 0;
}
