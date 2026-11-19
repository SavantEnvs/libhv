// HTTP/1 client side: raw response bytes from a server -> HttpParser (response half of
// http_parser.c, chunked decoding, Set-Cookie parsing) -> HttpResponse body parsing -> Dump.
#include <string>
#include "HttpParser.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return -1;
    size_t chunk = data[0] ? data[0] : size;
    data++; size--;

    HttpParser* parser = HttpParser::New(HTTP_CLIENT, HTTP_V1);
    if (!parser) return 0;
    HttpResponse res;
    parser->InitResponse(&res);
    size_t off = 0;
    while (off < size) {
        size_t n = size - off < chunk ? size - off : chunk;
        int nfeed = parser->FeedRecvData((const char*)data + off, n);
        if (nfeed != (int)n) break;
        off += n;
        if (parser->IsComplete()) break;
    }
    if (parser->IsComplete()) {
        res.ParseBody();
        (void)res.GetCookie("session");
        (void)res.GetHeader("Location");
        (void)res.Dump(true, true);
    }
    delete parser;
    return 0;
}
