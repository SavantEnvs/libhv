// HTTP/1 server side: raw request bytes -> HttpParser (http_parser.c, Http1Parser.cpp) ->
// HttpRequest url/body parsing (http_content.cpp: JSON, multipart, urlencoded) -> Dump.
// The first input byte selects the feed chunk size, so the incremental parser paths
// (headers or chunked bodies split across reads) are exercised too.
#include <string>
#include "HttpParser.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return -1;
    size_t chunk = data[0] ? data[0] : size;
    data++; size--;

    HttpParser* parser = HttpParser::New(HTTP_SERVER, HTTP_V1);
    if (!parser) return 0;
    HttpRequest req;
    parser->InitRequest(&req);
    size_t off = 0;
    while (off < size) {
        size_t n = size - off < chunk ? size - off : chunk;
        int nfeed = parser->FeedRecvData((const char*)data + off, n);
        if (nfeed != (int)n) break;
        off += n;
        if (parser->IsComplete()) break;
    }
    if (parser->IsComplete()) {
        req.ParseUrl();
        req.ParseBody();
        (void)req.Path();
        (void)req.GetHeader("Host");
        (void)req.GetCookie("session");
        (void)req.Dump(true, true);
    }
    parser->GetError();
    delete parser;
    return 0;
}
