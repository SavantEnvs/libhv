// WebSocket frames from a peer -> WebSocketParser (websocket_parser.c frame header/length/mask
// decoding, WebSocketParser.cpp fragment reassembly). Fed once whole, then again with the
// first byte as chunk size so frames split across reads are covered.
#include <string>
#include "WebSocketParser.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

static size_t g_total;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return -1;
    size_t chunk = data[0] ? data[0] : size;
    data++; size--;
    g_total = 0;
    {
        WebSocketParser ws;
        ws.onMessage = [](int opcode, const std::string& msg) { g_total += msg.size() + opcode; };
        ws.FeedRecvData((const char*)data, size);
    }
    {
        WebSocketParser ws;
        ws.onMessage = [](int opcode, const std::string& msg) { g_total += msg.size() + opcode; };
        size_t off = 0;
        while (off < size) {
            size_t n = size - off < chunk ? size - off : chunk;
            if (ws.FeedRecvData((const char*)data + off, n) != (int)n) break;
            off += n;
        }
    }
    return 0;
}
