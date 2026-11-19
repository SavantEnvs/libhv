// RESP replies from a Redis server -> hv::RedisParser (redis/RedisMessage.cpp), each reply
// re-encoded with RedisEncodeReply.
#include <string>
#include "RedisMessage.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    hv::RedisParser parser;
    size_t off = 0;
    // Feed in two halves so a reply split across reads is exercised.
    size_t half = size / 2;
    off += parser.Feed((const char*)data, half);
    if (!parser.HasError()) parser.Feed((const char*)data + half, size - half);
    int n = 0;
    while (parser.HasReply() && n++ < 10000) {
        hv::RedisReply reply = parser.NextReply();
        std::string enc = hv::RedisEncodeReply(reply);
        (void)enc;
    }
    (void)off;
    return 0;
}
