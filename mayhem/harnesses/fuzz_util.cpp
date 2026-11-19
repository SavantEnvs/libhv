// Small string decoders: base64 (util/base64.c) and the hbase.c parsers (sizes, durations,
// booleans, wildcard patterns).
#include <string>
#include <vector>
#include "base64.h"
#include "hbase.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1 << 20) return -1;
    std::string s((const char*)data, size);
    std::vector<unsigned char> dec(BASE64_DECODE_OUT_SIZE(size) + 1);
    int n = hv_base64_decode(s.data(), (unsigned)size, dec.data());
    if (n > 0) {
        std::vector<char> enc(BASE64_ENCODE_OUT_SIZE(n) + 1);
        hv_base64_encode(dec.data(), (unsigned)n, enc.data());
    }
    (void)hv_parse_size(s.c_str());
    (void)hv_parse_time(s.c_str());
    (void)hv_getboolean(s.c_str());
    size_t half = s.size() / 2;
    std::string str = s.substr(0, half), pat = s.substr(half);
    (void)hv_wildcard_match(str.c_str(), pat.c_str());
    return 0;
}
