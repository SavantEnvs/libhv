// URLs and query strings: HUrl::parse/dump/escape/unescape (cpputil/hurl.cpp), hv_parse_url
// (base/hbase.c), parse_query_params (http/http_content.cpp).
#include <string>
#include "hurl.h"
#include "hbase.h"
#include "http_content.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string s((const char*)data, size);
    HUrl url;
    if (url.parse(s)) (void)url.dump();
    std::string un = HUrl::unescape(s);
    std::string es = HUrl::escape(un);
    (void)hv::escapeURL(s);
    (void)hv::escapeHTML(s);
    hurl_t h;
    hv_parse_url(&h, s.c_str());
    hv::QueryParams q;
    if (hv::parse_query_params(s.c_str(), q) == 0) (void)hv::dump_query_params(q);
    return 0;
}
