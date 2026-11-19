// multipart/form-data bodies with a peer-chosen boundary (http/multipart_parser.c +
// http_content.cpp), plus the JSON body parser. Input: first line = boundary, rest = body.
#include <string>
#include "http_content.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string in((const char*)data, size);
    size_t nl = in.find('\n');
    if (nl == std::string::npos) return -1;
    std::string boundary = in.substr(0, nl);
    std::string body = in.substr(nl + 1);
    hv::MultiPart mp;
    if (hv::parse_multipart(body, mp, boundary.c_str()) == 0) {
        // dump_multipart() reads a part from disk when it names a filename but carries no
        // content; never let a fuzz input name a path on the host.
        for (auto it = mp.begin(); it != mp.end();) {
            if (!it->second.filename.empty() && it->second.content.empty()) it = mp.erase(it);
            else ++it;
        }
        (void)hv::dump_multipart(mp, boundary.c_str());
    }
    hv::Json j;
    std::string err;
    if (hv::parse_json(body.c_str(), j, err) == 0) (void)hv::dump_json(j);
    return 0;
}
