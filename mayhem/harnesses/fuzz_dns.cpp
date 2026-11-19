// DNS messages (protocol/dns.c): dns_unpack of a response packet, then dns_pack of what was
// parsed, then dns_free.
#include <stdlib.h>
#include <string.h>
#include <vector>
extern "C" {
#include "dns.h"
}
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 65535) return -1;  // a DNS message is at most 64 KiB (RFC 1035 TCP length field)
    std::vector<char> buf(data, data + size);
    dns_t dns;
    memset(&dns, 0, sizeof(dns));
    int ret = dns_unpack(buf.data(), (int)buf.size(), &dns);
    if (ret > 0) {
        std::vector<char> out(65536);
        dns_pack(&dns, out.data(), (int)out.size());
    }
    dns_free(&dns);
    return 0;
}
