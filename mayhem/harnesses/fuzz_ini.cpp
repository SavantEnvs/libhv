// INI config text -> IniParser::LoadFromMem (cpputil/iniparser.cpp), then query and dump.
#include <string>
#include "iniparser.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string s((const char*)data, size);
    IniParser ini;
    if (ini.LoadFromMem(s.c_str()) != 0) return 0;
    for (const auto& sec : ini.GetSections()) {
        for (const auto& key : ini.GetKeys(sec)) {
            (void)ini.GetValue(key, sec);
        }
    }
    (void)ini.GetValue("port");
    (void)ini.DumpString();
    return 0;
}
