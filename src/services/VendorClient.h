#pragma once
#include <string>

struct VendorCheckResult {
    bool ok = false;
    std::string err;
    std::string expire_time;
    std::string raw;
};

class VendorClient {
public:
    static VendorCheckResult Check(const std::string& vendorUrl,
        const std::string& vendorKey,
        const std::string& vendorSecret,
        const std::string& machineCode,
        int timeoutMs = 5000);

    static void CheckOrExit(const std::string& vendorUrl,
        const std::string& vendorKey,
        const std::string& vendorSecret,
        const std::string& machineCode,
        int timeoutMs = 5000);
};
