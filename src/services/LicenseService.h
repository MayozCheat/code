#pragma once
#include <string>
#include "json.hpp"

class DbPool;

class LicenseService {
public:
    explicit LicenseService(DbPool& pool);

    // token + machine_code -> valid/expire/status
    nlohmann::json check(const std::string& token, const std::string& machineCode);

private:
    DbPool& pool_;
};
