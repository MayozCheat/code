#pragma once
#include <string>
#include "json.hpp"

class DbPool;

class SignService {
public:
    explicit SignService(DbPool& pool);

    // 返回 {ok:true} 或 {ok:false, err:"..."}
    nlohmann::json verify(
        const std::string& method,
        const std::string& path,
        const nlohmann::json& body);

private:
    DbPool& pool_;
};
