#pragma once
#include <string>
#include "json.hpp"

class DbPool;

class SessionService {
public:
    explicit SessionService(DbPool& pool);

    // 登录：成功返回 {ok:true,data:{token,expire_at}}；失败 {ok:false,err,...}
    nlohmann::json login(const std::string& username, const std::string& password, const std::string& ip);

    // 校验 token：成功返回 ok:true,data:{user_id,expire_at}; 失败 ok:false,err
    nlohmann::json validateToken(const std::string& token);

private:
    DbPool& pool_;
};
