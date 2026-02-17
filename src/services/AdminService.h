#pragma once
#include <string>
#include "json.hpp"

class DbPool;

class AdminService {
public:
    explicit AdminService(DbPool& pool);

    // 生成 count 张卡密，durationDays 天
    nlohmann::json createCards(
        const std::string& adminKey,
        int durationDays,
        int count,
        const std::string& prefix,
        const std::string& ip
    );
    nlohmann::json listCards(const std::string& adminKey,
        int page,
        int pageSize,
        int isUsed,                 // -1=全部, 0=未用, 1=已用
        const std::string& keyword, // card_key 模糊搜索
        const std::string& ip);

    nlohmann::json listLogs(const std::string& adminKey,
        int page,
        int pageSize,
        const std::string& action,   // ""=全部
        int userId,                  // -1=全部
        const std::string& ipKeyword,// ""=全部，按ip模糊
        const std::string& ip);

    nlohmann::json listUsers(const std::string& adminKey,
        int page, int pageSize,
        const std::string& keyword,
        const std::string& ip);

    nlohmann::json setUserStatus(const std::string& adminKey,
        int userId,
        int status,
        const std::string& ip);

    nlohmann::json resetUserMachine(const std::string& adminKey,
        int userId,
        const std::string& ip);

    nlohmann::json addUserDays(const std::string& adminKey,
        int userId,
        int days,
        const std::string& ip);

    nlohmann::json disableCard(const std::string& adminKey,
        const std::string& cardKey,
        const std::string& reason,
        const std::string& ip);

    nlohmann::json setCardNote(const std::string& adminKey,
        const std::string& cardKey,
        const std::string& note,
        const std::string& ip);

private:
    DbPool& pool_;
};
