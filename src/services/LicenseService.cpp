#include "LicenseService.h"
#include "../db/DbPool.h"

using nlohmann::json;

LicenseService::LicenseService(DbPool& pool) : pool_(pool) {}

json LicenseService::check(const std::string& token, const std::string& machineCode) {
    auto conn = pool_.acquire();

    try {
        // 1) token -> user_id
        std::unique_ptr<sql::PreparedStatement> psSess(
            conn->prepareStatement(
                "SELECT user_id FROM sessions WHERE token=? AND expire_at > NOW() LIMIT 1"
            )
        );
        psSess->setString(1, token);
        std::unique_ptr<sql::ResultSet> rsSess(psSess->executeQuery());

        if (!rsSess->next()) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "token_invalid_or_expired"} };
        }

        int userId = rsSess->getInt("user_id");

        // 2) 查用户授权状态
        std::unique_ptr<sql::PreparedStatement> psUser(
            conn->prepareStatement(
                "SELECT status, machine_code, expire_time FROM users WHERE id=? LIMIT 1"
            )
        );
        psUser->setInt(1, userId);
        std::unique_ptr<sql::ResultSet> rsUser(psUser->executeQuery());

        if (!rsUser->next()) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "user_not_found"} };
        }

        int status = rsUser->getInt("status");
        if (status != 1) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", true}, {"data", json{{"valid", false}, {"reason", "banned"}}} };
        }

        std::string machineDb = rsUser->isNull("machine_code") ? "" : rsUser->getString("machine_code");
        if (!machineDb.empty() && machineDb != machineCode) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", true}, {"data", json{{"valid", false}, {"reason", "machine_mismatch"}}} };
        }

        // 3) 判断是否过期（在 SQL 里做最简单）
        // expire_time 为空视为无效
        if (rsUser->isNull("expire_time")) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", true}, {"data", json{{"valid", false}, {"reason", "no_expire"}}} };
        }

        std::string expire = rsUser->getString("expire_time");

        // 4) 用 SQL 比较是否仍有效（避免 C++ 解析时间）
        std::unique_ptr<sql::PreparedStatement> psValid(
            conn->prepareStatement(
                "SELECT (expire_time > NOW()) AS v FROM users WHERE id=?"
            )
        );
        psValid->setInt(1, userId);
        std::unique_ptr<sql::ResultSet> rsV(psValid->executeQuery());
        rsV->next();
        int v = rsV->getInt("v");

        pool_.release(std::move(conn));

        return json{
            {"ok", true},
            {"data", json{
                {"valid", v == 1},
                {"expire_time", expire},
                {"status", status}
            }}
        };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}
