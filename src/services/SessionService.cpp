#include "SessionService.h"
#include "../db/DbPool.h"
#include "../utils/Token.h"

using nlohmann::json;

SessionService::SessionService(DbPool& pool) : pool_(pool) {}

json SessionService::login(const std::string& username, const std::string& password, const std::string& ip) {
    auto conn = pool_.acquire();
    try {
        // 1) 验证用户名+密码（pass_hash=SHA2）
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement(
                "SELECT id, status FROM users "
                "WHERE username=? AND pass_hash=SHA2(?,256) LIMIT 1"
            )
        );
        ps->setString(1, username);
        ps->setString(2, password);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());

        if (!rs->next()) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "bad_user_or_password"} };
        }

        int userId = rs->getInt("id");
        int status = rs->getInt("status");
        if (status != 1) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "banned"} };
        }

        // 2) 生成 token
        std::string token = Token::randomHex(32); // 64 hex chars
        if (token.empty()) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "token_gen_failed"} };
        }

        // 3) 写 sessions（有效期 24 小时）
        //   用 SQL 计算 expire_at，避免本机时区/格式化麻烦
        std::unique_ptr<sql::PreparedStatement> psIns(
            conn->prepareStatement(
                "INSERT INTO sessions(user_id, token, expire_at) "
                "VALUES(?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))"
            )
        );
        psIns->setInt(1, userId);
        psIns->setString(2, token);
        psIns->executeUpdate();

        // 4) 读回 expire_at
        std::unique_ptr<sql::PreparedStatement> psSel(
            conn->prepareStatement("SELECT expire_at FROM sessions WHERE token=? LIMIT 1")
        );
        psSel->setString(1, token);
        std::unique_ptr<sql::ResultSet> rs2(psSel->executeQuery());
        rs2->next();
        std::string expireAt = rs2->getString("expire_at");

        conn->commit();
        pool_.release(std::move(conn));

        return json{
            {"ok", true},
            {"data", json{{"token", token}, {"expire_at", expireAt}}}
        };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

json SessionService::validateToken(const std::string& token) {
    auto conn = pool_.acquire();
    try {
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement(
                "SELECT user_id, expire_at FROM sessions "
                "WHERE token=? AND expire_at > NOW() LIMIT 1"
            )
        );
        ps->setString(1, token);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());

        if (!rs->next()) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "token_invalid_or_expired"} };
        }

        int userId = rs->getInt("user_id");
        std::string expireAt = rs->getString("expire_at");

        // 只读，不一定需要 commit
        pool_.release(std::move(conn));

        return json{
            {"ok", true},
            {"data", json{{"user_id", userId}, {"expire_at", expireAt}}}
        };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}
