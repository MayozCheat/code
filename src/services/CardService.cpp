#include "CardService.h"
#include "../db/DbPool.h"

using nlohmann::json;

CardService::CardService(DbPool& pool) : pool_(pool) {}

json CardService::activateCardByToken(
    const std::string& token,
    const std::string& machineCode,
    const std::string& cardKey,
    const std::string& ip
) {
    auto conn = pool_.acquire();

    try {
        // 1) 校验 token 并取 user_id（并发安全：FOR UPDATE 可选，这里不锁 session）
        std::unique_ptr<sql::PreparedStatement> psSess(
            conn->prepareStatement(
                "SELECT user_id FROM sessions "
                "WHERE token=? AND expire_at > NOW() LIMIT 1"
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

        // 2) 查用户状态、机器码
        std::unique_ptr<sql::PreparedStatement> psUser(
            conn->prepareStatement(
                "SELECT status, machine_code FROM users WHERE id=? LIMIT 1"
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
            return json{ {"ok", false}, {"err", "banned"} };
        }

        std::string machineDb = rsUser->isNull("machine_code") ? "" : rsUser->getString("machine_code");
        if (!machineDb.empty() && machineDb != machineCode) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "machine_mismatch"} };
        }

        // 3) 查卡密（FOR UPDATE 防止并发重复用）
        std::unique_ptr<sql::PreparedStatement> psCard(
            conn->prepareStatement(
                "SELECT id, duration_days, is_used FROM cards WHERE card_key=? FOR UPDATE"
            )
        );
        psCard->setString(1, cardKey);
        std::unique_ptr<sql::ResultSet> rsCard(psCard->executeQuery());

        if (!rsCard->next()) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "card_not_found"} };
        }

        int cardId = rsCard->getInt("id");
        int days = rsCard->getInt("duration_days");
        int used = rsCard->getInt("is_used");
        if (used != 0) {
            conn->rollback();
            pool_.release(std::move(conn));
            return json{ {"ok", false}, {"err", "card_used"} };
        }

        // 4) 更新用户到期时间 + 首次绑定机器码
        std::unique_ptr<sql::PreparedStatement> psUpUser(
            conn->prepareStatement(
                "UPDATE users SET "
                "machine_code = IF(machine_code IS NULL OR machine_code='', ?, machine_code), "
                "expire_time  = DATE_ADD(CASE "
                "  WHEN expire_time IS NULL THEN NOW() "
                "  WHEN expire_time < NOW() THEN NOW() "
                "  ELSE expire_time END, INTERVAL ? DAY) "
                "WHERE id=?"
            )
        );
        psUpUser->setString(1, machineCode);
        psUpUser->setInt(2, days);
        psUpUser->setInt(3, userId);
        psUpUser->executeUpdate();

        // 5) 标记卡密已使用
        std::unique_ptr<sql::PreparedStatement> psUpCard(
            conn->prepareStatement(
                "UPDATE cards SET is_used=1, used_by=?, used_time=NOW() WHERE id=?"
            )
        );
        psUpCard->setInt(1, userId);
        psUpCard->setInt(2, cardId);
        psUpCard->executeUpdate();

        // 6) 写日志
        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement(
                "INSERT INTO logs(user_id, action, detail, ip) VALUES(?, ?, ?, ?)"
            )
        );
        psLog->setInt(1, userId);
        psLog->setString(2, "activate");
        psLog->setString(3, "card=" + cardKey);
        psLog->setString(4, ip);
        psLog->executeUpdate();

        // 7) 返回 expire_time
        std::unique_ptr<sql::PreparedStatement> psExp(
            conn->prepareStatement("SELECT expire_time FROM users WHERE id=?")
        );
        psExp->setInt(1, userId);
        std::unique_ptr<sql::ResultSet> rsExp(psExp->executeQuery());
        rsExp->next();
        std::string expire = rsExp->getString("expire_time");

        conn->commit();
        pool_.release(std::move(conn));

        return json{ {"ok", true}, {"data", json{{"expire_time", expire}}} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}
