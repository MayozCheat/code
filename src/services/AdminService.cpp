#include "AdminService.h"
#include "../db/DbPool.h"
#include "../db/DbConfig.h"
#include "../utils/Token.h"

using nlohmann::json;

static std::string makeCardKey(const std::string& prefix) {
    // 用 Token::randomHex 生成随机 hex，再加前缀增强可读性
    std::string rnd = Token::randomHex(AppConfig::CARD_KEY_BYTES); // bytes->hex len=bytes*2
    if (rnd.empty()) return "";
    if (prefix.empty()) return rnd;
    return prefix + "-" + rnd;
}

AdminService::AdminService(DbPool& pool) : pool_(pool) {}

json AdminService::createCards(
    const std::string& adminKey,
    int durationDays,
    int count,
    const std::string& prefix,
    const std::string& ip
) {
    // 1) 管理口令校验
    if (adminKey != AppConfig::ADMIN_KEY) {
        return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    }

    // 参数限制：避免有人传 count=100000 搞崩你
    if (durationDays <= 0 || durationDays > 3650) {
        return json{ {"ok", false}, {"err", "bad_days"} };
    }
    if (count <= 0 || count > 200) {
        return json{ {"ok", false}, {"err", "bad_count"} };
    }

    auto conn = pool_.acquire();

    try {
        // 开事务：批量插入更稳
        std::vector<std::string> cards;
        cards.reserve((size_t)count);

        std::unique_ptr<sql::PreparedStatement> psIns(
            conn->prepareStatement(
                "INSERT INTO cards(card_key, duration_days, is_used) VALUES(?, ?, 0)"
            )
        );

        for (int i = 0; i < count; ++i) {
            // 生成卡密（若碰到重复则重试几次）
            std::string key;
            for (int t = 0; t < 5; ++t) {
                key = makeCardKey(prefix);
                if (!key.empty()) break;
            }
            if (key.empty()) {
                conn->rollback();
                pool_.release(std::move(conn));
                return json{ {"ok", false}, {"err", "card_gen_failed"} };
            }

            psIns->setString(1, key);
            psIns->setInt(2, durationDays);
            psIns->executeUpdate();

            cards.push_back(key);
        }

        // 写日志（可选，但建议）
        // logs: action=admin_create_cards detail=days=..,count=..
        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement(
                "INSERT INTO logs(user_id, action, detail, ip) VALUES(NULL, ?, ?, ?)"
            )
        );
        psLog->setString(1, "admin_create_cards");
        psLog->setString(2, "days=" + std::to_string(durationDays) + ",count=" + std::to_string(count));
        psLog->setString(3, ip);
        psLog->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));

        json data;
        data["cards"] = cards;
        return json{ {"ok", true}, {"data", data} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}
nlohmann::json AdminService::listCards(const std::string& adminKey,
    int page,
    int pageSize,
    int isUsed,
    const std::string& keyword,
    const std::string& ip) {
    using nlohmann::json;

    if (adminKey != AppConfig::ADMIN_KEY) {
        return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    }

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 10;
    if (pageSize > 100) pageSize = 100;

    int offset = (page - 1) * pageSize;

    auto conn = pool_.acquire();
    try {
        // 组装 WHERE（用参数绑定）
        std::string where = " WHERE 1=1 ";
        if (isUsed == 0 || isUsed == 1) where += " AND is_used=? ";
        if (!keyword.empty()) where += " AND card_key LIKE ? ";

        // total
        {
            std::unique_ptr<sql::PreparedStatement> psTotal(
                conn->prepareStatement(("SELECT COUNT(*) AS c FROM cards" + where).c_str())
            );

            int idx = 1;
            if (isUsed == 0 || isUsed == 1) psTotal->setInt(idx++, isUsed);
            if (!keyword.empty()) psTotal->setString(idx++, "%" + keyword + "%");

            std::unique_ptr<sql::ResultSet> rs(psTotal->executeQuery());
            rs->next();
            long long total = rs->getInt64("c");

            // list
            std::unique_ptr<sql::PreparedStatement> psList(
                conn->prepareStatement((
                    "SELECT id, card_key, duration_days, is_used, used_by, used_time, create_time, note "
                    "FROM cards" + where +
                    " ORDER BY id DESC LIMIT ? OFFSET ?"
                    ).c_str())
            );

            idx = 1;
            if (isUsed == 0 || isUsed == 1) psList->setInt(idx++, isUsed);
            if (!keyword.empty()) psList->setString(idx++, "%" + keyword + "%");
            psList->setInt(idx++, pageSize);
            psList->setInt(idx++, offset);

            std::unique_ptr<sql::ResultSet> rs2(psList->executeQuery());

            json items = json::array();
            while (rs2->next()) {
                json row;
                row["id"] = rs2->getInt("id");
                row["card_key"] = rs2->getString("card_key");
                row["duration_days"] = rs2->getInt("duration_days");
                row["is_used"] = rs2->getInt("is_used");
                row["used_by"] = rs2->isNull("used_by") ? json(nullptr) : json(rs2->getInt("used_by"));
                row["used_time"] = rs2->isNull("used_time") ? json(nullptr) : json(rs2->getString("used_time"));
                row["create_time"] = rs2->isNull("create_time") ? json(nullptr) : json(rs2->getString("create_time"));
                row["note"] = rs2->isNull("note") ? "" : rs2->getString("note");
                items.push_back(row);
            }

            pool_.release(std::move(conn));

            return json{
                {"ok", true},
                {"data", {
                    {"page", page},
                    {"page_size", pageSize},
                    {"total", total},
                    {"items", items}
                }}
            };
        }
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return nlohmann::json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

nlohmann::json AdminService::listLogs(const std::string& adminKey,
    int page,
    int pageSize,
    const std::string& action,
    int userId,
    const std::string& ipKeyword,
    const std::string& ip) {
    using nlohmann::json;

    if (adminKey != AppConfig::ADMIN_KEY) {
        return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    }

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 10;
    if (pageSize > 200) pageSize = 200;

    int offset = (page - 1) * pageSize;

    auto conn = pool_.acquire();
    try {
        std::string where = " WHERE 1=1 ";
        if (!action.empty()) where += " AND action=? ";
        if (userId >= 0) where += " AND user_id=? ";
        if (!ipKeyword.empty()) where += " AND ip LIKE ? ";

        // total
        std::unique_ptr<sql::PreparedStatement> psTotal(
            conn->prepareStatement(("SELECT COUNT(*) AS c FROM logs" + where).c_str())
        );

        int idx = 1;
        if (!action.empty()) psTotal->setString(idx++, action);
        if (userId >= 0) psTotal->setInt(idx++, userId);
        if (!ipKeyword.empty()) psTotal->setString(idx++, "%" + ipKeyword + "%");

        std::unique_ptr<sql::ResultSet> rs(psTotal->executeQuery());
        rs->next();
        long long total = rs->getInt64("c");

        // list
        std::unique_ptr<sql::PreparedStatement> psList(
            conn->prepareStatement((
                "SELECT id, user_id, action, detail, ip, created_at "
                "FROM logs" + where +
                " ORDER BY id DESC LIMIT ? OFFSET ?"
                ).c_str())
        );

        idx = 1;
        if (!action.empty()) psList->setString(idx++, action);
        if (userId >= 0) psList->setInt(idx++, userId);
        if (!ipKeyword.empty()) psList->setString(idx++, "%" + ipKeyword + "%");
        psList->setInt(idx++, pageSize);
        psList->setInt(idx++, offset);

        std::unique_ptr<sql::ResultSet> rs2(psList->executeQuery());

        json items = json::array();
        while (rs2->next()) {
            json row;
            row["id"] = rs2->getInt("id");
            row["user_id"] = rs2->isNull("user_id") ? json(nullptr) : json(rs2->getInt("user_id"));
            row["action"] = rs2->getString("action");
            row["detail"] = rs2->isNull("detail") ? "" : rs2->getString("detail");
            row["ip"] = rs2->isNull("ip") ? "" : rs2->getString("ip");
            row["created_at"] = rs2->isNull("created_at") ? json(nullptr) : json(rs2->getString("created_at"));
            items.push_back(row);
        }

        pool_.release(std::move(conn));

        return json{
            {"ok", true},
            {"data", {
                {"page", page},
                {"page_size", pageSize},
                {"total", total},
                {"items", items}
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
nlohmann::json AdminService::listUsers(const std::string& adminKey,
    int page, int pageSize,
    const std::string& keyword,
    const std::string& ip) {
    using nlohmann::json;

    if (adminKey != AppConfig::ADMIN_KEY) return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 10;
    if (pageSize > 100) pageSize = 100;
    int offset = (page - 1) * pageSize;

    auto conn = pool_.acquire();
    try {
        std::string where = " WHERE 1=1 ";
        if (!keyword.empty()) where += " AND (username LIKE ? OR machine_code LIKE ?) ";

        // total
        std::unique_ptr<sql::PreparedStatement> psTotal(
            conn->prepareStatement(("SELECT COUNT(*) AS c FROM users" + where).c_str())
        );
        int idx = 1;
        if (!keyword.empty()) {
            psTotal->setString(idx++, "%" + keyword + "%");
            psTotal->setString(idx++, "%" + keyword + "%");
        }
        auto rsT = std::unique_ptr<sql::ResultSet>(psTotal->executeQuery());
        rsT->next();
        long long total = rsT->getInt64("c");

        // list（不返回 password_hash）
        std::unique_ptr<sql::PreparedStatement> psList(
            conn->prepareStatement((
                "SELECT id, username, status, machine_code, expire_time "
                "FROM users" + where +
                " ORDER BY id DESC LIMIT ? OFFSET ?"
                ).c_str())
        );
        idx = 1;
        if (!keyword.empty()) {
            psList->setString(idx++, "%" + keyword + "%");
            psList->setString(idx++, "%" + keyword + "%");
        }
        psList->setInt(idx++, pageSize);
        psList->setInt(idx++, offset);

        auto rs = std::unique_ptr<sql::ResultSet>(psList->executeQuery());
        json items = json::array();
        while (rs->next()) {
            json row;
            row["id"] = rs->getInt("id");
            row["username"] = rs->getString("username");
            row["status"] = rs->getInt("status");
            row["machine_code"] = rs->isNull("machine_code") ? json(nullptr) : json(rs->getString("machine_code"));
            row["expire_time"] = rs->isNull("expire_time") ? json(nullptr) : json(rs->getString("expire_time"));
            items.push_back(row);
        }

        pool_.release(std::move(conn));
        return json{ {"ok", true}, {"data", {{"page", page}, {"page_size", pageSize}, {"total", total}, {"items", items}}} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

nlohmann::json AdminService::setUserStatus(const std::string& adminKey,
    int userId,
    int status,
    const std::string& ip) {
    using nlohmann::json;
    if (adminKey != AppConfig::ADMIN_KEY) return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    if (userId <= 0) return json{ {"ok", false}, {"err", "bad_user_id"} };
    if (!(status == 0 || status == 1)) return json{ {"ok", false}, {"err", "bad_status"} };

    auto conn = pool_.acquire();
    try {
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement("UPDATE users SET status=? WHERE id=?")
        );
        ps->setInt(1, status);
        ps->setInt(2, userId);
        int n = ps->executeUpdate();

        // log
        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement("INSERT INTO logs(user_id, action, detail, ip) VALUES(NULL, ?, ?, ?)")
        );
        psLog->setString(1, "admin_user_status");
        psLog->setString(2, "user_id=" + std::to_string(userId) + ",status=" + std::to_string(status));
        psLog->setString(3, ip);
        psLog->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));

        return (n > 0) ? json{ {"ok", true} } : json{ {"ok", false}, {"err", "user_not_found"} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

nlohmann::json AdminService::resetUserMachine(const std::string& adminKey,
    int userId,
    const std::string& ip) {
    using nlohmann::json;
    if (adminKey != AppConfig::ADMIN_KEY) return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    if (userId <= 0) return json{ {"ok", false}, {"err", "bad_user_id"} };

    auto conn = pool_.acquire();
    try {
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement("UPDATE users SET machine_code=NULL WHERE id=?")
        );
        ps->setInt(1, userId);
        int n = ps->executeUpdate();

        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement("INSERT INTO logs(user_id, action, detail, ip) VALUES(NULL, ?, ?, ?)")
        );
        psLog->setString(1, "admin_reset_machine");
        psLog->setString(2, "user_id=" + std::to_string(userId));
        psLog->setString(3, ip);
        psLog->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));

        return (n > 0) ? json{ {"ok", true} } : json{ {"ok", false}, {"err", "user_not_found"} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

nlohmann::json AdminService::addUserDays(const std::string& adminKey,
    int userId,
    int days,
    const std::string& ip) {
    using nlohmann::json;
    if (adminKey != AppConfig::ADMIN_KEY) return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    if (userId <= 0) return json{ {"ok", false}, {"err", "bad_user_id"} };
    if (days == 0 || days < -3650 || days > 3650) return json{ {"ok", false}, {"err", "bad_days"} };

    auto conn = pool_.acquire();
    try {
        // 如果 expire_time 为空：从 NOW() 开始加
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement(
                "UPDATE users "
                "SET expire_time = CASE "
                "  WHEN expire_time IS NULL OR expire_time < NOW() THEN DATE_ADD(NOW(), INTERVAL ? DAY) "
                "  ELSE DATE_ADD(expire_time, INTERVAL ? DAY) "
                "END "
                "WHERE id=?"
            )
        );
        ps->setInt(1, days);
        ps->setInt(2, days);
        ps->setInt(3, userId);
        int n = ps->executeUpdate();

        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement("INSERT INTO logs(user_id, action, detail, ip) VALUES(NULL, ?, ?, ?)")
        );
        psLog->setString(1, "admin_add_days");
        psLog->setString(2, "user_id=" + std::to_string(userId) + ",days=" + std::to_string(days));
        psLog->setString(3, ip);
        psLog->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));

        return (n > 0) ? json{ {"ok", true} } : json{ {"ok", false}, {"err", "user_not_found"} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

nlohmann::json AdminService::disableCard(const std::string& adminKey,
    const std::string& cardKey,
    const std::string& reason,
    const std::string& ip) {
    using nlohmann::json;
    if (adminKey != AppConfig::ADMIN_KEY) return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    if (cardKey.empty()) return json{ {"ok", false}, {"err", "bad_card_key"} };

    auto conn = pool_.acquire();
    try {
        // 只允许把 未使用(0) 的卡作废为 2；已使用(1) 不建议改（避免售后纠纷时追溯困难）
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement("UPDATE cards SET is_used=2, note=? WHERE card_key=? AND is_used=0")
        );
        std::string note = reason.empty() ? "disabled" : ("disabled: " + reason);
        ps->setString(1, note);
        ps->setString(2, cardKey);
        int n = ps->executeUpdate();

        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement("INSERT INTO logs(user_id, action, detail, ip) VALUES(NULL, ?, ?, ?)")
        );
        psLog->setString(1, "admin_disable_card");
        psLog->setString(2, "card=" + cardKey + ",reason=" + (reason.empty() ? "-" : reason));
        psLog->setString(3, ip);
        psLog->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));

        if (n <= 0) return json{ {"ok", false}, {"err", "card_not_found_or_not_unused"} };
        return json{ {"ok", true} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}

nlohmann::json AdminService::setCardNote(const std::string& adminKey,
    const std::string& cardKey,
    const std::string& note,
    const std::string& ip) {
    using nlohmann::json;
    if (adminKey != AppConfig::ADMIN_KEY) return json{ {"ok", false}, {"err", "admin_unauthorized"} };
    if (cardKey.empty()) return json{ {"ok", false}, {"err", "bad_card_key"} };

    auto conn = pool_.acquire();
    try {
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement("UPDATE cards SET note=? WHERE card_key=?")
        );
        ps->setString(1, note);
        ps->setString(2, cardKey);
        int n = ps->executeUpdate();

        std::unique_ptr<sql::PreparedStatement> psLog(
            conn->prepareStatement("INSERT INTO logs(user_id, action, detail, ip) VALUES(NULL, ?, ?, ?)")
        );
        psLog->setString(1, "admin_set_card_note");
        psLog->setString(2, "card=" + cardKey + ",note=" + note);
        psLog->setString(3, ip);
        psLog->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));

        if (n <= 0) return json{ {"ok", false}, {"err", "card_not_found"} };
        return json{ {"ok", true} };
    }
    catch (const sql::SQLException& e) {
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }
}
