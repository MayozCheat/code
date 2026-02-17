#include "PlatformVendorHandlers.h"
#include "HttpJson.h"
#include "AppConfig.h"

#include "../db/DbPool.h"       
#include "../services/SignService.h" 

#include <iostream>
#include <random>
#include <string>
#include <memory>

// mysql connector
#include <mysql/jdbc.h>

class DbPool;
class SignService;

using json = nlohmann::json;

static std::string randHex(size_t n) {
    static const char* h = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 15);
    std::string s; s.reserve(n);
    for (size_t i = 0; i < n; ++i) s.push_back(h[dis(gen)]);
    return s;
}

static std::string genVendorKey() {
    return std::string("VENDOR-") + randHex(24);
}
static std::string genVendorSecret() {
    return std::string("VS-") + randHex(64);
}

static bool RequireSign(SignService& signSvc,
    const std::string& method,
    const std::string& path,
    const json& in,
    httplib::Response& res) {
    auto vr = signSvc.verify(method, path, in);
    if (!vr.contains("ok") || !vr["ok"].get<bool>()) {
        HttpJson::reply(res, vr, 401);
        return false;
    }
    return true;
}

static bool RequireAdminKey(const json& in, httplib::Response& res) {
    if (!in.contains("admin_key") || !in["admin_key"].is_string()) {
        HttpJson::reply(res, HttpJson::fail("bad_admin_key"), 400);
        return false;
    }
    if (in["admin_key"].get<std::string>() != AppConfig::ADMIN_KEY) {
        HttpJson::reply(res, HttpJson::fail("admin_key_invalid"), 403);
        return false;
    }
    return true;
}



namespace PlatformVendorHandlers {

    void Register(httplib::Server& svr, DbPool& db, SignService& signSvc) {

        // -------------------------
        // POST /platform/vendor/create
        // -------------------------
        svr.Post("/platform/vendor/create", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                auto in = HttpJson::parse(req, res);
                if (in.is_null()) return;

                if (!RequireSign(signSvc, "POST", "/platform/vendor/create", in, res)) return;
                if (!RequireAdminKey(in, res)) return;

                if (!in.contains("days") || !in["days"].is_number_integer()) {
                    HttpJson::reply(res, HttpJson::fail("bad_days"), 400);
                    return;
                }
                int days = in["days"].get<int>();
                if (days <= 0 || days > 3650) {
                    HttpJson::reply(res, HttpJson::fail("days_out_of_range"), 400);
                    return;
                }

                std::string customer = in.value("customer_name", "");
                std::string note = in.value("note", "");

                std::string vendor_key = genVendorKey();
                std::string vendor_secret = genVendorSecret();

                auto conn = db.acquire();

                // 插入
                {
                    std::unique_ptr<sql::PreparedStatement> ps(
                        conn->prepareStatement(
                            "INSERT INTO vendor_keys(vendor_key, vendor_secret, customer_name, status, expire_time, bind_machine, note) "
                            "VALUES(?, ?, ?, 1, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? DAY), '', ?)"
                        )
                    );
                    ps->setString(1, vendor_key);
                    ps->setString(2, vendor_secret);
                    ps->setString(3, customer);
                    ps->setInt(4, days);
                    ps->setString(5, note);
                    ps->executeUpdate();
                }

                // 查 expire_time
                std::string expire_time;
                {
                    std::unique_ptr<sql::PreparedStatement> ps(
                        conn->prepareStatement(
                            "SELECT DATE_FORMAT(expire_time, '%Y-%m-%d %H:%i:%s') "
                            "FROM vendor_keys WHERE vendor_key=?"
                        )
                    );
                    ps->setString(1, vendor_key);
                    std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                    if (rs->next()) expire_time = rs->getString(1);
                }

                HttpJson::reply(res, HttpJson::ok({
                    {"vendor_key", vendor_key},
                    {"vendor_secret", vendor_secret},
                    {"expire_time", expire_time}
                    }));
            }
            catch (const sql::SQLException& e) {
                std::cerr << "[PlatformVendor] sql: " << e.what()
                    << " code=" << e.getErrorCode()
                    << " state=" << e.getSQLStateCStr() << "\n";
                HttpJson::reply(res, HttpJson::fail(std::string("db_error: ") + e.what()), 500);
            }
            catch (const std::exception& e) {
                std::cerr << "[PlatformVendor] ex: " << e.what() << "\n";
                HttpJson::reply(res, HttpJson::fail(std::string("exception: ") + e.what()), 500);
            }
            catch (...) {
                std::cerr << "[PlatformVendor] unknown\n";
                HttpJson::reply(res, HttpJson::fail("unknown_exception"), 500);
            }
            });

        // -------------------------
        // POST /platform/vendor/list
        // -------------------------
        svr.Post("/platform/vendor/list", [&](const httplib::Request& req, httplib::Response& res) {
            try {
                auto in = HttpJson::parse(req, res);
                if (in.is_null()) return;

                if (!RequireSign(signSvc, "POST", "/platform/vendor/list", in, res)) return;
                if (!RequireAdminKey(in, res)) return;

                int page = in.value("page", 1);
                int page_size = in.value("page_size", 20);
                std::string keyword = in.value("keyword", "");

                if (page < 1) page = 1;
                if (page_size < 1) page_size = 20;
                if (page_size > 100) page_size = 100;

                int offset = (page - 1) * page_size;
                std::string like = "%" + keyword + "%";

                auto conn = db.acquire();

                // total
                int total = 0;
                {
                    std::unique_ptr<sql::PreparedStatement> ps(
                        conn->prepareStatement(
                            "SELECT COUNT(*) FROM vendor_keys "
                            "WHERE (?='' OR vendor_key LIKE ? OR customer_name LIKE ? OR note LIKE ?)"
                        )
                    );
                    ps->setString(1, keyword);
                    ps->setString(2, like);
                    ps->setString(3, like);
                    ps->setString(4, like);
                    std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                    if (rs->next()) total = rs->getInt(1);
                }

                // items
                json items = json::array();
                {
                    std::unique_ptr<sql::PreparedStatement> ps(
                        conn->prepareStatement(
                            "SELECT id, vendor_key, vendor_secret, customer_name, status, "
                            "DATE_FORMAT(expire_time, '%Y-%m-%d %H:%i:%s') AS expire_time, "
                            "bind_machine, note, DATE_FORMAT(create_time, '%Y-%m-%d %H:%i:%s') AS create_time "
                            "FROM vendor_keys "
                            "WHERE (?='' OR vendor_key LIKE ? OR customer_name LIKE ? OR note LIKE ?) "
                            "ORDER BY id DESC LIMIT ? OFFSET ?"
                        )
                    );
                    ps->setString(1, keyword);
                    ps->setString(2, like);
                    ps->setString(3, like);
                    ps->setString(4, like);
                    ps->setInt(5, page_size);
                    ps->setInt(6, offset);

                    std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                    while (rs->next()) {
                        items.push_back({
                            {"id", rs->getInt64(1)},
                            {"vendor_key", rs->getString(2)},
                            {"vendor_secret", rs->getString(3)}, // 你平台自己查看需要它
                            {"customer_name", rs->getString(4)},
                            {"status", rs->getInt(5)},
                            {"expire_time", rs->getString(6)},
                            {"bind_machine", rs->getString(7)},
                            {"note", rs->getString(8)},
                            {"create_time", rs->getString(9)}
                            });
                    }
                }

                HttpJson::reply(res, HttpJson::ok({
                    {"page", page},
                    {"page_size", page_size},
                    {"total", total},
                    {"items", items}
                    }));
            }
            catch (const sql::SQLException& e) {
                std::cerr << "[PlatformVendor] sql: " << e.what()
                    << " code=" << e.getErrorCode()
                    << " state=" << e.getSQLStateCStr() << "\n";
                HttpJson::reply(res, HttpJson::fail(std::string("db_error: ") + e.what()), 500);
            }
            catch (const std::exception& e) {
                std::cerr << "[PlatformVendor] ex: " << e.what() << "\n";
                HttpJson::reply(res, HttpJson::fail(std::string("exception: ") + e.what()), 500);
            }
            catch (...) {
                std::cerr << "[PlatformVendor] unknown\n";
                HttpJson::reply(res, HttpJson::fail("unknown_exception"), 500);
            }
            });
    }

} // namespace
