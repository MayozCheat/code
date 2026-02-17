#include "httplib.h"
#include "json.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <chrono>

#include <mysql/jdbc.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#include "AppConfig.h"
#include "HttpJson.h"
#include "PlatformVendorHandlers.h"

// 现有的
#include"../db/DbPool.h"
#include "../services/SignService.h"

// 引入定义的 Vendor 相关代码
#include "../services/VendorClient.h"

#include <random>
#include<openssl/rand.h>

using json = nlohmann::json;

static const int64_t VENDOR_TS_WINDOW_SEC = 60;      // ts 允许误差
static const int64_t NONCE_KEEP_SEC = 10 * 60; // nonce 保留 10 分钟

static std::string BytesToHex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0xF]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

// -------------------- UTC unix seconds --------------------
static int64_t NowUnixSecondsUTC() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}
// -------------------- URL encode (UTF-8 bytes) --------------------
static std::string UrlEncode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((char)c);
        }
        else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

// ----------------------- MySQL datetime 解析： "YYYY-MM-DD HH:MM:SS" -> epoch(UTC) -----------------------
static bool ParseMysqlDatetimeUTC(const std::string& dt, int64_t& outEpoch) {
    // 简单解析：要求固定格式
    if (dt.size() < 19) return false;

    std::tm tm{};
    tm.tm_year = std::stoi(dt.substr(0, 4)) - 1900;
    tm.tm_mon = std::stoi(dt.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(dt.substr(8, 2));
    tm.tm_hour = std::stoi(dt.substr(11, 2));
    tm.tm_min = std::stoi(dt.substr(14, 2));
    tm.tm_sec = std::stoi(dt.substr(17, 2));

#if defined(_WIN32)
    // Windows: _mkgmtime 把 tm 当 UTC
    outEpoch = (int64_t)_mkgmtime(&tm);
#else
    outEpoch = (int64_t)timegm(&tm);
#endif
    return true;
}

// ----------------------- canonical：按 key 排序，key=value\n（sign 不参与） -----------------------
static bool BuildCanonical(const json& body, std::string& out) {
    if (!body.is_object()) return false;

    std::vector<std::string> keys;
    keys.reserve(body.size());
    for (auto it = body.begin(); it != body.end(); ++it) {
        if (it.key() == "sign") continue;
        keys.push_back(it.key());
    }
    std::sort(keys.begin(), keys.end(), [](const std::string& a, const std::string& b) {
        return a < b; // 默认字典序即可
        });

    std::string s;
    for (auto& k : keys) {
        const auto& v = body.at(k);
        if (v.is_object() || v.is_array()) return false; // 只支持扁平字段（你现在接口都是扁平）

        std::string vs;
        if (v.is_string()) {
            vs = UrlEncode(v.get<std::string>()); // 关键：字符串做 URL encode（解决中文）
        }
        else if (v.is_boolean()) {
            vs = v.get<bool>() ? "true" : "false";
        }
        else if (v.is_number_integer()) {
            vs = std::to_string(v.get<int64_t>());
        }
        else if (v.is_number_float()) {
            std::ostringstream oss;
            oss << v.get<double>();
            vs = oss.str();
        }
        else if (v.is_null()) {
            vs = "null";
        }
        else {
            return false;
        }

        s += k;
        s += "=";
        s += vs;
        s += "\n";
    }

    out = std::move(s);
    return true;
}


// ----------------------- HMAC-SHA256 hex -----------------------
static std::string HmacSha256Hex(const std::string& key, const std::string& msg) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(),
        key.data(), (int)key.size(),
        (const unsigned char*)msg.data(), msg.size(),
        hash, &len);

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(hex[(hash[i] >> 4) & 0xF]);
        out.push_back(hex[hash[i] & 0xF]);
    }
    return out;
}

// ----------------------- VerifySignHex -----------------------
static bool VerifySignHex(const std::string& secret,
    const std::string& method,
    const std::string& path,
    const json& body,
    std::string& outErr,
    std::string* outCanonical = nullptr,
    std::string* outExpected = nullptr) {

    outErr.clear();

    if (!body.contains("sign") || !body["sign"].is_string()) {
        outErr = "missing_sign";
        return false;
    }
    std::string clientSign = body["sign"].get<std::string>();

    std::string canonical;
    if (!BuildCanonical(body, canonical)) {
        outErr = "bad_canonical";
        return false;
    }

    std::string payload = method + "\n" + path + "\n" + canonical;
    std::string expected = HmacSha256Hex(secret, payload);

    if (outCanonical) *outCanonical = canonical;
    if (outExpected) *outExpected = expected;

    if (clientSign != expected) {
        outErr = "sign_mismatch";
        return false;
    }
    return true;
}

// ----------------------- 公共：admin_key 校验 -----------------------
static bool CheckAdminKey(const json& in, httplib::Response& res) {
    const std::string ADMIN_KEY = "2222112176-AdminKey-2026";
    if (!in.contains("admin_key") || !in["admin_key"].is_string()) {
        HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
        return false;
    }
    if (in["admin_key"].get<std::string>() != ADMIN_KEY) {
        HttpJson::reply(res, HttpJson::fail("bad_admin_key"), 403);
        return false;
    }
    return true;
}


// ----------------------- 公共：ts & nonce（防重放）-----------------------
static bool CheckTsAndNonce(DbPool& dbPool,
    const json& in,
    httplib::Response& res,
    int windowSec = 60) {

    if (!in.contains("ts") || !in["ts"].is_number_integer() ||
        !in.contains("nonce") || !in["nonce"].is_string()) {
        HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
        return false;
    }

    int64_t ts = in["ts"].get<int64_t>();
    std::string nonce = in["nonce"].get<std::string>();

    int64_t now = NowUnixSecondsUTC();
    int64_t diff = ts - now;
    if (diff > windowSec || diff < -windowSec) {
        HttpJson::reply(res, HttpJson::fail("ts_out_of_range"), 401);
        return false;
    }

    try {
        auto conn = dbPool.acquire();
        conn->setAutoCommit(false);

        // 插入 nonce（重复会 1062）
        {
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement("INSERT INTO vendor_nonce(nonce, ts) VALUES(?, ?)"));
            ps->setString(1, nonce);
            ps->setInt(2, (int)ts);
            ps->executeUpdate();
        }

        // 清理 10 分钟以前的 nonce
        {
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement("DELETE FROM vendor_nonce WHERE ts < ?"));
            int cutoff = (int)(NowUnixSecondsUTC() - 10 * 60);
            ps->setInt(1, cutoff);
            ps->executeUpdate();
        }

        conn->commit();
        dbPool.release(std::move(conn));
        return true;
    }
    catch (const sql::SQLException& e) {
        if (e.getErrorCode() == 1062) {
            HttpJson::reply(res, HttpJson::fail("nonce_reused"), 401);
            return false;
        }
        std::string msg = std::string("db_error: ") + e.what() +
            " code=" + std::to_string(e.getErrorCode()) +
            " state=" + std::string(e.getSQLStateCStr());
        HttpJson::reply(res, HttpJson::fail(msg), 500);
        return false;
    }
}

static std::string ScalarToStringForSign(const nlohmann::json& v) {
    if (v.is_string()) return v.get<std::string>();
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_number_integer()) return std::to_string(v.get<int64_t>());
    if (v.is_number_unsigned()) return std::to_string(v.get<uint64_t>());
    if (v.is_number_float()) {
        // 避免科学计数法，足够用
        std::ostringstream oss;
        oss << std::fixed << v.get<double>();
        std::string s = oss.str();
        // 去尾 0
        while (s.size() > 1 && s.back() == '0') s.pop_back();
        if (!s.empty() && s.back() == '.') s.pop_back();
        return s;
    }
    return ""; // 不支持 object/array
}


static std::string GetClientIp(const httplib::Request& req) {
    // 如果将来前面挂了 Nginx，可用 X-Forwarded-For
    auto it = req.headers.find("X-Forwarded-For");
    if (it != req.headers.end()) return it->second;
    return req.remote_addr; // cpp-httplib 自带
}

//添加日志记录
static void InsertVendorLog(sql::Connection* conn,
    const std::string& action,
    const std::string& vendor_key,
    const std::string& ip,
    const std::string& detail)
{
    if (!conn) return;

    try {
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement(
                "INSERT INTO vendor_log(action, vendor_key, ip, detail) VALUES(?, ?, ?, ?)"
            )
        );
        ps->setString(1, action);

        if (vendor_key.empty()) ps->setNull(2, sql::DataType::VARCHAR);
        else ps->setString(2, vendor_key);

        ps->setString(3, ip);
        ps->setString(4, detail);
        ps->executeUpdate();
    }
    catch (const sql::SQLException& e) {
        // 日志写失败不要影响主流程
        std::cerr << "[VendorLog] insert failed: " << e.what()
            << " code=" << e.getErrorCode()
            << " state=" << e.getSQLStateCStr() << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "[VendorLog] insert exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cerr << "[VendorLog] insert unknown exception\n";
    }
}






static std::string NowMysqlDatetimeUTC() {
    int64_t now = NowUnixSecondsUTC();
    std::tm tm{};
#if defined(_WIN32)
    time_t t = (time_t)now;
    gmtime_s(&tm, &t);
#else
    time_t t = (time_t)now;
    gmtime_r(&t, &tm);
#endif
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}




static std::string AddDaysUtcMysqlDatetime(const std::string& base, int addDays) {
    int64_t baseEpoch = 0;
    if (!ParseMysqlDatetimeUTC(base, baseEpoch)) return "";

    int64_t newEpoch = baseEpoch + (int64_t)addDays * 86400;

    std::tm tm{};
#if defined(_WIN32)
    time_t t = (time_t)newEpoch;
    gmtime_s(&tm, &t);
#else
    time_t t = (time_t)newEpoch;
    gmtime_r(&t, &tm);
#endif
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

void HandleVendorCheckFinal(const httplib::Request& req, httplib::Response& res, DbPool& dbPool) {
    try {
        std::cout << "[Vendor] Received /vendor/check\n" << std::flush;

        // 1) parse json
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        std::cout << "[Vendor] JSON=" << in.dump() << "\n" << std::flush;

        // 2) fields
        if (!in.contains("vendor_key") || !in["vendor_key"].is_string() ||
            !in.contains("machine_code") || !in["machine_code"].is_string() ||
            !in.contains("ts") || !in["ts"].is_number_integer() ||
            !in.contains("nonce") || !in["nonce"].is_string() ||
            !in.contains("sign") || !in["sign"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        const std::string vendor_key = in["vendor_key"].get<std::string>();
        const std::string machine_code = in["machine_code"].get<std::string>();
        const int64_t ts = in["ts"].get<int64_t>();
        const std::string nonce = in["nonce"].get<std::string>();

        const std::string ip = GetClientIp(req);

        // 3) ts basic check（先做一个快速判断，减少打 DB）
        {
            const int64_t now = NowUnixSecondsUTC();
            const int64_t diff = ts - now;
            if (diff > VENDOR_TS_WINDOW_SEC || diff < -VENDOR_TS_WINDOW_SEC) {
                std::cout << "[Vendor] ts_out_of_range ts=" << ts << " now=" << now << " diff=" << diff << "\n" << std::flush;
                HttpJson::reply(res, HttpJson::fail("ts_out_of_range"), 401);
                return;
            }
        }

        // 4) DB transaction（先取 vendor_secret，再验签；验签通过后才插 nonce）
        auto conn = dbPool.acquire();
        conn->setAutoCommit(false);

        int db_status = 0;
        std::string db_machine;
        std::string db_expire;
        std::string vendor_secret;

        // 4.1) SELECT license FOR UPDATE（防止并发 machine bind / ban 冲突）
        {
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement(
                    "SELECT status, machine_code, expire_time, vendor_secret "
                    "FROM vendor_license WHERE vendor_key=? LIMIT 1 FOR UPDATE"
                )
            );
            ps->setString(1, vendor_key);

            std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
            if (!rs->next()) {
                InsertVendorLog(conn.get(), "vendor_check_fail", vendor_key, ip, "err=vendor_not_found");
                conn->commit();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("vendor_not_found"), 404);
                return;
            }

            db_status = rs->getInt("status");
            db_expire = rs->getString("expire_time").asStdString();

            if (rs->isNull("machine_code")) db_machine = "";
            else db_machine = rs->getString("machine_code").asStdString();

            vendor_secret = rs->getString("vendor_secret").asStdString();
        }

        // 4.2) verify sign（关键：一定在插 nonce 之前）
        {
            std::string verr;
            // 注意：path 要严格是 "/vendor/check"，method "POST"
            if (!VerifySignHex(vendor_secret, "POST", "/vendor/check", in, verr)) {
                InsertVendorLog(conn.get(), "vendor_check_fail", vendor_key, ip, "err=" + verr);
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail(verr), 401);
                return;
            }
        }

        // 4.3) nonce 防重放（验签通过后才插）
        {
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement("INSERT INTO vendor_nonce(nonce, ts) VALUES(?, ?)")
            );
            ps->setString(1, nonce);
            ps->setInt(2, (int)ts);
            ps->executeUpdate();
        }

        // 4.4) cleanup old nonce
        {
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement("DELETE FROM vendor_nonce WHERE ts < ?")
            );
            const int cutoff = (int)(NowUnixSecondsUTC() - NONCE_KEEP_SEC);
            ps->setInt(1, cutoff);
            int del = ps->executeUpdate();
            std::cout << "[Vendor] nonce cleanup deleted=" << del << "\n" << std::flush;
        }

        // 5) business: status/expire/machine bind
        if (db_status == 0) {
            InsertVendorLog(conn.get(), "vendor_check_fail", vendor_key, ip, "err=vendor_banned");
            conn->commit();
            dbPool.release(std::move(conn));
            HttpJson::reply(res, HttpJson::fail("vendor_banned"), 403);
            return;
        }

        // expire check
        int64_t expireEpoch = 0;
        if (!ParseMysqlDatetimeUTC(db_expire, expireEpoch)) {
            InsertVendorLog(conn.get(), "vendor_check_fail", vendor_key, ip, "err=bad_expire_time_format");
            conn->rollback();
            dbPool.release(std::move(conn));
            HttpJson::reply(res, HttpJson::fail("bad_expire_time_format"), 500);
            return;
        }
        if (NowUnixSecondsUTC() >= expireEpoch) {
            InsertVendorLog(conn.get(), "vendor_check_fail", vendor_key, ip, "err=expired");
            conn->commit();
            dbPool.release(std::move(conn));
            HttpJson::reply(res, HttpJson::fail("expired"), 403);
            return;
        }

        // machine bind
        if (db_machine.empty()) {
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement("UPDATE vendor_license SET machine_code=? WHERE vendor_key=? LIMIT 1")
            );
            ps->setString(1, machine_code);
            ps->setString(2, vendor_key);
            ps->executeUpdate();
            std::cout << "[Vendor] machine bind vendor_key=" << vendor_key << " machine_code=" << machine_code << "\n" << std::flush;
        }
        else {
            if (db_machine != machine_code) {
                InsertVendorLog(conn.get(), "vendor_check_fail", vendor_key, ip,
                    "err=machine_mismatch stored=" + db_machine + " req=" + machine_code);
                conn->commit();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("machine_mismatch"), 403);
                return;
            }
        }

        InsertVendorLog(conn.get(), "vendor_check_ok", vendor_key, ip,
            "machine=" + machine_code + " expire=" + db_expire);

        conn->commit();
        dbPool.release(std::move(conn));

        HttpJson::reply(res, HttpJson::ok({ {"expire_time", db_expire} }));
    }
    catch (const sql::SQLException& e) {
        // nonce 重复：1062
        if (e.getErrorCode() == 1062) {
            std::cout << "[Vendor] nonce_reused\n" << std::flush;
            HttpJson::reply(res, HttpJson::fail("nonce_reused"), 401);
            return;
        }
        std::string msg = std::string("db_error: ") + e.what() +
            " code=" + std::to_string(e.getErrorCode()) +
            " state=" + std::string(e.getSQLStateCStr());
        std::cout << "[Vendor] " << msg << "\n" << std::flush;
        HttpJson::reply(res, HttpJson::fail(msg), 500);
    }
    catch (const std::exception& e) {
        std::cout << "[Vendor] exception: " << e.what() << "\n" << std::flush;
        HttpJson::reply(res, HttpJson::fail(std::string("exception: ") + e.what()), 500);
    }
    catch (...) {
        std::cout << "[Vendor] unknown exception\n" << std::flush;
        HttpJson::reply(res, HttpJson::fail("unknown_exception"), 500);
    }
}




// ----------------------- 生成卡密 key（prefix-随机hex） -----------------------
// 生成：prefix-24hex  (24 hex = 12 bytes 随机数，碰撞概率极低)
static std::string MakeCardKey(const std::string& prefix) {
    unsigned char buf[12];
    if (RAND_bytes(buf, (int)sizeof(buf)) != 1) {
        return ""; // 让上层报错
    }
    return prefix + "-" + BytesToHex(buf, sizeof(buf));
}




// ============================================================================
//  路由：SetupVendorRoutes
// ============================================================================
void SetupVendorRoutes(httplib::Server& svr, DbPool& dbPool) {

    // -------------------------
    // GET /ping
    // -------------------------
    svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("pong", "text/plain; charset=utf-8");
        });

    // =========================================================================
    // Admin: 创建 vendor 卡密（给开发者续期用）
    // POST /admin/vendor/card/create
    // body: {admin_key, days, count, prefix, ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/card/create", [&](const httplib::Request& req, httplib::Response& res) {
        try {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("days") || !in["days"].is_number_integer() ||
            !in.contains("count") || !in["count"].is_number_integer() ||
            !in.contains("prefix") || !in["prefix"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckAdminKey(in, res)) return;
        if (!CheckTsAndNonce(dbPool, in, res)) return;

        int days = in["days"].get<int>();
        int count = in["count"].get<int>();
        std::string prefix = in["prefix"].get<std::string>();

        if (days <= 0 || days > 3650 || count <= 0 || count > 200) {
            HttpJson::reply(res, HttpJson::fail("bad_range"), 400);
            return;
        }

        try {
            auto conn = dbPool.acquire();
            conn->setAutoCommit(false);

     

            // 4) 生成并入库 cards（带 1062 重试）
            std::vector<std::string> cards;
            cards.reserve((size_t)count);

            std::unique_ptr<sql::PreparedStatement> psIns(
                conn->prepareStatement("INSERT INTO vendor_card(card_key, days) VALUES(?, ?)"));

            for (int i = 0; i < count; ++i) {
                bool ok = false;
                for (int retry = 0; retry < 50; ++retry) { // 每张卡最多重试 50 次，基本不会用到
                    std::string ck = MakeCardKey(prefix);
                    if (ck.empty()) {
                        conn->rollback();
                        dbPool.release(std::move(conn));
                        HttpJson::reply(res, HttpJson::fail("make_card_key_failed_rand"), 500);
                        return;
                    }

                    try {
                        psIns->setString(1, ck);
                        psIns->setInt(2, days);
                        psIns->executeUpdate();

                        cards.push_back(std::move(ck));
                        ok = true;
                        break;
                    }
                    catch (const sql::SQLException& e) {
                        if (e.getErrorCode() == 1062) {
                            // key 冲突：换一个 ck 继续试
                            continue;
                        }
                        throw; // 其它数据库错误交给外层 catch
                    }
                }

                if (!ok) {
                    conn->rollback();
                    dbPool.release(std::move(conn));
                    HttpJson::reply(res, HttpJson::fail("make_card_key_failed_too_many_collisions"), 500);
                    return;
                }
            }


            InsertVendorLog(conn.get(), "admin_create_cards", "", GetClientIp(req),
                "days=" + std::to_string(days) + ",count=" + std::to_string(count));

            conn->commit();
            dbPool.release(std::move(conn));

            json out;
            out["cards"] = cards;
            HttpJson::reply(res, HttpJson::ok(out));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            std::cout << "[Admin] card/create " << msg << "\n" << std::flush;
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        catch (const std::exception& e) {
            std::string msg = std::string("exception: ") + e.what();
            std::cout << "[Admin] card/create " << msg << "\n" << std::flush;
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        catch (...) {
            std::cout << "[Admin] card/create unknown_exception\n" << std::flush;
            HttpJson::reply(res, HttpJson::fail("unknown_exception"), 500);
        }
        });

    // =========================================================================
    // Admin: 卡密列表
    // POST /admin/vendor/card/list
    // body: {admin_key, page, page_size, keyword, is_used(-1/0/1), ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/card/list", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("page") || !in["page"].is_number_integer() ||
            !in.contains("page_size") || !in["page_size"].is_number_integer() ||
            !in.contains("keyword") || !in["keyword"].is_string() ||
            !in.contains("is_used") || !in["is_used"].is_number_integer()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckAdminKey(in, res)) return;
        if (!CheckTsAndNonce(dbPool, in, res)) return;

        int page = in["page"].get<int>();
        int page_size = in["page_size"].get<int>();
        std::string keyword = in["keyword"].get<std::string>();
        int is_used = in["is_used"].get<int>(); // -1/0/1

        if (page <= 0) page = 1;
        if (page_size <= 0) page_size = 20;
        if (page_size > 200) page_size = 200;
        if (!(is_used == -1 || is_used == 0 || is_used == 1)) is_used = -1;

        try {
            auto conn = dbPool.acquire();

            std::string where = " WHERE 1=1 ";
            if (!keyword.empty()) where += " AND card_key LIKE ? ";
            if (is_used != -1) where += " AND is_used=? ";

            // total
            int total = 0;
            {
                std::string sql = "SELECT COUNT(*) AS c FROM vendor_card" + where;
                std::unique_ptr<sql::PreparedStatement> ps(conn->prepareStatement(sql));
                int idx = 1;
                if (!keyword.empty()) ps->setString(idx++, "%" + keyword + "%");
                if (is_used != -1) ps->setInt(idx++, is_used);
                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                if (rs->next()) total = rs->getInt("c");
            }

            // items
            json items = json::array();
            {
                int offset = (page - 1) * page_size;
                std::string sql =
                    "SELECT id, card_key, days, is_used, used_by_vendor_key, used_time, create_time, note "
                    "FROM vendor_card" + where +
                    " ORDER BY id DESC LIMIT ? OFFSET ?";

                std::unique_ptr<sql::PreparedStatement> ps(conn->prepareStatement(sql));
                int idx = 1;
                if (!keyword.empty()) ps->setString(idx++, "%" + keyword + "%");
                if (is_used != -1) ps->setInt(idx++, is_used);
                ps->setInt(idx++, page_size);
                ps->setInt(idx++, offset);

                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                while (rs->next()) {
                    json it;
                    it["id"] = rs->getInt64("id");
                    it["card_key"] = rs->getString("card_key").asStdString();
                    it["days"] = rs->getInt("days");
                    it["is_used"] = rs->getInt("is_used");
                    it["note"] = rs->getString("note").asStdString();

                    if (rs->isNull("used_by_vendor_key")) it["used_by_vendor_key"] = nullptr;
                    else it["used_by_vendor_key"] = rs->getString("used_by_vendor_key").asStdString();

                    if (rs->isNull("used_time")) it["used_time"] = nullptr;
                    else it["used_time"] = rs->getString("used_time").asStdString();

                    it["create_time"] = rs->getString("create_time").asStdString();
                    items.push_back(std::move(it));
                }
            }

            dbPool.release(std::move(conn));

            json out;
            out["page"] = page;
            out["page_size"] = page_size;
            out["total"] = total;
            out["items"] = items;
            HttpJson::reply(res, HttpJson::ok(out));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        });

    // =========================================================================
    // Admin: 卡密备注
    // POST /admin/vendor/card/note
    // body: {admin_key, card_key, note, ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/card/note", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("card_key") || !in["card_key"].is_string() ||
            !in.contains("note") || !in["note"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckAdminKey(in, res)) return;
        if (!CheckTsAndNonce(dbPool, in, res)) return;

        std::string card_key = in["card_key"].get<std::string>();
        std::string note = in["note"].get<std::string>();
        if ((int)note.size() > 200) {
            HttpJson::reply(res, HttpJson::fail("note_too_long"), 400);
            return;
        }

        try {
            auto conn = dbPool.acquire();
            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement("UPDATE vendor_card SET note=? WHERE card_key=? LIMIT 1"));
            ps->setString(1, note);
            ps->setString(2, card_key);
            int rows = ps->executeUpdate();
            dbPool.release(std::move(conn));

            if (rows != 1) {
                HttpJson::reply(res, HttpJson::fail("card_not_found"), 404);
                return;
            }
            HttpJson::reply(res, HttpJson::ok({}));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        });

    // =========================================================================
    // Admin: 禁用卡密
    // POST /admin/vendor/card/disable
    // body: {admin_key, card_key, reason, ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/card/disable", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("admin_key") || !in["admin_key"].is_string() ||
            !in.contains("card_key") || !in["card_key"].is_string() ||
            !in.contains("reason") || !in["reason"].is_string() ||
            !in.contains("ts") || !in["ts"].is_number_integer() ||
            !in.contains("nonce") || !in["nonce"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        const std::string admin_key = in["admin_key"].get<std::string>();
        const std::string card_key = in["card_key"].get<std::string>();
        const std::string reason = in["reason"].get<std::string>();
        const int64_t ts = in["ts"].get<int64_t>();
        const std::string nonce = in["nonce"].get<std::string>();

        const std::string ADMIN_KEY = "2222112176-AdminKey-2026";
        if (admin_key != ADMIN_KEY) {
            HttpJson::reply(res, HttpJson::fail("bad_admin_key"), 403);
            return;
        }

        int64_t now = NowUnixSecondsUTC();
        int64_t diff = ts - now;
        if (diff > 60 || diff < -60) {
            HttpJson::reply(res, HttpJson::fail("ts_out_of_range"), 401);
            return;
        }

        if ((int)reason.size() > 200) {
            HttpJson::reply(res, HttpJson::fail("reason_too_long"), 400);
            return;
        }

        try {
            auto conn = dbPool.acquire();
            conn->setAutoCommit(false);

            // nonce 防重放
            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement("INSERT INTO vendor_nonce(nonce, ts) VALUES(?, ?)"));
                ps->setString(1, nonce);
                ps->setInt(2, (int)ts);
                ps->executeUpdate();
            }

            // 只允许禁用：未使用 & 未禁用 的卡
            int rows = 0;
            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement(
                        "UPDATE vendor_card "
                        "SET disabled=1, disabled_reason=? "
                        "WHERE card_key=? AND is_used=0 AND disabled=0 "
                        "LIMIT 1"
                    )
                );
                ps->setString(1, reason);
                ps->setString(2, card_key);
                rows = ps->executeUpdate();
            }

            // 清理旧 nonce
            {
                std::unique_ptr<sql::PreparedStatement> ps2(
                    conn->prepareStatement("DELETE FROM vendor_nonce WHERE ts < ?"));
                int cutoff = (int)(NowUnixSecondsUTC() - 10 * 60);
                ps2->setInt(1, cutoff);
                ps2->executeUpdate();
            }

            if (rows != 1) {
                // 这里返回明确原因（很重要：避免你误以为禁用了）
                // 进一步判断到底是哪种情况：
                int is_used = -1, disabled = -1;
                {
                    std::unique_ptr<sql::PreparedStatement> ps(
                        conn->prepareStatement("SELECT is_used, disabled FROM vendor_card WHERE card_key=? LIMIT 1"));
                    ps->setString(1, card_key);
                    std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                    if (!rs->next()) {
                        conn->rollback();
                        dbPool.release(std::move(conn));
                        HttpJson::reply(res, HttpJson::fail("card_not_found"), 404);
                        return;
                    }
                    is_used = rs->getInt("is_used");
                    disabled = rs->getInt("disabled");
                }

                conn->rollback();
                dbPool.release(std::move(conn));

                if (is_used != 0) {
                    HttpJson::reply(res, HttpJson::fail("card_used"), 409);
                }
                else if (disabled != 0) {
                    HttpJson::reply(res, HttpJson::fail("card_disabled"), 409);
                }
                else {
                    HttpJson::reply(res, HttpJson::fail("disable_failed"), 500);
                }
                return;
            }

            conn->commit();
            dbPool.release(std::move(conn));
            HttpJson::reply(res, HttpJson::ok({}));
        }
        catch (const sql::SQLException& e) {
            if (e.getErrorCode() == 1062) {
                HttpJson::reply(res, HttpJson::fail("nonce_reused"), 401);
                return;
            }
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        });


    // =========================================================================
    // Vendor: check（开发者后台启动时调用）
    // POST /vendor/check
    // body: {vendor_key, machine_code, ts, nonce, sign}
    // sign = HMACSHA256(vendor_secret, "POST\n/vendor/check\n" + canonical)
    // =========================================================================
    svr.Post("/vendor/check", [&](const httplib::Request& req, httplib::Response& res) {
        HandleVendorCheckFinal(req, res, dbPool);
        });

    // =========================================================================
    // Vendor: activate（开发者输入卡密续期）
    // POST /vendor/activate
    // body: {vendor_key, machine_code, card_key, ts, nonce}
    // =========================================================================
    svr.Post("/vendor/activate", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("vendor_key") || !in["vendor_key"].is_string() ||
            !in.contains("machine_code") || !in["machine_code"].is_string() ||
            !in.contains("card_key") || !in["card_key"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckTsAndNonce(dbPool, in, res)) return;

        const std::string vendor_key = in["vendor_key"].get<std::string>();
        const std::string machine_code = in["machine_code"].get<std::string>();
        const std::string card_key = in["card_key"].get<std::string>();

        try {
            auto conn = dbPool.acquire();
            conn->setAutoCommit(false);

            // license
            int status = 0;
            std::string db_machine;
            std::string expire_time;

            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement(
                        "SELECT status, machine_code, expire_time FROM vendor_license WHERE vendor_key=? LIMIT 1"
                    )
                );
                ps->setString(1, vendor_key);
                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                if (!rs->next()) {
                    conn->rollback();
                    dbPool.release(std::move(conn));
                    HttpJson::reply(res, HttpJson::fail("vendor_not_found"), 404);
                    return;
                }
                status = rs->getInt("status");
                expire_time = rs->getString("expire_time").asStdString();
                if (rs->isNull("machine_code")) db_machine = "";
                else db_machine = rs->getString("machine_code").asStdString();
            }

            if (status == 0) {
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("vendor_banned"), 403);
                return;
            }

            // machine bind / mismatch
            if (db_machine.empty()) {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement("UPDATE vendor_license SET machine_code=? WHERE vendor_key=? LIMIT 1"));
                ps->setString(1, machine_code);
                ps->setString(2, vendor_key);
                ps->executeUpdate();
                db_machine = machine_code;
            }
            else if (db_machine != machine_code) {
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("machine_mismatch"), 403);
                return;
            }

            // card lock
            int days = 0;
            int is_used = 0;
            int disabled = 0;

            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement(
                        "SELECT days, is_used, disabled FROM vendor_card WHERE card_key=? LIMIT 1 FOR UPDATE"
                    )
                );
                ps->setString(1, card_key);
                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                if (!rs->next()) {
                    InsertVendorLog(conn.get(), "vendor_activate_fail", vendor_key, GetClientIp(req), "err=card_not_found card=" + card_key);
                    conn->rollback();
                    dbPool.release(std::move(conn));
                    HttpJson::reply(res, HttpJson::fail("card_not_found"), 404);
                    return;
                }
                days = rs->getInt("days");
                is_used = rs->getInt("is_used");
                disabled = rs->getInt("disabled");
            }

            if (disabled != 0) {
                InsertVendorLog(conn.get(), "vendor_activate_fail", vendor_key, GetClientIp(req), "err=card_disabled card=" + card_key);
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("card_disabled"), 403);
                return;
            }
            if (is_used != 0) {
                InsertVendorLog(conn.get(), "vendor_activate_fail", vendor_key, GetClientIp(req), "err=card_used card=" + card_key);
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("card_used"), 409);
                return;
            }

            // 计算新 expire：如果已过期，用 now 为 base；否则用当前 expire_time 为 base
            int64_t expEpoch = 0;
            if (!ParseMysqlDatetimeUTC(expire_time, expEpoch)) {
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("bad_expire_time_format"), 500);
                return;
            }

            std::string base = (NowUnixSecondsUTC() >= expEpoch) ? NowMysqlDatetimeUTC() : expire_time;

            // 用 SQL 做 DATE_ADD（避免你 C++ 自己算日期出错）
            std::string newExpire;
            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement("SELECT DATE_ADD(?, INTERVAL ? DAY) AS ne"));
                ps->setString(1, base);
                ps->setInt(2, days);
                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                if (rs->next()) newExpire = rs->getString("ne").asStdString();
            }
            if (newExpire.empty()) {
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("calc_expire_failed"), 500);
                return;
            }

            // mark card used
            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement(
                        "UPDATE vendor_card SET is_used=1, used_by_vendor_key=?, used_time=UTC_TIMESTAMP() "
                        "WHERE card_key=? AND is_used=0 LIMIT 1"
                    )
                );
                ps->setString(1, vendor_key);
                ps->setString(2, card_key);
                int rows = ps->executeUpdate();
                if (rows != 1) {
                    conn->rollback();
                    dbPool.release(std::move(conn));
                    HttpJson::reply(res, HttpJson::fail("card_used"), 409);
                    return;
                }
            }

            // update license expire
            {
                std::unique_ptr<sql::PreparedStatement> ps(
                    conn->prepareStatement("UPDATE vendor_license SET expire_time=? WHERE vendor_key=? LIMIT 1"));
                ps->setString(1, newExpire);
                ps->setString(2, vendor_key);
                ps->executeUpdate();
            }

            InsertVendorLog(conn.get(), "vendor_activate_ok", vendor_key, GetClientIp(req),
                "card=" + card_key + " days=" + std::to_string(days) + " new_expire=" + newExpire);

            conn->commit();
            dbPool.release(std::move(conn));

            HttpJson::reply(res, HttpJson::ok({ {"expire_time", newExpire} }));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        catch (const std::exception& e) {
            HttpJson::reply(res, HttpJson::fail(std::string("exception: ") + e.what()), 500);
        }
        catch (...) {
            HttpJson::reply(res, HttpJson::fail("unknown_exception"), 500);
        }
        });

    // =========================================================================
    // Admin: 授权列表（vendor_license）
    // POST /admin/vendor/license/list
    // body: {admin_key, page, page_size, keyword, ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/license/list", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("page") || !in["page"].is_number_integer() ||
            !in.contains("page_size") || !in["page_size"].is_number_integer() ||
            !in.contains("keyword") || !in["keyword"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckAdminKey(in, res)) return;
        if (!CheckTsAndNonce(dbPool, in, res)) return;

        int page = in["page"].get<int>();
        int page_size = in["page_size"].get<int>();
        std::string keyword = in["keyword"].get<std::string>();

        if (page <= 0) page = 1;
        if (page_size <= 0) page_size = 20;
        if (page_size > 200) page_size = 200;

        try {
            auto conn = dbPool.acquire();

            std::string where = " WHERE 1=1 ";
            if (!keyword.empty()) where += " AND (vendor_key LIKE ? OR machine_code LIKE ?) ";

            int total = 0;
            {
                std::string sql = "SELECT COUNT(*) AS c FROM vendor_license" + where;
                std::unique_ptr<sql::PreparedStatement> ps(conn->prepareStatement(sql));
                int idx = 1;
                if (!keyword.empty()) {
                    ps->setString(idx++, "%" + keyword + "%");
                    ps->setString(idx++, "%" + keyword + "%");
                }
                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                if (rs->next()) total = rs->getInt("c");
            }

            json items = json::array();
            {
                int offset = (page - 1) * page_size;
                std::string sql =
                    "SELECT vendor_key, machine_code, expire_time, status "
                    "FROM vendor_license" + where +
                    " ORDER BY id DESC LIMIT ? OFFSET ?";

                std::unique_ptr<sql::PreparedStatement> ps(conn->prepareStatement(sql));
                int idx = 1;
                if (!keyword.empty()) {
                    ps->setString(idx++, "%" + keyword + "%");
                    ps->setString(idx++, "%" + keyword + "%");
                }
                ps->setInt(idx++, page_size);
                ps->setInt(idx++, offset);

                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                while (rs->next()) {
                    json it;
                    it["vendor_key"] = rs->getString("vendor_key").asStdString();
                    it["machine_code"] = rs->isNull("machine_code") ? "" : rs->getString("machine_code").asStdString();
                    it["expire_time"] = rs->getString("expire_time").asStdString();
                    it["status"] = rs->getInt("status");
                    items.push_back(std::move(it));
                }
            }

            dbPool.release(std::move(conn));

            json out;
            out["page"] = page;
            out["page_size"] = page_size;
            out["total"] = total;
            out["items"] = items;
            HttpJson::reply(res, HttpJson::ok(out));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        });

    // =========================================================================
    // Admin: ban/unban 授权（vendor_license.status + disabled_reason）
    // POST /admin/vendor/license/ban
    // body: {admin_key, vendor_key, status(0/1), reason, ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/license/ban", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("vendor_key") || !in["vendor_key"].is_string() ||
            !in.contains("status") || !in["status"].is_number_integer() ||
            !in.contains("reason") || !in["reason"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckAdminKey(in, res)) return;
        if (!CheckTsAndNonce(dbPool, in, res)) return;

        std::string vendor_key = in["vendor_key"].get<std::string>();
        int status = in["status"].get<int>();
        std::string reason = in["reason"].get<std::string>();

        if (!(status == 0 || status == 1)) {
            HttpJson::reply(res, HttpJson::fail("invalid_status"), 400);
            return;
        }
        if ((int)reason.size() > 200) {
            HttpJson::reply(res, HttpJson::fail("reason_too_long"), 400);
            return;
        }

        try {
            auto conn = dbPool.acquire();
            conn->setAutoCommit(false);

            std::unique_ptr<sql::PreparedStatement> ps(
                conn->prepareStatement(
                    "UPDATE vendor_license SET status=?, disabled_reason=? WHERE vendor_key=? LIMIT 1"
                )
            );
            ps->setInt(1, status);
            ps->setString(2, reason);
            ps->setString(3, vendor_key);

            int rows = ps->executeUpdate();
            if (rows != 1) {
                conn->rollback();
                dbPool.release(std::move(conn));
                HttpJson::reply(res, HttpJson::fail("vendor_key_not_found"), 404);
                return;
            }

            InsertVendorLog(conn.get(), "admin_license_ban", vendor_key, GetClientIp(req),
                "status=" + std::to_string(status) + " reason=" + reason);

            conn->commit();
            dbPool.release(std::move(conn));

            HttpJson::reply(res, HttpJson::ok({}));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        });

    // =========================================================================
    // Admin: 日志查询（vendor_log）
    // POST /admin/vendor/log/list
    // body: {admin_key, page, page_size, vendor_key(optional), action(optional), ts, nonce}
    // =========================================================================
    svr.Post("/admin/vendor/log/list", [&](const httplib::Request& req, httplib::Response& res) {
        auto in = HttpJson::parse(req, res);
        if (in.is_null()) return;

        if (!in.contains("page") || !in["page"].is_number_integer() ||
            !in.contains("page_size") || !in["page_size"].is_number_integer() ||
            !in.contains("vendor_key") || !in["vendor_key"].is_string() ||
            !in.contains("action") || !in["action"].is_string()) {
            HttpJson::reply(res, HttpJson::fail("bad_fields"), 400);
            return;
        }

        if (!CheckAdminKey(in, res)) return;
        if (!CheckTsAndNonce(dbPool, in, res)) return;

        int page = in["page"].get<int>();
        int page_size = in["page_size"].get<int>();
        std::string vendor_key = in["vendor_key"].get<std::string>();
        std::string action = in["action"].get<std::string>();

        if (page <= 0) page = 1;
        if (page_size <= 0) page_size = 20;
        if (page_size > 200) page_size = 200;

        try {
            auto conn = dbPool.acquire();

            std::string where = " WHERE 1=1 ";
            if (!vendor_key.empty()) where += " AND vendor_key=? ";
            if (!action.empty()) where += " AND action=? ";

            int total = 0;
            {
                std::string sql = "SELECT COUNT(*) AS c FROM vendor_log" + where;
                std::unique_ptr<sql::PreparedStatement> ps(conn->prepareStatement(sql));
                int idx = 1;
                if (!vendor_key.empty()) ps->setString(idx++, vendor_key);
                if (!action.empty()) ps->setString(idx++, action);
                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                if (rs->next()) total = rs->getInt("c");
            }

            json items = json::array();
            {
                int offset = (page - 1) * page_size;
                std::string sql =
                    "SELECT id, action, vendor_key, ip, detail, created_at "
                    "FROM vendor_log" + where +
                    " ORDER BY id DESC LIMIT ? OFFSET ?";

                std::unique_ptr<sql::PreparedStatement> ps(conn->prepareStatement(sql));
                int idx = 1;
                if (!vendor_key.empty()) ps->setString(idx++, vendor_key);
                if (!action.empty()) ps->setString(idx++, action);
                ps->setInt(idx++, page_size);
                ps->setInt(idx++, offset);

                std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
                while (rs->next()) {
                    json it;
                    it["id"] = rs->getInt64("id");
                    it["action"] = rs->getString("action").asStdString();
                    it["vendor_key"] = rs->isNull("vendor_key") ? "" : rs->getString("vendor_key").asStdString();
                    it["ip"] = rs->getString("ip").asStdString();
                    it["detail"] = rs->getString("detail").asStdString();
                    it["created_at"] = rs->getString("created_at").asStdString();
                    items.push_back(std::move(it));
                }
            }

            dbPool.release(std::move(conn));

            json out;
            out["page"] = page;
            out["page_size"] = page_size;
            out["total"] = total;
            out["items"] = items;
            HttpJson::reply(res, HttpJson::ok(out));
        }
        catch (const sql::SQLException& e) {
            std::string msg = std::string("db_error: ") + e.what() +
                " code=" + std::to_string(e.getErrorCode()) +
                " state=" + std::string(e.getSQLStateCStr());
            HttpJson::reply(res, HttpJson::fail(msg), 500);
        }
        });

    // -------------------------
    // logger（你想要的控制台输出）
    // -------------------------
    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::cout << "[HTTP] " << req.method << " " << req.path
            << " -> " << res.status
            << " body=" << req.body.size()
            << "\n" << std::flush;
        });
}









static bool BuildCanonicalNoSign(const nlohmann::json& body, std::string& out) {
    if (!body.is_object()) return false;

    std::vector<std::string> keys;
    keys.reserve(body.size());
    for (auto it = body.begin(); it != body.end(); ++it) {
        if (it.key() == "sign") continue;
        keys.push_back(it.key());
    }
    std::sort(keys.begin(), keys.end(), std::less<>());

    std::string s;
    for (auto& k : keys) {
        const auto& v = body.at(k);
        if (v.is_object() || v.is_array()) return false;
        std::string vs = ScalarToStringForSign(v);
        s += k;
        s += "=";
        s += vs;
        s += "\n";
    }
    out = std::move(s);
    return true;
}


static bool VerifyVendorSign(const std::string& method,
    const std::string& path,
    const json& body,
    const std::string& vendor_secret,
    std::string& outErr) {
    if (!body.contains("sign") || !body["sign"].is_string()) {
        outErr = "bad_sign_fields";
        return false;
    }
    std::string canonical;
    if (!BuildCanonicalNoSign(body, canonical)) {
        outErr = "canonical_failed";
        return false;
    }
    std::string payload = method + "\n" + path + "\n" + canonical;
    std::string expected = HmacSha256Hex(vendor_secret, payload);
    std::string got = body["sign"].get<std::string>();
    if (got != expected) {
        outErr = "sign_mismatch";
        return false;
    }
    return true;
}

static bool CheckVendorTs(const json& in, std::string& outErr) {
    if (!in.contains("ts") || !in["ts"].is_number_integer()) { outErr = "bad_ts"; return false; }
    int64_t ts = in["ts"].get<int64_t>();
    int64_t now = NowUnixSecondsUTC();
    int64_t diff = ts - now;
    if (diff > AppConfig::VENDOR_TS_WINDOW_SEC || diff < -AppConfig::VENDOR_TS_WINDOW_SEC) {
        outErr = "ts_out_of_range";
        return false;
    }
    return true;
}

static bool PutVendorNonce(DbPool& db, const std::string& nonce, int64_t ts, std::string& outErr) {
    try {
        auto conn = db.acquire();
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement("INSERT INTO vendor_nonce(nonce, ts) VALUES(?, ?)"));
        ps->setString(1, nonce);
        ps->setInt(2, (int)ts);
        ps->executeUpdate();
        return true;
    }
    catch (const sql::SQLException& e) {
        // 重复 nonce
        if (e.getErrorCode() == 1062) { outErr = "nonce_reused"; return false; }
        outErr = std::string("db_error: ") + e.what();
        return false;
    }
}

static bool LoadVendorRow(DbPool& db,
    const std::string& vendor_key,
    int& outStatus,
    std::string& outExpire,
    std::string& outBindMachine,
    std::string& outSecret,
    std::string& outErr) {
    try {
        auto conn = db.acquire();
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement(
                "SELECT status, DATE_FORMAT(expire_time,'%Y-%m-%d %H:%i:%s') AS et, "
                "IFNULL(bind_machine,''), vendor_secret "
                "FROM vendor_keys WHERE vendor_key=?"));
        ps->setString(1, vendor_key);
        std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
        if (!rs->next()) { outErr = "vendor_not_found"; return false; }

        outStatus = rs->getInt(1);
        outExpire = rs->getString(2);
        outBindMachine = rs->getString(3);
        outSecret = rs->getString(4);
        return true;
    }
    catch (const sql::SQLException& e) {
        outErr = std::string("db_error: ") + e.what();
        return false;
    }
}

// 绑定机器码（第一次 activate）
static bool BindMachineOnce(DbPool& db,
    const std::string& vendor_key,
    const std::string& machine_code,
    std::string& outErr) {
    try {
        auto conn = db.acquire();
        std::unique_ptr<sql::PreparedStatement> ps(
            conn->prepareStatement(
                "UPDATE vendor_keys SET bind_machine=? "
                "WHERE vendor_key=? AND (bind_machine='' OR bind_machine IS NULL)"));
        ps->setString(1, machine_code);
        ps->setString(2, vendor_key);
        int n = ps->executeUpdate();
        if (n <= 0) {
            // 已绑定（不允许覆盖）
            outErr = "machine_already_bound";
            return false;
        }
        return true;
    }
    catch (const sql::SQLException& e) {
        outErr = std::string("db_error: ") + e.what();
        return false;
    }
}

int main() {
    try {
        // 创建数据库连接池
        DbPool dbPool(AppConfig::DB_POOL_SIZE);

        // 创建服务器
        httplib::Server svr;

        svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
            std::cout
                << "[HTTP] " << req.method << " " << req.path
                << " -> " << res.status
                << " body=" << req.body.size()
                << "\n" << std::flush;
            });

        svr.set_error_handler([](const httplib::Request& req, httplib::Response& res) {
            // 如果 handler 没写 body，这里补一个统一 JSON
            if (res.body.empty()) {
                std::string err = "http_error_" + std::to_string(res.status);
                HttpJson::reply(res, HttpJson::fail(err), res.status);
            }

            std::cout << "[HTTP] error_handler: "
                << req.method << " " << req.path
                << " -> " << res.status
                << " body=" << req.body.size()
                << " resp_body=" << res.body.size()
                << "\n" << std::flush;
            });

        svr.set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
            std::string msg = "unknown_exception";
            try {
                if (ep) std::rethrow_exception(ep);
            }
            catch (const std::exception& e) {
                msg = std::string("exception: ") + e.what();
            }
            catch (...) {
                msg = "unknown_exception";
            }

            std::cout << "[HTTP] exception_handler: "
                << req.method << " " << req.path
                << " -> 500 " << msg
                << "\n" << std::flush;

            HttpJson::reply(res, HttpJson::fail(msg), 500);
            });
        

        // 设置路由
        SetupVendorRoutes(svr, dbPool);

        // 启动服务器
        std::cout << "Server is running at http://127.0.0.1:9001\n"; // 输出服务启动信息

        svr.set_mount_point("/", "./web");

        svr.listen("0.0.0.0", 9001);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

