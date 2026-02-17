#include "SignService.h"
#include "../db/DbPool.h"
#include "../db/DbConfig.h"
#include "../utils/Hmac.h"

#include <ctime>
#include <vector>
#include <algorithm>

using nlohmann::json;

static long long nowSec() {
    return (long long)std::time(nullptr);
}

static std::string scalarToString(const json& v) {
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number_integer()) return std::to_string(v.get<long long>());
    if (v.is_number_float()) return std::to_string(v.get<double>());
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    // 为了保证一致性：只允许标量
    return "";
}

static std::string percentEncode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        // 只保留安全 ASCII
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

// 关键：做一个“与 JSON 字段顺序无关”的 canonical 字符串
// 仅支持扁平字段（你的接口现在都是扁平的）
// 重要：对 string 做 percent-encode，避免中文/空格/换行导致签名不一致
static bool buildCanonical(const json& bodyNoSign, std::string& out) {
    std::vector<std::string> keys;
    keys.reserve(bodyNoSign.size());
    for (auto it = bodyNoSign.begin(); it != bodyNoSign.end(); ++it) {
        keys.push_back(it.key());
    }

    // 推荐：确定性排序（字节序）
    std::sort(keys.begin(), keys.end(), [](const std::string& a, const std::string& b) {
        return a < b; // std::string 比较本身就是字节序
        });

    std::string s;
    for (auto& k : keys) {
        const auto& v = bodyNoSign.at(k);
        if (v.is_object() || v.is_array()) return false; // 暂不支持嵌套

        std::string vs = scalarToString(v);

        // 关键：只对字符串做编码，其他类型保持原样
        if (v.is_string()) {
            vs = percentEncode(vs);
        }

        s += k;
        s += "=";
        s += vs;
        s += "\n";
    }
    out = std::move(s);
    return true;
}

SignService::SignService(DbPool& pool) : pool_(pool) {}

json SignService::verify(const std::string& method,
    const std::string& path,
    const json& body) {
    // 1) 字段检查
    if (!body.contains("ts") || !body["ts"].is_number_integer() ||
        !body.contains("nonce") || !body["nonce"].is_string() ||
        !body.contains("sign") || !body["sign"].is_string()) {
        return json{ {"ok", false}, {"err", "bad_sign_fields"} };
    }

    long long ts = body["ts"].get<long long>();
    std::string nonce = body["nonce"].get<std::string>();
    std::string sign = body["sign"].get<std::string>();

    // 2) 时间窗
    long long n = nowSec();
    long long skew = ts > n ? (ts - n) : (n - ts);
    if (skew > AppConfig::SIGN_MAX_SKEW_SEC) {
        return json{ {"ok", false}, {"err", "ts_out_of_range"} };
    }

    // 3) 生成 canonical
    json bodyNoSign = body;
    bodyNoSign.erase("sign");

    std::string canonical;
    if (!buildCanonical(bodyNoSign, canonical)) {
        return json{ {"ok", false}, {"err", "bad_body_format"} };
    }

    // 4) 计算 expected sign
    std::string payload = method + "\n" + path + "\n" + canonical;
    std::string expected = Hmac::hmacSha256Hex(AppConfig::APP_SECRET, payload);

    if (expected.empty() || expected != sign) {
        return json{ {"ok", false}, {"err", "sign_mismatch"} };
    }

    // 5) nonce 防重放：写入表，重复 nonce 会触发 UNIQUE 错误 1062
    auto conn = pool_.acquire();
    try {
        // 顺手清理过期 nonce（简单实现）
        {
            std::unique_ptr<sql::PreparedStatement> psDel(
                conn->prepareStatement("DELETE FROM nonces WHERE expire_at < NOW()")
            );
            psDel->executeUpdate();
        }

        std::unique_ptr<sql::PreparedStatement> psIns(
            conn->prepareStatement(
                "INSERT INTO nonces(nonce, expire_at) VALUES(?, DATE_ADD(NOW(), INTERVAL ? SECOND))"
            )
        );
        psIns->setString(1, nonce);
        psIns->setInt(2, AppConfig::NONCE_TTL_SEC);
        psIns->executeUpdate();

        conn->commit();
        pool_.release(std::move(conn));
    }
    catch (const sql::SQLException& e) {
        int code = e.getErrorCode();
        try { conn->rollback(); }
        catch (...) {}
        pool_.release(std::move(conn));

        if (code == 1062) {
            return json{ {"ok", false}, {"err", "nonce_reused"} };
        }
        return json{ {"ok", false}, {"err", "db_error"}, {"detail", e.what()} };
    }

    return json{ {"ok", true} };
}
