#pragma once
#include "json.hpp"
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>

#include <openssl/hmac.h>
#include <openssl/evp.h>

using json = nlohmann::json;

// --------- OpenSSL HMAC-SHA256 -> hex(lc) ----------
static std::string HmacSha256Hex_OpenSSL(const std::string& key, const std::string& msg) {
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

// --------- scalar -> string (for sign) ----------
static std::string SignScalarToString(const json& v) {
    if (v.is_string()) return v.get<std::string>();
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_number_integer()) return std::to_string(v.get<int64_t>());
    if (v.is_number_unsigned()) return std::to_string(v.get<uint64_t>());

    if (v.is_number_float()) {
        // 尽量稳定（一般你接口里不会用 float）
        std::ostringstream oss;
        oss.setf(std::ios::fixed);
        oss.precision(6);
        oss << v.get<double>();
        std::string s = oss.str();
        while (s.size() > 1 && s.back() == '0') s.pop_back();
        if (!s.empty() && s.back() == '.') s.pop_back();
        return s;
    }
    return ""; // object/array 不支持
}

// --------- build canonical: key=value\n (sorted, exclude sign) ----------
static bool BuildCanonicalNoSign(const json& body, std::string& outCanonical) {
    if (!body.is_object()) return false;

    std::vector<std::string> keys;
    keys.reserve(body.size());
    for (auto it = body.begin(); it != body.end(); ++it) {
        if (it.key() == "sign") continue;
        keys.push_back(it.key());
    }
    std::sort(keys.begin(), keys.end()); // ordinal

    std::string s;
    for (const auto& k : keys) {
        const auto& v = body.at(k);
        if (v.is_object() || v.is_array()) return false;

        std::string vs = SignScalarToString(v);
        s += k;
        s += "=";
        s += vs;
        s += "\n";
    }
    outCanonical = std::move(s);
    return true;
}

// --------- calc sign(method, path, body-no-sign) ----------
static bool CalcSignHex(const std::string& secret,
    const std::string& method,
    const std::string& path,
    const json& body,
    std::string& outSignHex,
    std::string* outCanonical = nullptr,
    std::string* outPayload = nullptr) {

    std::string canonical;
    if (!BuildCanonicalNoSign(body, canonical)) return false;

    std::string payload = method + "\n" + path + "\n" + canonical;

    if (outCanonical) *outCanonical = canonical;
    if (outPayload) *outPayload = payload;

    outSignHex = HmacSha256Hex_OpenSSL(secret, payload);
    return true;
}

// --------- verify sign ----------
static bool VerifySignHex(const std::string& secret,
    const std::string& method,
    const std::string& path,
    const json& body,
    std::string& outErr,
    bool debugReturnExpected = false,
    std::string* outExpected = nullptr,
    std::string* outCanonical = nullptr) {

    outErr.clear();
    if (!body.contains("sign") || !body["sign"].is_string()) {
        outErr = "missing_sign";
        return false;
    }

    std::string expected, canonical;
    if (!CalcSignHex(secret, method, path, body, expected, &canonical, nullptr)) {
        outErr = "bad_canonical";
        return false;
    }

    std::string got = body["sign"].get<std::string>();
    if (outExpected) *outExpected = expected;
    if (outCanonical) *outCanonical = canonical;

    if (got != expected) {
        outErr = "sign_mismatch";
        return false;
    }
    return true;
}
