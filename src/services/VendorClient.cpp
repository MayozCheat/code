#include <openssl/hmac.h>
#include <openssl/evp.h>
#pragma comment(lib, "libcrypto.lib")

#include "VendorClient.h"
#include "json.hpp"

#include <windows.h>
#include <winhttp.h>
#include <chrono>
#include <iostream>
#include <sstream>
#include <vector>
#include <random>
#include <cctype>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

// ---------- 工具：UTC Unix 秒 ----------
static int64_t NowUnixSecondsUTC() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// ---------- 工具：随机 16 hex nonce ----------
static std::string NewNonce16Hex() {
    static const char* hex = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 15);
    std::string s;
    s.reserve(16);
    for (int i = 0; i < 16; ++i) s.push_back(hex[dis(gen)]);
    return s;
}

// ---------- URL 解析：仅支持 http://host:port ----------
struct ParsedUrl {
    std::wstring host;
    INTERNET_PORT port = 0;
    bool ok = false;
};

static ParsedUrl ParseHttpUrl(const std::string& url) {
    ParsedUrl p;
    // 仅支持 http://
    const std::string prefix = "http://";
    if (url.rfind(prefix, 0) != 0) return p;

    std::string rest = url.substr(prefix.size()); // host:port or host
    std::string host, portStr;

    auto pos = rest.find('/');
    if (pos != std::string::npos) rest = rest.substr(0, pos);

    auto c = rest.find(':');
    if (c == std::string::npos) {
        host = rest;
        portStr = "80";
    }
    else {
        host = rest.substr(0, c);
        portStr = rest.substr(c + 1);
    }

    if (host.empty() || portStr.empty()) return p;

    int port = std::atoi(portStr.c_str());
    if (port <= 0 || port > 65535) return p;

    // 转宽字串
    int wlen = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, nullptr, 0);
    std::wstring whost(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, whost.data(), wlen);
    if (!whost.empty() && whost.back() == L'\0') whost.pop_back();

    p.host = whost;
    p.port = (INTERNET_PORT)port;
    p.ok = true;
    return p;
}

static std::string UrlEncodeUtf8(const std::string& s) {
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

static std::string TrimAscii(const std::string& s) {
    size_t l = 0, r = s.size();
    while (l < r && std::isspace((unsigned char)s[l])) ++l;
    while (r > l && std::isspace((unsigned char)s[r - 1])) --r;
    return s.substr(l, r - l);
}

static std::string NormalizeSecret(const std::string& raw) {
    std::string s = TrimAscii(raw);
    // 兼容部署时误加引号："secret" 或 'secret'
    if (s.size() >= 2) {
        char a = s.front();
        char b = s.back();
        if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
            s = s.substr(1, s.size() - 2);
            s = TrimAscii(s);
        }
    }
    return s;
}

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

static std::string ScalarToStringForSign(const json& v) {
    if (v.is_string()) return UrlEncodeUtf8(v.get<std::string>());
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_number_integer()) return std::to_string(v.get<long long>());
    if (v.is_number_unsigned()) return std::to_string(v.get<unsigned long long>());
    if (v.is_number_float()) {
        // 与 vendor 端保持一致：不使用 std::to_string(固定 6 位)
        // 避免出现 "1.500000" vs "1.5" 的签名不一致。
        std::ostringstream oss;
        oss << v.get<double>();
        return oss.str();
    }
    if (v.is_null()) return "null";
    return "";
}

// body 里可能已经有 sign，但 canonical 必须忽略 sign
static bool BuildCanonicalNoSign(const json& body, std::string& outCanonical) {
    if (!body.is_object()) return false;

    std::vector<std::string> keys;
    keys.reserve(body.size());
    for (auto it = body.begin(); it != body.end(); ++it) {
        if (it.key() == "sign") continue;
        keys.push_back(it.key());
    }
    std::sort(keys.begin(), keys.end()); // Ordinal

    std::string s;
    for (auto& k : keys) {
        const auto& v = body.at(k);
        if (v.is_object() || v.is_array()) return false;
        s += k;
        s += "=";
        s += ScalarToStringForSign(v);
        s += "\n";
    }
    outCanonical = std::move(s);
    return true;
}

static std::string MakeSign(const std::string& method,
    const std::string& path,
    const json& bodyNoSign,
    const std::string& secret) {
    std::string canonical;
    if (!BuildCanonicalNoSign(bodyNoSign, canonical)) return "";
    std::string payload = method + "\n" + path + "\n" + canonical;
    return HmacSha256Hex(secret, payload);
}


// ---------- WinHTTP POST JSON ----------
static bool WinHttpPostJson(const ParsedUrl& p,
    const std::wstring& path,      // L"/vendor/check"
    const std::string& bodyUtf8,    // JSON
    int timeoutMs,
    std::string& outRespUtf8,
    std::string& outErr) {
    outRespUtf8.clear();
    outErr.clear();

    HINTERNET hSession = WinHttpOpen(L"VendorClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    auto SetWinHttpError = [&](const char* where) {
        DWORD le = GetLastError();
        outErr = std::string(where) + " failed le=" + std::to_string(le);
        };

    if (!hSession) {
        SetWinHttpError("WinHttpOpen");
        return false;
    }

    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, p.host.c_str(), p.port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        SetWinHttpError("WinHttpConnect");
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        SetWinHttpError("WinHttpOpenRequest");
        return false;
    }

    std::wstring headers = L"Content-Type: application/json; charset=utf-8\r\n";

    BOOL b = WinHttpSendRequest(hRequest,
        headers.c_str(),
        (DWORD)headers.size(),
        (LPVOID)bodyUtf8.data(),
        (DWORD)bodyUtf8.size(),
        (DWORD)bodyUtf8.size(),
        0);

    if (!b) {
        SetWinHttpError("WinHttpSendRequest");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    b = WinHttpReceiveResponse(hRequest, nullptr);
    if (!b) {
        SetWinHttpError("WinHttpReceiveResponse");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // 读响应
    std::string resp;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;

        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) break;
        resp.append(buf.data(), buf.data() + read);
    }

    outRespUtf8 = std::move(resp);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

// ---------- 对外：VendorClient::Check ----------
VendorCheckResult VendorClient::Check(const std::string& vendorUrl,
    const std::string& vendorKey,
    const std::string& vendorSecret,
    const std::string& machineCode,
    int timeoutMs) {
    VendorCheckResult r;

    ParsedUrl p = ParseHttpUrl(vendorUrl);
    if (!p.ok) { r.err = "bad_vendor_url"; return r; }

    const std::string path = "/vendor/check";
    const std::string cleanSecret = NormalizeSecret(vendorSecret);
    if (cleanSecret.empty()) {
        r.err = "bad_vendor_secret";
        return r;
    }

    json req;
    req["vendor_key"] = vendorKey;
    req["machine_code"] = machineCode;
    req["ts"] = (int64_t)NowUnixSecondsUTC();
    req["nonce"] = NewNonce16Hex();

    // 生成 sign（注意：path/method 必须与服务端验证一致）
    std::string sign = MakeSign("POST", path, req, cleanSecret);
    if (sign.empty()) {
        r.err = "make_sign_failed";
        return r;
    }
    req["sign"] = sign;

    std::string body = req.dump();

    std::string resp, err;
    if (!WinHttpPostJson(p, L"/vendor/check", body, timeoutMs, resp, err)) {
        // 这里最好把 WinHTTP 的 GetLastError 打出来，你之前已经做过 le=xxxx，可继续保留
        r.err = "http_failed:" + err;
        return r;
    }

    r.raw = resp;

    try {
        auto j = json::parse(resp);
        if (j.contains("ok") && j["ok"].get<bool>()) {
            r.ok = true;
            if (j.contains("data") && j["data"].contains("expire_time")) {
                r.expire_time = j["data"]["expire_time"].get<std::string>();
            }
        }
        else {
            if (j.contains("err")) r.err = j["err"].get<std::string>();
            else r.err = "vendor_check_failed";
        }
    }
    catch (...) {
        r.err = "bad_vendor_response";
    }

    return r;
}


void VendorClient::CheckOrExit(const std::string& vendorUrl,
    const std::string& vendorKey,
    const std::string& vendorSecret,
    const std::string& machineCode,
    int timeoutMs) {
    const int kMaxTry = 30;
    const int kSleepMs = 1000;

    for (int i = 1; i <= kMaxTry; ++i) {
        auto r = Check(vendorUrl, vendorKey, vendorSecret, machineCode, timeoutMs);
        if (r.ok) {
            std::cout << "[Vendor] OK, expire_time=" << r.expire_time << "\n";
            return;
        }

        std::cerr << "[Vendor] check failed (" << i << "/" << kMaxTry << "): " << r.err << "\n";
        if (!r.raw.empty()) std::cerr << "[Vendor] raw: " << r.raw << "\n";

        // 只对“网络类问题”重试（你之前见过 12029）
        bool isNet =
            (r.err.find("le=12029") != std::string::npos) ||
            (r.err.find("le=12007") != std::string::npos);

        if (r.err == "sign_mismatch") {
            std::cerr << "[Vendor] hint: check VENDOR_KEY/VENDOR_SECRET with DB vendor_license.vendor_key/vendor_secret and remove accidental leading/trailing spaces.\n";
        }

        if (!isNet) {
            std::cerr << "Program will exit.\n";
            std::exit(1);
        }

        Sleep(kSleepMs);
    }

    std::cerr << "[Vendor] vendor server not reachable, exit.\n";
    std::exit(1);
}

