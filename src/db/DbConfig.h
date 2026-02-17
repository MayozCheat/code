#pragma once

// ====== 数据库配置：只在这里改 ======
namespace DbConfig {
    inline constexpr const char* HOST = "tcp://127.0.0.1:3306";
    inline constexpr const char* USER = "authsvc";
    inline constexpr const char* PASS = "AuthSvc@123456";
    inline constexpr const char* NAME = "login_system";

    inline constexpr int POOL_SIZE = 16; // 你可以调回 8/16
}

namespace AppConfig {
    // 管理后台口令（/admin/card/create）
    inline constexpr const char* ADMIN_KEY = "2222112176-AdminKey-2026";

    // 卡密随机强度（bytes -> hex长度=bytes*2）
    inline constexpr int CARD_KEY_BYTES = 12;

    // 签名密钥（M5：HMAC 防重放）
    inline constexpr const char* APP_SECRET = "2222112176-Secret-For-HMAC-2026-30659653-1111123zq..-515682287-339762633";

    // ts 允许误差（秒）
    inline constexpr int SIGN_MAX_SKEW_SEC = 300;//开VPN测试会有8小时时差,用30000   正式上线用60

    // nonce 存活时间（秒）
    inline constexpr int NONCE_TTL_SEC = 120;

}