#pragma once
#include <string>

struct AppConfig {
    // 平台管理员 key（你自己用，不给A）
    inline static const std::string ADMIN_KEY = "2222112176-AdminKey-2026";

    // 服务监听
    inline static const char* LISTEN_HOST = "0.0.0.0";
    inline static const int   LISTEN_PORT = 9001;

    // 数据库连接池大小（你 DbPool(int) 用它）
    inline static const int DB_POOL_SIZE = 8;

    // vendor/check 的 ts 允许误差（秒）
    static const int64_t VENDOR_TS_WINDOW_SEC = 60;      // ts 允许误差
    static const int64_t NONCE_KEEP_SEC = 10 * 60; // nonce 保留 10 分钟
};
