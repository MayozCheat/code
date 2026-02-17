#pragma once
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>

#include <mysql/jdbc.h>

class DbPool {
public:
    explicit DbPool(int poolSize);

    // 取一个连接（没有可用连接会等待）
    std::unique_ptr<sql::Connection> acquire();

    // 归还连接（归还前会尝试 rollback 清理状态）
    void release(std::unique_ptr<sql::Connection> conn);

private:
    void init(int poolSize);

private:
    std::mutex m_;
    std::condition_variable cv_;
    std::queue<std::unique_ptr<sql::Connection>> pool_;
};
