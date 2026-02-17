#include "DbPool.h"
#include "DbConfig.h"

inline constexpr const char* DB_NAME = "vendor_auth";

DbPool::DbPool(int poolSize) {
    init(poolSize);
}

void DbPool::init(int poolSize) {
    std::lock_guard<std::mutex> lk(m_);

    sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();

    for (int i = 0; i < poolSize; ++i) {
        try {
            auto c = std::unique_ptr<sql::Connection>(
                driver->connect(DbConfig::HOST, DbConfig::USER, DbConfig::PASS)
            );

			c->setSchema(DB_NAME);//改为自己的库名
            c->setAutoCommit(false);

            pool_.push(std::move(c));
        }
        catch (const sql::SQLException& e) {
            std::cerr << "[DbPool] connect failed at index " << i << "\n"
                << "  what: " << e.what() << "\n"
                << "  errCode: " << e.getErrorCode() << "\n"
                << "  sqlState: " << e.getSQLState() << "\n";
            throw; // 让程序直接退出，但你能看到真实原因
        }
    }
}

std::unique_ptr<sql::Connection> DbPool::acquire() {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait(lk, [&] { return !pool_.empty(); });
    auto conn = std::move(pool_.front());
    pool_.pop();
    return conn;
}

void DbPool::release(std::unique_ptr<sql::Connection> conn) {
    // 归还前尽量把连接状态清干净，避免上一个请求残留事务
    try { conn->rollback(); }
    catch (...) {}
    try { conn->setAutoCommit(false); }
    catch (...) {}

    {
        std::lock_guard<std::mutex> lk(m_);
        pool_.push(std::move(conn));
    }
    cv_.notify_one();
}
