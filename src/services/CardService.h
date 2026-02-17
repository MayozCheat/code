#pragma once
#include <string>
#include "json.hpp"

class DbPool;

class CardService {
public:
    explicit CardService(DbPool& pool);

    // token + machine_code + card_key
    nlohmann::json activateCardByToken(
        const std::string& token,
        const std::string& machineCode,
        const std::string& cardKey,
        const std::string& ip
    );

private:
    DbPool& pool_;
};
