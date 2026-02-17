#pragma once
#include <string>

namespace Hmac {
    // HMAC-SHA256(secret, msg) -> hex lowercase
    std::string hmacSha256Hex(const std::string& secret, const std::string& msg);
}
