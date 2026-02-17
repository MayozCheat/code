#include "Token.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

namespace Token {

    static std::string toHex(const std::vector<unsigned char>& buf) {
        std::ostringstream oss;
        for (auto b : buf) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }

    std::string randomHex(size_t nBytes) {
        std::vector<unsigned char> buf(nBytes);

        NTSTATUS st = BCryptGenRandom(
            nullptr,
            buf.data(),
            (ULONG)buf.size(),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (st != 0) {
            // 不引入异常库，直接返回空，由上层报错
            return "";
        }

        return toHex(buf);
    }

}
