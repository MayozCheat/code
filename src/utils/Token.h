#pragma once
#include <string>

namespace Token {
    // 生成 nBytes 随机字节，并转为 hex 字符串（长度 = nBytes*2）
    std::string randomHex(size_t nBytes = 32);
}
