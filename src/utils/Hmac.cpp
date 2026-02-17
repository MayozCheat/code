#include "Hmac.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

static std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

namespace Hmac {

    std::string hmacSha256Hex(const std::string& secret, const std::string& msg) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;

        DWORD cbData = 0, cbHashObject = 0, cbHash = 0;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return "";

        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        std::vector<unsigned char> hashObject(cbHashObject);
        std::vector<unsigned char> hash(cbHash);

        if (BCryptCreateHash(
            hAlg, &hHash,
            hashObject.data(), (ULONG)hashObject.size(),
            (PUCHAR)secret.data(), (ULONG)secret.size(),
            0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        if (BCryptHashData(hHash, (PUCHAR)msg.data(), (ULONG)msg.size(), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        if (BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return toHex(hash.data(), hash.size());
    }

}
