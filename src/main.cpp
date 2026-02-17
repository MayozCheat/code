#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <algorithm>
#include <cctype>

#include "db/DbConfig.h"
#include "db/DbPool.h"
#include "services/CardService.h"
#include "services/SessionService.h"
#include "app/Router.h"
#include "http/HttpServer.h"
#include "services/LicenseService.h"
#include "services/AdminService.h"
#include "services/SignService.h"
#include "services/VendorClient.h"


int main() {
    // 1) 从环境变量读取（保留安全默认值）
    auto trim = [](std::string s) {
        auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
        s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
        return s;
        };

    auto envOr = [](const char* k, const char* defv, bool& usedEnv) {
        const char* v = std::getenv(k);
        usedEnv = (v && *v);
        return std::string(usedEnv ? v : defv);
        };

    bool usedEnvUrl = false, usedEnvKey = false, usedEnvMachine = false, usedEnvSecret = false;

    std::string vendorUrl = trim(envOr("VENDOR_URL", "http://127.0.0.1:9001", usedEnvUrl));
    std::string vendorKey = trim(envOr("VENDOR_KEY", "VENDOR-TEST", usedEnvKey));
    std::string machine = trim(envOr("MACHINE_CODE", "", usedEnvMachine));
    std::string vendorSecret = trim(envOr("VENDOR_SECRET", "TEST-SECRET-0123456789abcdef0123456789abcdef", usedEnvSecret));

    std::cout
        << "[VendorConfig] url=" << vendorUrl << (usedEnvUrl ? " (env)" : " (default)") << "\n"
        << "[VendorConfig] key=" << vendorKey << (usedEnvKey ? " (env)" : " (default)") << "\n"
        << "[VendorConfig] machine=" << machine << (usedEnvMachine ? " (env)" : " (default)") << "\n"
        << "[VendorConfig] secret_len=" << vendorSecret.size() << (usedEnvSecret ? " (env)" : " (default)") << "\n";

    if (usedEnvSecret) {
        std::cout << "[VendorConfig] note: VENDOR_SECRET from env overrides code default.\n";
    }

    if (vendorSecret.find("CHANGE-ME") != std::string::npos) {
        std::cerr << "[ERROR] VENDOR_SECRET is still using placeholder, vendor check will fail with sign_mismatch.\n";
        std::cerr << "[ERROR] Set env VENDOR_SECRET to vendor_license.vendor_secret before starting.\n";
        return 1;
    }

    // 2) 启动前必须通过 vendor 授权
    VendorClient::CheckOrExit(vendorUrl, vendorKey, vendorSecret, machine);




    // 3)
    std::cout << "AUTH SERVER M2 (login+token)\n";

    DbPool pool(DbConfig::POOL_SIZE);

    CardService cardSvc(pool);
    SessionService sessionSvc(pool);
    LicenseService licenseSvc(pool);
    AdminService adminSvc(pool);
    SignService signSvc(pool);

    Router router(cardSvc, sessionSvc, licenseSvc, adminSvc, signSvc);

    HttpServer server;

    server.attachRoutes(router);

    const char* ip = "0.0.0.0";
    int port = 8080;

    std::cout << "Listening: http://" << ip << ":" << port << "\n";
    server.listen(ip, port);
   
}
