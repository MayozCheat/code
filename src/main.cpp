#include <iostream>

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
    // 1) 从配置读（先写死也行）
    std::string vendorUrl = "http://127.0.0.1:9001";
    std::string vendorKey = "VENDOR-TEST";
    std::string machine = "A-SERVER-001";
    std::string vendorSecret = "TEST-SECRET-CHANGE-ME-0123456789abcdef0123456789abcdef";

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
