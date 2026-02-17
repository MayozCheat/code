#pragma once
#include <memory>

#include "httplib.h"

class Router;

class HttpServer {
public:
    HttpServer();
    void attachRoutes(const Router& router);

    void listen(const char* ip, int port);

private:
    std::unique_ptr<httplib::Server> svr_;
};
