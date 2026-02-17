#include "HttpServer.h"
#include "../app/Router.h"

HttpServer::HttpServer()
    : svr_(std::make_unique<httplib::Server>()) {
}

void HttpServer::attachRoutes(const Router& router) {
    router.bind(*svr_);
}

void HttpServer::listen(const char* ip, int port) {
    svr_->listen(ip, port);
}
