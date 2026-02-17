#pragma once
#include "httplib.h"

class CardService;
class SessionService;
class LicenseService;
class AdminService;
class SignService;

class Router {
public:
    Router(CardService& cardSvc, SessionService& sessionSvc, LicenseService& licenseSvc, AdminService& adminSvc, SignService& signSvc);
    void bind(httplib::Server& svr) const;

private:
    CardService& cardSvc_;
    SessionService& sessionSvc_;
    LicenseService& licenseSvc_;
    AdminService& adminSvc_;
    SignService& signSvc_;
};