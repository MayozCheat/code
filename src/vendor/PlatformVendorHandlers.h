#pragma once
#include "httplib.h"

class DbPool;
class SignService;

namespace PlatformVendorHandlers {
	void Register(httplib::Server& svr, DbPool& db, SignService& signSvc);
}
