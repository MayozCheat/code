#pragma once
#include "httplib.h"

class DbPool;

void SetupVendorRoutes(httplib::Server& svr, DbPool& dbPool);
