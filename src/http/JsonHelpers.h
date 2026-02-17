#pragma once
#include <string>

#include "httplib.h"
#include "json.hpp"

namespace HttpJson {
    using json = nlohmann::json;

    inline bool parseBody(const httplib::Request& req, json& out) {
        try {
            out = json::parse(req.body);
            return true;
        }
        catch (...) {
            return false;
        }
    }

    inline void reply(httplib::Response& res, const json& j, int code = 200) {
        res.status = code;
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.set_content(j.dump(), "application/json; charset=utf-8");
    }

    inline json ok(const json& data = json::object()) {
        return json{ {"ok", true}, {"data", data} };
    }

    inline json fail(const std::string& err, const std::string& msg = "") {
        json j;
        j["ok"] = false;
        j["err"] = err;
        if (!msg.empty()) j["msg"] = msg;
        return j;
    }
}
