#pragma once
#include "httplib.h"
#include "json.hpp"
#include <string>

namespace HttpJson {
    using json = nlohmann::json;

    inline json ok(const json& data = json::object()) {
        json j;
        j["ok"] = true;
        j["data"] = data;
        return j;
    }

    inline json fail(const std::string& err) {
        json j;
        j["ok"] = false;
        j["err"] = err;
        return j;
    }

    inline void reply(httplib::Response& res, const json& j, int status = 200) {
        res.status = status;
        res.set_content(j.dump(), "application/json; charset=utf-8");
    }

    inline json parse(const httplib::Request& req, httplib::Response& res) {
        try {
            if (req.body.empty()) {
                reply(res, fail("empty_body"), 400);
                return json(); // null
            }
            return json::parse(req.body);
        }
        catch (...) {
            reply(res, fail("bad_json"), 400);
            return json();
        }
    }
}
