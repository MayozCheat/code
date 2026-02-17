#include "Router.h"
#include "../http/JsonHelpers.h"
#include "../services/CardService.h"
#include "../services/SessionService.h"
#include "../services/LicenseService.h"
#include "../services/AdminService.h"
#include "../services/SignService.h"


Router::Router(CardService& cardSvc, SessionService& sessionSvc, LicenseService& licenseSvc, AdminService& adminSvc, SignService& signSvc)
    : cardSvc_(cardSvc), sessionSvc_(sessionSvc), licenseSvc_(licenseSvc), adminSvc_(adminSvc), signSvc_(signSvc) {
}


static bool RequireSign(SignService& signSvc,
    const std::string& method,
    const std::string& path,
    const HttpJson::json& in,
    httplib::Response& res) {
    auto vr = signSvc.verify(method, path, in);
    if (!vr.contains("ok") || !vr["ok"].get<bool>()) {
        HttpJson::reply(res, vr, 401);
        return false;
    }
    return true;
}

void Router::bind(httplib::Server& svr) const {

    svr.Get("/debug/time", [](const httplib::Request&, httplib::Response& res) {
        long long now = (long long)std::time(nullptr);
        HttpJson::reply(res, HttpJson::ok({
            {"server_unix", now}
            }));
        });

    // -------------------------
    // GET /ping
    // -------------------------
    svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        HttpJson::reply(res, HttpJson::ok({ {"msg", "pong"} }));
        });

    // 允许跨域（开发期全放开）
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Headers", "Content-Type"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"}
        });

    // 处理 OPTIONS 预检请求（对于跨域的 HTTP 请求需要响应）
    svr.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
        });

    // -------------------------
    // POST /login
    // JSON: {"username":"admin","password":"123456"}
    // -------------------------
    svr.Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
        HttpJson::json in;
        if (!HttpJson::parseBody(req, in)) {
            HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
            return;
        }
        if (!in.contains("username") || !in.contains("password")) {
            HttpJson::reply(res, HttpJson::fail("bad_request", "缺少username/password"), 400);
            return;
        }

        std::string username = in["username"].get<std::string>();
        std::string password = in["password"].get<std::string>();
        std::string ip = req.remote_addr;

        auto out = sessionSvc_.login(username, password, ip);
        HttpJson::reply(res, out, 200);
        });

    // -------------------------
    // POST /card/activate  (token版)
    // JSON: {"token":"...","machine_code":"PC-001","card_key":"NEWCARD-000001"}
    // -------------------------
    svr.Post("/card/activate", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            HttpJson::json in;
            if (!HttpJson::parseBody(req, in)) {
                HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                return;
            }
            if (!RequireSign(signSvc_, "POST", "/card/activate", in, res)) return;

            if (!in.contains("token") || !in["token"].is_string() ||
                !in.contains("machine_code") || !in["machine_code"].is_string() ||
                !in.contains("card_key") || !in["card_key"].is_string()) {
                HttpJson::reply(res, HttpJson::fail("bad_request", "token/machine_code/card_key 必须是字符串"), 400);
                return;
            }

            std::string token = in["token"].get<std::string>();
            std::string machine = in["machine_code"].get<std::string>();
            std::string cardKey = in["card_key"].get<std::string>();
            std::string ip = req.remote_addr;

            auto out = cardSvc_.activateCardByToken(token, machine, cardKey, ip);
            HttpJson::reply(res, out, 200);
        }
        catch (const std::exception& e) {
            // 关键：把异常原因返回给你看
            HttpJson::reply(res, HttpJson::json{
                {"ok", false},
                {"err", "unhandled_exception"},
                {"detail", e.what()}
                }, 500);
        }
        catch (...) {
            HttpJson::reply(res, HttpJson::json{
                {"ok", false},
                {"err", "unknown_exception"}
                }, 500);
        }
        });

    svr.Post("/admin/card/list", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            HttpJson::json in;
            if (!HttpJson::parseBody(req, in)) {
                HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                return;
            }

            if (!RequireSign(signSvc_, "POST", "/admin/card/list", in, res)) return;

            if (!in.contains("admin_key") || !in["admin_key"].is_string()) {
                HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key"), 400);
                return;
            }

            int page = in.contains("page") ? in["page"].get<int>() : 1;
            int pageSize = in.contains("page_size") ? in["page_size"].get<int>() : 10;
            int isUsed = in.contains("is_used") ? in["is_used"].get<int>() : -1; // -1/0/1
            std::string keyword = in.contains("keyword") ? in["keyword"].get<std::string>() : "";

            std::string adminKey = in["admin_key"].get<std::string>();
            std::string ip = req.remote_addr;

            auto out = adminSvc_.listCards(adminKey, page, pageSize, isUsed, keyword, ip);
            HttpJson::reply(res, out, 200);
        }
        catch (const std::exception& e) {
            HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
        }
        });
        svr.Post("/admin/log/list", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            HttpJson::json in;
            if (!HttpJson::parseBody(req, in)) {
                HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                return;
            }

            if (!RequireSign(signSvc_, "POST", "/admin/log/list", in, res)) return;

            if (!in.contains("admin_key") || !in["admin_key"].is_string()) {
                HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key"), 400);
                return;
            }

            int page = in.contains("page") ? in["page"].get<int>() : 1;
            int pageSize = in.contains("page_size") ? in["page_size"].get<int>() : 20;

            std::string action = in.contains("action") ? in["action"].get<std::string>() : "";
            int userId = in.contains("user_id") ? in["user_id"].get<int>() : -1;
            std::string ipKeyword = in.contains("ip") ? in["ip"].get<std::string>() : "";

            std::string adminKey = in["admin_key"].get<std::string>();
            std::string ip = req.remote_addr;

            auto out = adminSvc_.listLogs(adminKey, page, pageSize, action, userId, ipKeyword, ip);
            HttpJson::reply(res, out, 200);
        }
        catch (const std::exception& e) {
            HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
        }
        });

        svr.Post("/admin/user/list", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                HttpJson::json in;
                if (!HttpJson::parseBody(req, in)) {
                    HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                    return;
                }

                if (!RequireSign(signSvc_, "POST", "/admin/user/list", in, res)) return;

                if (!in.contains("admin_key") || !in["admin_key"].is_string()) {
                    HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key"), 400);
                    return;
                }

                int page = in.contains("page") ? in["page"].get<int>() : 1;
                int pageSize = in.contains("page_size") ? in["page_size"].get<int>() : 10;
                std::string keyword = in.contains("keyword") ? in["keyword"].get<std::string>() : "";

                std::string adminKey = in["admin_key"].get<std::string>();
                std::string ip = req.remote_addr;

                auto out = adminSvc_.listUsers(adminKey, page, pageSize, keyword, ip);
                HttpJson::reply(res, out, 200);
            }
            catch (const std::exception& e) {
                HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
            }
            });


        svr.Post("/admin/user/ban", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                HttpJson::json in;
                if (!HttpJson::parseBody(req, in)) {
                    HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                    return;
                }

                if (!RequireSign(signSvc_, "POST", "/admin/user/ban", in, res)) return;

                if (!in.contains("admin_key") || !in["admin_key"].is_string() ||
                    !in.contains("user_id") || !in["user_id"].is_number_integer() ||
                    !in.contains("status") || !in["status"].is_number_integer()) {
                    HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key/user_id/status"), 400);
                    return;
                }

                std::string adminKey = in["admin_key"].get<std::string>();
                int userId = in["user_id"].get<int>();
                int status = in["status"].get<int>();
                std::string ip = req.remote_addr;

                auto out = adminSvc_.setUserStatus(adminKey, userId, status, ip);
                HttpJson::reply(res, out, 200);
            }
            catch (const std::exception& e) {
                HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
            }
            });

        svr.Post("/admin/user/reset_machine", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                HttpJson::json in;
                if (!HttpJson::parseBody(req, in)) {
                    HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                    return;
                }

                if (!RequireSign(signSvc_, "POST", "/admin/user/reset_machine", in, res)) return;

                if (!in.contains("admin_key") || !in["admin_key"].is_string() ||
                    !in.contains("user_id") || !in["user_id"].is_number_integer()) {
                    HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key/user_id"), 400);
                    return;
                }

                std::string adminKey = in["admin_key"].get<std::string>();
                int userId = in["user_id"].get<int>();
                std::string ip = req.remote_addr;

                auto out = adminSvc_.resetUserMachine(adminKey, userId, ip);
                HttpJson::reply(res, out, 200);
            }
            catch (const std::exception& e) {
                HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
            }
            });


        svr.Post("/admin/user/add_days", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                HttpJson::json in;
                if (!HttpJson::parseBody(req, in)) {
                    HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                    return;
                }

                if (!RequireSign(signSvc_, "POST", "/admin/user/add_days", in, res)) return;

                if (!in.contains("admin_key") || !in["admin_key"].is_string() ||
                    !in.contains("user_id") || !in["user_id"].is_number_integer() ||
                    !in.contains("days") || !in["days"].is_number_integer()) {
                    HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key/user_id/days"), 400);
                    return;
                }

                std::string adminKey = in["admin_key"].get<std::string>();
                int userId = in["user_id"].get<int>();
                int days = in["days"].get<int>();
                std::string ip = req.remote_addr;

                auto out = adminSvc_.addUserDays(adminKey, userId, days, ip);
                HttpJson::reply(res, out, 200);
            }
            catch (const std::exception& e) {
                HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
            }
            });

        svr.Post("/admin/card/disable", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                HttpJson::json in;
                if (!HttpJson::parseBody(req, in)) {
                    HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                    return;
                }

                if (!RequireSign(signSvc_, "POST", "/admin/card/disable", in, res)) return;

                if (!in.contains("admin_key") || !in["admin_key"].is_string() ||
                    !in.contains("card_key") || !in["card_key"].is_string()) {
                    HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key/card_key"), 400);
                    return;
                }

                std::string adminKey = in["admin_key"].get<std::string>();
                std::string cardKey = in["card_key"].get<std::string>();
                std::string reason = in.contains("reason") ? in["reason"].get<std::string>() : "";
                std::string ip = req.remote_addr;

                auto out = adminSvc_.disableCard(adminKey, cardKey, reason, ip);
                HttpJson::reply(res, out, 200);
            }
            catch (const std::exception& e) {
                HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
            }
            });

        svr.Post("/admin/card/note", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                HttpJson::json in;
                if (!HttpJson::parseBody(req, in)) {
                    HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
                    return;
                }

                if (!RequireSign(signSvc_, "POST", "/admin/card/note", in, res)) return;

                if (!in.contains("admin_key") || !in["admin_key"].is_string() ||
                    !in.contains("card_key") || !in["card_key"].is_string() ||
                    !in.contains("note") || !in["note"].is_string()) {
                    HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key/card_key/note"), 400);
                    return;
                }

                std::string adminKey = in["admin_key"].get<std::string>();
                std::string cardKey = in["card_key"].get<std::string>();
                std::string note = in["note"].get<std::string>();
                std::string ip = req.remote_addr;

                auto out = adminSvc_.setCardNote(adminKey, cardKey, note, ip);
                HttpJson::reply(res, out, 200);
            }
            catch (const std::exception& e) {
                HttpJson::reply(res, HttpJson::json{ {"ok", false}, {"err", "unhandled_exception"}, {"detail", e.what()} }, 500);
            }
            });


    // -------------------------
    // POST /license/check
    // JSON: {"token":"...","machine_code":"PC-001"}
    // -------------------------
    svr.Post("/license/check", [this](const httplib::Request& req, httplib::Response& res) {
        HttpJson::json in;
        if (!HttpJson::parseBody(req, in)) {
            HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
            return;
        }
        if (!RequireSign(signSvc_, "POST", "/license/check", in, res)) return;
        if (!in.contains("token") || !in.contains("machine_code")) {
            HttpJson::reply(res, HttpJson::fail("bad_request", "缺少token/machine_code"), 400);
            return;
        }

        std::string token = in["token"].get<std::string>();
        std::string machine = in["machine_code"].get<std::string>();

        auto out = licenseSvc_.check(token, machine);
        HttpJson::reply(res, out, 200);
        });

    // POST /admin/card/create
    // JSON: {"admin_key":"...","days":30,"count":10,"prefix":"VIP"}  (prefix 可选)
    svr.Post("/admin/card/create", [this](const httplib::Request& req, httplib::Response& res) {
        HttpJson::json in;
        if (!HttpJson::parseBody(req, in)) {
            HttpJson::reply(res, HttpJson::fail("bad_json", "JSON解析失败"), 400);
            return;
        }
        if (!RequireSign(signSvc_, "POST", "/admin/card/create", in, res)) return;
        if (!in.contains("admin_key") || !in.contains("days") || !in.contains("count")) {
            HttpJson::reply(res, HttpJson::fail("bad_request", "缺少admin_key/days/count"), 400);
            return;
        }

        std::string adminKey = in["admin_key"].get<std::string>();
        int days = in["days"].get<int>();
        int count = in["count"].get<int>();
        std::string prefix = in.contains("prefix") ? in["prefix"].get<std::string>() : "";

        std::string ip = req.remote_addr;

        auto out = adminSvc_.createCards(adminKey, days, count, prefix, ip);
        HttpJson::reply(res, out, 200);
        });



}

