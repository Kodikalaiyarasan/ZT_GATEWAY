// ============================================================
// Zero Trust Gateway — High-Performance C++ Reverse Proxy
// ============================================================
// Intercepts all HTTP traffic on port 8000.  Before forwarding
// to the internal target backend it:
//   1. Queries the Control Plane (/v1/evaluate) for authorization.
//   2. Optionally sends file uploads to the Sandbox Service (/scan).
//   3. Rejects denied or unclean requests with 403 / 422.
// ============================================================

#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>

// cpp-httplib — header-only HTTP server/client
#include "httplib.h"

// nlohmann/json — header-only JSON
#include "nlohmann/json.hpp"

// libcurl — used for outbound HTTP calls (multipart support)
#include <curl/curl.h>

using json = nlohmann::json;

// ── Configuration (read from environment or defaults) ────────

static std::string env(const char* key, const char* fallback) {
    const char* val = std::getenv(key);
    return val ? std::string(val) : std::string(fallback);
}

static const std::string CONTROL_PLANE_HOST = env("CONTROL_PLANE_HOST", "control-plane");
static const int         CONTROL_PLANE_PORT = std::stoi(env("CONTROL_PLANE_PORT", "8081"));
static const std::string SANDBOX_HOST       = env("SANDBOX_HOST",       "sandbox-service");
static const int         SANDBOX_PORT       = std::stoi(env("SANDBOX_PORT",       "8002"));
static const std::string TARGET_HOST        = env("TARGET_HOST",        "target-backend");
static const int         TARGET_PORT        = std::stoi(env("TARGET_PORT",        "8080"));
static const int         LISTEN_PORT        = std::stoi(env("PROXY_PORT",         "8000"));

// ── cURL write callback ──────────────────────────────────────

static size_t curl_write_cb(void* contents, size_t size, size_t nmemb, std::string* out) {
    size_t total = size * nmemb;
    out->append(static_cast<char*>(contents), total);
    return total;
}

// ── Helper: POST JSON via cpp-httplib ────────────────────────

static json call_control_plane(const json& payload) {
    httplib::Client cli(CONTROL_PLANE_HOST, CONTROL_PLANE_PORT);
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(5, 0);

    auto res = cli.Post("/v1/evaluate", payload.dump(), "application/json");
    if (res && res->status == 200) {
        return json::parse(res->body);
    }
    if (res) {
        std::cerr << "[proxy] control-plane returned status " << res->status << "\n";
    } else {
        std::cerr << "[proxy] control-plane unreachable: " << httplib::to_string(res.error()) << "\n";
    }
    return json{{"allowed", false}, {"reason", "Control plane unreachable — fail-closed"}};
}

// ── Helper: POST multipart file to Sandbox via libcurl ───────

static json call_sandbox(const std::string& filename,
                         const std::string& file_data,
                         const std::string& content_type) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return json{{"clean", false}, {"threat_found", "Sandbox client init failed"}};
    }

    std::string response_body;
    std::string url = "http://" + SANDBOX_HOST + ":" + std::to_string(SANDBOX_PORT) + "/scan";

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_data(part, file_data.data(), file_data.size());
    curl_mime_filename(part, filename.c_str());
    curl_mime_type(part, content_type.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode rc = curl_easy_perform(curl);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        std::cerr << "[proxy] sandbox call failed: " << curl_easy_strerror(rc) << "\n";
        return json{{"clean", false}, {"threat_found", "Sandbox unreachable"}};
    }

    try {
        return json::parse(response_body);
    } catch (...) {
        return json{{"clean", false}, {"threat_found", "Invalid sandbox response"}};
    }
}

// ── Helper: proxy the authorised request to the target ───────

static void proxy_to_target(const httplib::Request& req, httplib::Response& res) {
    httplib::Client target(TARGET_HOST, TARGET_PORT);
    target.set_connection_timeout(10, 0);
    target.set_read_timeout(30, 0);

    httplib::Headers hdrs;
    for (auto& h : req.headers) {
        // Skip hop-by-hop headers
        if (h.first == "Host" || h.first == "Connection") continue;
        hdrs.emplace(h.first, h.second);
    }

    httplib::Result result;
    if (req.method == "GET") {
        result = target.Get(req.path, hdrs);
    } else if (req.method == "POST") {
        result = target.Post(req.path, hdrs, req.body, req.get_header_value("Content-Type"));
    } else if (req.method == "PUT") {
        result = target.Put(req.path, hdrs, req.body, req.get_header_value("Content-Type"));
    } else if (req.method == "DELETE") {
        result = target.Delete(req.path, hdrs);
    } else {
        result = target.Get(req.path, hdrs);  // fallback
    }

    if (result) {
        res.status = result->status;
        res.body   = result->body;
        for (auto& h : result->headers) {
            res.set_header(h.first, h.second);
        }
    } else {
        res.status = 502;
        res.set_content(R"({"error":"Bad Gateway — target backend unreachable"})", "application/json");
    }
}

// ── Main ─────────────────────────────────────────────────────

int main() {
    curl_global_init(CURL_GLOBAL_ALL);

    httplib::Server svr;

    // Catch-all handler for every method and path
    auto handler = [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "[proxy] " << req.method << " " << req.path
                  << " from " << req.remote_addr << "\n";

        // ── Extract identity context from headers ────────────
        std::string auth      = req.get_header_value("Authorization");
        std::string client_ip = req.get_header_value("X-Client-IP");
        std::string user_id   = req.get_header_value("X-User-ID");
        std::string role      = req.get_header_value("X-Role");
        std::string risk_str  = req.get_header_value("X-Risk-Score");

        if (client_ip.empty()) client_ip = req.remote_addr;
        if (user_id.empty())   user_id   = "anonymous";
        if (role.empty())      role      = "user";

        int risk_score = 0;
        if (!risk_str.empty()) {
            try { risk_score = std::stoi(risk_str); } catch (...) {}
        }

        bool jwt_valid = !auth.empty();  // simplified JWT presence check

        // ── 1. Query Control Plane ───────────────────────────
        json eval_payload = {
            {"user_id",   user_id},
            {"role",      role},
            {"jwt_valid", jwt_valid},
            {"client_ip", client_ip},
            {"path",      req.path},
            {"risk_score", risk_score}
        };

        json eval_result = call_control_plane(eval_payload);
        bool allowed = eval_result.value("allowed", false);
        std::string reason = eval_result.value("reason", "No reason");

        if (!allowed) {
            std::cout << "[proxy] DENIED: " << reason << "\n";
            json deny = {{"error", "Access Denied"}, {"reason", reason}};
            res.status = 403;
            res.set_content(deny.dump(), "application/json");
            return;
        }

        // ── 2. Sandbox scan for file uploads ─────────────────
        std::string ct = req.get_header_value("Content-Type");
        if (ct.find("multipart/form-data") != std::string::npos && req.has_file("file")) {
            auto file = req.get_file_value("file");
            std::cout << "[proxy] scanning upload: " << file.filename
                      << " (" << file.content.size() << " bytes)\n";

            json scan = call_sandbox(file.filename, file.content, file.content_type);
            bool clean = scan.value("clean", false);

            if (!clean) {
                std::string threat = scan.value("threat_found", "unknown threat");
                std::cout << "[proxy] QUARANTINED: " << threat << "\n";
                json deny = {{"error", "File Rejected"}, {"threat_found", threat}};
                res.status = 422;
                res.set_content(deny.dump(), "application/json");
                return;
            }
        }

        // ── 3. Proxy to internal target ──────────────────────
        proxy_to_target(req, res);
    };

    // Register catch-all for common methods
    svr.Get(".*",    handler);
    svr.Post(".*",   handler);
    svr.Put(".*",    handler);
    svr.Delete(".*", handler);
    svr.Patch(".*",  handler);

    std::cout << "=== Zero Trust Data Plane Proxy listening on :" << LISTEN_PORT << " ===\n";
    svr.listen("0.0.0.0", LISTEN_PORT);

    curl_global_cleanup();
    return 0;
}
