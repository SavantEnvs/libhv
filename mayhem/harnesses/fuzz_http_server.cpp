// End-to-end HTTP server: raw client bytes -> hv::HttpServer (http/server/HttpHandler.cpp:
// routing, static files, WebSocket upgrade, reverse proxy; HttpService, middleware).
// HttpHandler is not an installed header, so the server is driven over loopback exactly as a
// peer would. The routes and the document root are set up once at init and are read-only to
// requests. The server itself is started fresh for every input and stopped after it, because it
// owns a FileCache (HttpServer.cpp HttpServerPrivdata::filecache) that requests fill and that
// changes later responses (cache hits skip the stat/read, prepend_header rewrites the cached
// buffer); http_server_stop deletes it. Each input is one TCP connection that writes the input,
// half-closes, and reads until the server closes.
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "HttpServer.h"
#include "WebSocketServer.h"
#include "fuzz_common.h"

static hv::HttpService g_router;
static hv::WebSocketService g_ws;

static int dead_port() {
    // a port with no listener, so proxied requests fail fast with ECONNREFUSED
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    bind(fd, (struct sockaddr*)&a, sizeof(a));
    socklen_t l = sizeof(a); getsockname(fd, (struct sockaddr*)&a, &l);
    close(fd);
    return ntohs(a.sin_port);
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    fuzz_quiet_logs();
    const char* tmp = getenv("TMPDIR");
    std::string root = std::string(tmp && *tmp ? tmp : "/tmp") + "/libhv-fuzz-www-XXXXXX";
    char* dir = mkdtemp(&root[0]);
    if (dir) {
        std::string f = std::string(dir) + "/index.html";
        FILE* fp = fopen(f.c_str(), "w");
        if (fp) { fputs("<html>fuzz</html>\n", fp); fclose(fp); }
        g_router.Static("/static", dir);
        g_router.document_root = dir;
    }
    g_router.GET("/ping", [](HttpRequest*, HttpResponse* resp) { return resp->String("pong"); });
    g_router.POST("/echo", [](const HttpContextPtr& ctx) {
        return ctx->send(ctx->body(), ctx->type());
    });
    g_router.POST("/json", [](HttpRequest* req, HttpResponse* resp) {
        resp->json = req->GetJson();
        resp->json["form"] = req->GetFormData("name");
        resp->json["kv"] = req->GetUrlEncoded("k");
        return 200;
    });
    g_router.GET("/user/{id}", [](HttpRequest* req, HttpResponse* resp) {
        return resp->String(req->GetParam("id") + req->GetParam("q"));
    });
    char upstream[64];
    snprintf(upstream, sizeof(upstream), "http://127.0.0.1:%d/", dead_port());
    g_router.Proxy("/proxy/", upstream);
    g_ws.onmessage = [](const WebSocketChannelPtr& ch, const std::string& msg) { ch->send(msg); };

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > (1 << 20)) return -1;
    hv::WebSocketServer server(&g_ws);
    server.registerHttpService(&g_router);
    server.setHost("127.0.0.1");
    server.setPort(0);
    server.setThreadNum(1);
    if (server.start() != 0) abort();
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) abort();
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(server.port);
    if (connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) abort();
    size_t off = 0;
    while (off < size) {
        ssize_t n = send(fd, data + off, size - off, MSG_NOSIGNAL);
        if (n <= 0) break;
        off += n;
    }
    shutdown(fd, SHUT_WR);
    char buf[16384];
    while (recv(fd, buf, sizeof(buf), 0) > 0) {}
    close(fd);
    server.stop();
    return 0;
}
