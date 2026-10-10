#include "minihttp/minihttp.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------ 平台适配 ------------------------------- */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h> /* GetTickCount64 */
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define sock_close   closesocket
#define sock_errno   WSAGetLastError()
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <strings.h> /* strcasecmp */
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#define sock_close   close
#define sock_errno   errno
#endif

#define MAX_CONNS        32
#define RX_CAP           (16 * 1024)     /* 单个请求的最大字节数 */
#define IDLE_TIMEOUT_MS  10000           /* keep-alive 空闲多久断开 */
#define SEND_CHUNK       65536

/* -------------------------------- 日志 --------------------------------- */

int mg_log_level = MG_LL_INFO;

static void (*s_log_fn)(char ch, void* param) = NULL;
static void* s_log_param = NULL;

void mg_log_set_fn(void (*fn)(char ch, void* param), void* param)
{
    s_log_fn = fn;
    s_log_param = param;
}

static void mini_log_at(const int level, const char* file, const int line, const char* fmt, ...);

/**
 * 日志格式必须与项目的 logFn 解析器对齐 (见 WebLogFiles.c 的 logFn):
 *
 *     <无空格的时间戳> <2 位级别> <纯文件名>:<行号>: <消息>
 *
 * 两个坑:
 *   1. 解析器用 strchr(buf,' ') 找**第一个**空格来定位级别, 所以时间戳里不能有空格;
 *   2. 级别必须**正好占 1 个字符**, 因为解析器按固定偏移取它 ——
 *      格式串里不能写成 %2d (空格会补到左边把偏移挤歪);
 *   3. 文件名里不能出现 ':' —— 否则会把 Windows 路径的 "C:" 当成行号分隔符。
 *      所以这里只取 basename。
 */
#define mini_log(level, ...) mini_log_at((level), __FILE__, __LINE__, __VA_ARGS__)

static void mini_log_at(const int level, const char* file, const int line, const char* fmt, ...)
{
    if (s_log_fn == NULL || level > mg_log_level) return;

    const char* base = file;
    for (const char* p = file; *p; ++p)
    {
        if (*p == '/' || *p == '\\') base = p + 1;
    }

    char stamp[16];
    const time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    strftime(stamp, sizeof(stamp), "%H:%M:%S", &tmv);

    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    char buf[640];
    /* 格式必须与项目 logFn 的解析器**逐字符对齐** (见 WebLogFiles.c):
     *     <无空格的时间戳> <级别 1 字符> <纯文件名>:<行号>: <消息>
     *
     * 解析器取 "第一个空格之后的第 1 个字符" 当级别、第 3 个字符当文件名起点,
     * 所以级别**必须正好占 1 个字符**。写成 %2d 会让空格补在左边, 级别落到
     * 第 2 个位置, 于是被判成 VERBOSE 并被日志级别过滤掉 ——
     * 表现是 Web 服务端日志全部静默消失。 */
    snprintf(buf, sizeof(buf), "%s %d %s:%d:%s", stamp, level, base, line, msg);

    for (const char* p = buf; *p; ++p) s_log_fn(*p, s_log_param);
    s_log_fn('\n', s_log_param);
}

/* ------------------------------ 字符串工具 ----------------------------- */

int mg_strcmp(const struct mg_str a, const struct mg_str b)
{
    const size_t n = a.len < b.len ? a.len : b.len;
    const int r = n ? memcmp(a.buf, b.buf, n) : 0;
    if (r != 0) return r;
    if (a.len == b.len) return 0;
    return a.len < b.len ? -1 : 1;
}

/** 单段通配匹配 (支持 * 与 ?), 递归实现, 模式串很短所以无所谓性能 */
static bool glob_match(const char* s, const size_t slen, const char* p, const size_t plen)
{
    size_t si = 0, pi = 0;

    while (pi < plen)
    {
        if (p[pi] == '*')
        {
            /* 连续的 * 等价于一个 */
            while (pi < plen && p[pi] == '*') pi++;
            if (pi == plen) return true;
            for (size_t k = si; k <= slen; ++k)
            {
                if (glob_match(s + k, slen - k, p + pi, plen - pi)) return true;
            }
            return false;
        }
        if (si >= slen) return false;
        if (p[pi] != '?' && p[pi] != s[si]) return false;
        si++;
        pi++;
    }
    return si == slen;
}

bool mg_match(const struct mg_str str, const struct mg_str pattern, void* unused)
{
    (void)unused;
    if (pattern.buf == NULL) return false;
    return glob_match(str.buf, str.len, pattern.buf, pattern.len);
}

/* -------------------------------- 时间 --------------------------------- */

static uint64_t now_ms(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/* ------------------------------ 连接与事件 ----------------------------- */

struct mg_connection
{
    sock_t fd;
    char   rx[RX_CAP];
    size_t rx_len;
    uint64_t last_active;

    /* 一次请求内的状态 */
    bool responded;
    bool close_after;
    char peer[46];
};

static bool send_all(sock_t fd, const char* buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        const int n = (int)send(fd, buf + sent, (int)(len - sent > SEND_CHUNK ? SEND_CHUNK : len - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static void conn_close(struct mg_mgr* mgr, const int idx)
{
    if (idx < 0 || idx >= mgr->nconn) return;
    if (mgr->conns[idx].fd != SOCK_INVALID) sock_close(mgr->conns[idx].fd);
    /* 用最后一个补位, 顺序不重要 */
    mgr->conns[idx] = mgr->conns[mgr->nconn - 1];
    mgr->nconn--;
}

/* ------------------------------ 构造与销毁 ----------------------------- */

void mg_mgr_init(struct mg_mgr* mgr)
{
    if (mgr == NULL) return;
    memset(mgr, 0, sizeof(*mgr));
    mgr->listen_fd = (int)SOCK_INVALID;
    mgr->max_conn = MAX_CONNS;
    mgr->conns = (struct mg_connection*)calloc((size_t)MAX_CONNS, sizeof(struct mg_connection));

#ifdef _WIN32
    /* 只初始化一次; 不做 WSACleanup —— 进程退出时由系统回收 */
    static bool wsa_done = false;
    if (wsa_done == false)
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) wsa_done = true;
    }
#endif
}

void mg_mgr_free(struct mg_mgr* mgr)
{
    if (mgr == NULL) return;
    for (int i = mgr->nconn - 1; i >= 0; --i) conn_close(mgr, i);
    if ((sock_t)mgr->listen_fd != SOCK_INVALID)
    {
        sock_close((sock_t)mgr->listen_fd);
        mgr->listen_fd = (int)SOCK_INVALID;
    }
    free(mgr->conns);
    mgr->conns = NULL;
    mgr->nconn = 0;
}

struct mg_connection* mg_http_listen(struct mg_mgr* mgr, const char* url,
                                     void (*fn)(struct mg_connection*, int, void*),
                                     void* userdata)
{
    if (mgr == NULL || url == NULL || fn == NULL) return NULL;

    /* url 形如 "http://127.0.0.1:8888" */
    const char* host = url;
    if (strncmp(host, "http://", 7) == 0) host += 7;

    char hostbuf[128] = "127.0.0.1";
    int port = 80;
    const char* colon = strrchr(host, ':');
    if (colon != NULL)
    {
        const size_t hlen = (size_t)(colon - host);
        if (hlen > 0 && hlen < sizeof(hostbuf))
        {
            memcpy(hostbuf, host, hlen);
            hostbuf[hlen] = '\0';
        }
        port = atoi(colon + 1);
    }
    else
    {
        snprintf(hostbuf, sizeof(hostbuf), "%s", host);
    }

    const sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == SOCK_INVALID)
    {
        mini_log(MG_LL_ERROR, "[minihttp] socket() 失败: %d", sock_errno);
        return NULL;
    }

    /**
     * 端口复用选项在两个平台上的**语义是相反的**, 不能都写 SO_REUSEADDR:
     *
     *   · Linux: SO_REUSEADDR 只是让 bind 不被 TIME_WAIT 的残留连接挡住, 是服务端
     *     该有的行为 —— 所以用它。
     *   · Windows: SO_REUSEADDR 的意思是"允许别的进程再 bind 同一个端口", 而且
     *     后绑的那个会把新连接抢走。也就是说本机任意一个进程都能顶着 8888 起一个
     *     冒牌网页界面, 用户完全看不出来。Windows 上该用的是 SO_EXCLUSIVEADDRUSE:
     *     独占端口, 第二个实例老实报"端口被占用"。
     *
     * (这个坑是实测踩出来的: 隔离目录里的第二个实例明明该绑不上 8888, 却绑上了。)
     */
#ifdef _WIN32
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&one, sizeof(one)) != 0)
    {
        /* 极少数旧系统不认识这个选项; 失败也不能因此起不来, 只是少了那层保护 */
        mini_log(MG_LL_DEBUG, "[minihttp] SO_EXCLUSIVEADDRUSE 设置失败: %d", sock_errno);
    }
#else
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (strcmp(hostbuf, "0.0.0.0") == 0)
    {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else if (inet_pton(AF_INET, hostbuf, &addr.sin_addr) != 1)
    {
        mini_log(MG_LL_ERROR, "[minihttp] 无法解析监听地址: %s", hostbuf);
        sock_close(fd);
        return NULL;
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        mini_log(MG_LL_ERROR, "[minihttp] bind %s:%d 失败: %d", hostbuf, port, sock_errno);
        sock_close(fd);
        return NULL;
    }
    if (listen(fd, 16) != 0)
    {
        mini_log(MG_LL_ERROR, "[minihttp] listen 失败: %d", sock_errno);
        sock_close(fd);
        return NULL;
    }

    mgr->listen_fd = (int)fd;
    mgr->handler = fn;
    mgr->userdata = userdata;
    mini_log(MG_LL_INFO, "[minihttp] 监听 %s:%d", hostbuf, port);
    return (struct mg_connection*)mgr; /* 非 NULL 即成功 */
}

/* ------------------------------ 请求解析 ------------------------------- */

/** 在 [buf, buf+len) 里找 "\r\n\r\n"; 返回正文起始下标, 未找到返回 0 */
static size_t find_header_end(const char* buf, const size_t len)
{
    for (size_t i = 0; i + 3 < len; ++i)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    }
    return 0;
}

static bool header_contains(const char* hdrs, const size_t n, const char* name, const char* needle)
{
    const size_t nlen = strlen(name);
    for (size_t i = 0; i + nlen < n; ++i)
    {
        if (i > 0 && hdrs[i - 1] != '\n') continue;
        if (strncasecmp(hdrs + i, name, nlen) != 0) continue;
        const char* p = hdrs + i + nlen;
        const char* end = hdrs + n;
        while (p < end && *p != '\n')
        {
            if (strncasecmp(p, needle, strlen(needle)) == 0) return true;
            p++;
        }
    }
    return false;
}

static long header_content_length(const char* hdrs, const size_t n)
{
    const char name[] = "Content-Length:";
    for (size_t i = 0; i + sizeof(name) < n; ++i)
    {
        if (i > 0 && hdrs[i - 1] != '\n') continue;
        if (strncasecmp(hdrs + i, name, sizeof(name) - 1) != 0) continue;
        return strtol(hdrs + i + sizeof(name) - 1, NULL, 10);
    }
    return -1;
}

/* -------------------------------- 应答 --------------------------------- */

static const char* status_text(const int code)
{
    switch (code)
    {
    case 200: return "OK";
    case 204: return "No Content";
    case 302: return "Found";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default:  return "OK";
    }
}

static void reply_raw(struct mg_connection* c, const int code, const char* headers,
                      const char* body, const size_t body_len)
{
    if (c == NULL || c->responded) return;

    char head[1024];
    const int n = snprintf(head, sizeof(head),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Length: %zu\r\n"
                           "%s"
                           "%s"
                           "\r\n",
                           code, status_text(code), body_len,
                           c->close_after ? "Connection: close\r\n" : "",
                           headers ? headers : "");

    if (n <= 0) { c->responded = true; return; }
    const size_t head_len = (size_t)n;

    /**
     * 头与正文**合成一次 send** 发出去。
     *
     * 分成两次 send 会被 Nagle 算法与对端延迟 ACK 夹住: 第一段小包发出去以后,
     * 第二段要等对端 ACK 才发, 而延迟 ACK 的定时器是 ~40 ms —— 表现就是
     * 每个请求凭空多 40 ms。实测并发 12 个请求从 13 ms 掉到 1918 ms,
     * 单请求平均 37.8 ms, 正好是这个数字。
     */
    if (body_len > 0 && body != NULL)
    {
        char* buf = (char*)malloc(head_len + body_len);
        if (buf != NULL)
        {
            memcpy(buf, head, head_len);
            memcpy(buf + head_len, body, body_len);
            send_all(c->fd, buf, head_len + body_len);
            free(buf);
            c->responded = true;
            return;
        }
        /* 内存不够就退回两次写 —— 慢一点, 但至少能发出去 */
    }

    send_all(c->fd, head, head_len);
    if (body_len > 0 && body != NULL) send_all(c->fd, body, body_len);
    c->responded = true;
}

void mg_http_reply(struct mg_connection* c, const int code, const char* headers,
                   const char* fmt, ...)
{
    if (c == NULL || c->responded) return;

    char stackbuf[2048];
    stackbuf[0] = '\0';

    if (fmt != NULL && fmt[0] != '\0')
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
        va_end(ap);
    }

    /* 204 / 302 这类不需要正文; 但 Content-Length 仍要如实给出 */
    reply_raw(c, code, headers, stackbuf, strlen(stackbuf));
}

/* ---------------------------- 静态文件服务 ----------------------------- */

static const char* content_type_for(const char* path)
{
    const char* dot = strrchr(path, '.');
    if (dot == NULL) return "application/octet-stream";
    if (strcasecmp(dot, ".html") == 0) return "text/html; charset=utf-8";
    if (strcasecmp(dot, ".css") == 0)  return "text/css; charset=utf-8";
    if (strcasecmp(dot, ".js") == 0)   return "text/javascript; charset=utf-8";
    if (strcasecmp(dot, ".json") == 0) return "application/json; charset=utf-8";
    if (strcasecmp(dot, ".svg") == 0)  return "image/svg+xml";
    if (strcasecmp(dot, ".png") == 0)  return "image/png";
    if (strcasecmp(dot, ".jpg") == 0)  return "image/jpeg";
    if (strcasecmp(dot, ".ico") == 0)  return "image/x-icon";
    if (strcasecmp(dot, ".txt") == 0)  return "text/plain; charset=utf-8";
    if (strcasecmp(dot, ".woff2") == 0) return "font/woff2";
    return "application/octet-stream";
}

/* 路径里不允许出现 ".." —— 否则 root_dir 可以被穿越出去 */
static bool path_is_safe(const char* uri, const size_t len)
{
    for (size_t i = 0; i + 1 < len; ++i)
    {
        if (uri[i] == '.' && uri[i + 1] == '.') return false;
    }
    return true;
}

void mg_http_serve_dir(struct mg_connection* c, struct mg_http_message* hm,
                       const struct mg_http_serve_opts* opts)
{
    if (c == NULL || hm == NULL || opts == NULL || opts->root_dir == NULL) return;
    if (c->responded) return;

    const char* uri = hm->uri.buf;
    size_t uri_len = hm->uri.len;

    if (path_is_safe(uri, uri_len) == false)
    {
        mini_log(MG_LL_ERROR, "[minihttp] 拒绝可疑路径: %.*s", (int)uri_len, uri);
        mg_http_reply(c, 400, "Content-Type: text/plain; charset=utf-8\r\n", "Bad path\n");
        return;
    }

    /* 去掉前导 '/'; 空路径映射到 index.html */
    while (uri_len > 0 && *uri == '/') { uri++; uri_len--; }

    char rel[512];
    if (uri_len == 0)
    {
        snprintf(rel, sizeof(rel), "index.html");
    }
    else
    {
        size_t n = uri_len < sizeof(rel) - 6 ? uri_len : sizeof(rel) - 6;
        memcpy(rel, uri, n);
        rel[n] = '\0';
        /* 目录形式也当 index.html 处理 */
        if (rel[n - 1] == '/') snprintf(rel + n, sizeof(rel) - n, "index.html");
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s%c%s", opts->root_dir, '/', rel);

    FILE* f = fopen(path, "rb");
    if (f == NULL)
    {
        mini_log(MG_LL_DEBUG, "[minihttp] 404: %s", path);
        mg_http_reply(c, 404, "Content-Type: text/plain; charset=utf-8\r\n", "Not found\n");
        return;
    }

    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0)
    {
        fclose(f);
        mg_http_reply(c, 500, "", "");
        return;
    }

    char* body = (char*)malloc((size_t)size);
    if (body == NULL && size > 0)
    {
        fclose(f);
        mg_http_reply(c, 500, "", "");
        return;
    }
    const size_t got = fread(body, 1, (size_t)size, f);
    fclose(f);

    char headers[256];
    snprintf(headers, sizeof(headers),
             "Content-Type: %s\r\nCache-Control: no-cache\r\n", content_type_for(rel));

    reply_raw(c, 200, headers, body, got);
    free(body);
}

/* ------------------------------ 查询串解析 ----------------------------- */

static int hex_val(const char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int mg_http_get_var(const struct mg_str* query, const char* name, char* buf, const size_t len)
{
    if (query == NULL || name == NULL || buf == NULL || len == 0) return -1;

    const size_t nlen = strlen(name);
    const char* p = query->buf;
    const char* end = query->buf + query->len;

    while (p < end)
    {
        const char* amp = memchr(p, '&', (size_t)(end - p));
        const char* seg_end = amp ? amp : end;

        if ((size_t)(seg_end - p) > nlen && strncmp(p, name, nlen) == 0 && p[nlen] == '=')
        {
            const char* v = p + nlen + 1;
            size_t out = 0;
            while (v < seg_end && out + 1 < len)
            {
                if (*v == '%' && v + 2 < seg_end)
                {
                    const int hi = hex_val(v[1]);
                    const int lo = hex_val(v[2]);
                    if (hi >= 0 && lo >= 0)
                    {
                        buf[out++] = (char)((hi << 4) | lo);
                        v += 3;
                        continue;
                    }
                }
                buf[out++] = (*v == '+') ? ' ' : *v;
                v++;
            }
            buf[out] = '\0';
            return (int)out;
        }
        p = amp ? amp + 1 : end;
    }
    return -1;
}

/* ------------------------------ 单个连接处理 --------------------------- */

/* 返回: 1 = 已处理完一次请求, 0 = 数据还不够, -1 = 连接该关掉 */
static int conn_handle(struct mg_mgr* mgr, const int idx)
{
    struct mg_connection* c = &mgr->conns[idx];

    char tmp[4096];
    const int n = recv(c->fd, tmp, (int)sizeof(tmp), 0);
    if (n <= 0) return -1;

    if (c->rx_len + (size_t)n > RX_CAP)
    {
        c->close_after = true;
        mg_http_reply(c, 413, "Content-Type: text/plain; charset=utf-8\r\n", "Request too large\n");
        return 1;
    }
    memcpy(c->rx + c->rx_len, tmp, (size_t)n);
    c->rx_len += (size_t)n;
    c->last_active = now_ms();

    const size_t hdr_end = find_header_end(c->rx, c->rx_len);
    if (hdr_end == 0) return 0; /* 头还没收全 */

    /* --- 请求行 --- */
    const char* line_end = strstr(c->rx, "\r\n");
    if (line_end == NULL) return -1;

    const char* sp1 = memchr(c->rx, ' ', (size_t)(line_end - c->rx));
    if (sp1 == NULL) return -1;
    const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - sp1 - 1));
    if (sp2 == NULL) return -1;

    struct mg_http_message hm;
    memset(&hm, 0, sizeof(hm));
    hm.method.buf = c->rx;
    hm.method.len = (size_t)(sp1 - c->rx);

    const char* target = sp1 + 1;
    const size_t target_len = (size_t)(sp2 - target);
    const char* q = memchr(target, '?', target_len);
    if (q != NULL)
    {
        hm.uri.buf = target;
        hm.uri.len = (size_t)(q - target);
        hm.query.buf = q + 1;
        hm.query.len = target_len - hm.uri.len - 1;
    }
    else
    {
        hm.uri.buf = target;
        hm.uri.len = target_len;
        hm.query.buf = "";
        hm.query.len = 0;
    }

    /* --- 请求体 --- */
    const long clen = header_content_length(c->rx, hdr_end);
    if (clen > 0)
    {
        const size_t need = hdr_end + (size_t)clen;
        if (c->rx_len < need) return 0; /* 正文还没收全 */
        hm.body.buf = c->rx + hdr_end;
        hm.body.len = (size_t)clen;
    }

    /* --- keep-alive 判定 --- */
    const bool is_11 = (strncmp(c->rx, "HTTP/1.1", 8) == 0) ||
                       (line_end - c->rx > 8 && memcmp(line_end - 8, "HTTP/1.1", 8) == 0);
    const bool want_close = header_contains(c->rx, hdr_end, "Connection:", "close");
    c->close_after = want_close || (is_11 == false);
    c->responded = false;

    /* --- 交给上层 --- */
    mgr->handler(c, MG_EV_HTTP_MSG, &hm);

    /* 上层没应答 (例如方法不是 GET/POST) 就补一个 405, 免得浏览器干等 */
    if (c->responded == false)
    {
        c->close_after = true;
        mg_http_reply(c, 405, "Content-Type: text/plain; charset=utf-8\r\n",
                      "Method not allowed\n");
    }

    /* 下一次请求: 把粘包里的剩余字节挪到前面 (支持流水线) */
    const size_t consumed = hdr_end + (clen > 0 ? (size_t)clen : 0);
    if (consumed < c->rx_len)
    {
        memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
        c->rx_len -= consumed;
    }
    else
    {
        c->rx_len = 0;
    }
    c->last_active = now_ms();

    return c->close_after ? -1 : 1;
}

/* ------------------------------- 主循环 -------------------------------- */

void mg_mgr_poll(struct mg_mgr* mgr, const int ms)
{
    if (mgr == NULL || (sock_t)mgr->listen_fd == SOCK_INVALID) return;

    fd_set rfds;
    FD_ZERO(&rfds);
    sock_t maxfd = (sock_t)mgr->listen_fd;
    FD_SET((sock_t)mgr->listen_fd, &rfds);

    for (int i = 0; i < mgr->nconn; ++i)
    {
        FD_SET(mgr->conns[i].fd, &rfds);
        if (mgr->conns[i].fd > maxfd) maxfd = mgr->conns[i].fd;
    }

    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    const int ready = select((int)maxfd + 1, &rfds, NULL, NULL, &tv);

    /* 无论有没有事件, 都清一遍空闲连接 */
    const uint64_t now = now_ms();
    for (int i = mgr->nconn - 1; i >= 0; --i)
    {
        if (now - mgr->conns[i].last_active > IDLE_TIMEOUT_MS) conn_close(mgr, i);
    }

    if (ready <= 0) return;

    /* 新连接 */
    if (FD_ISSET((sock_t)mgr->listen_fd, &rfds))
    {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        const sock_t fd = accept((sock_t)mgr->listen_fd, (struct sockaddr*)&peer, &plen);
        if (fd != SOCK_INVALID)
        {
            if (mgr->nconn >= mgr->max_conn)
            {
                mini_log(MG_LL_ERROR, "[minihttp] 连接数已满, 拒绝新连接");
                sock_close(fd);
            }
            else
            {
                struct mg_connection* c = &mgr->conns[mgr->nconn++];
                memset(c, 0, sizeof(*c));
                c->fd = fd;
                c->last_active = now;
                c->peer[0] = '\0';
                inet_ntop(AF_INET, &peer.sin_addr, c->peer, sizeof(c->peer));

                /* 关掉 Nagle: 小响应立刻发, 不等对端 ACK。
                 * 不关的话每个请求会被延迟 ACK 的 40 ms 定时器拖住 (见 reply_raw)。 */
                int nodelay = 1;
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
            }
        }
    }

    /* 已有连接 */
    for (int i = mgr->nconn - 1; i >= 0; --i)
    {
        if (FD_ISSET(mgr->conns[i].fd, &rfds) == 0) continue;
        const int r = conn_handle(mgr, i);
        if (r < 0) conn_close(mgr, i);
    }
}
