#ifndef ESURFINGCLIENT_MINIHTTP_H
#define ESURFINGCLIENT_MINIHTTP_H

/**
 * minihttp —— 一个刚好够用的阻塞式 HTTP/1.1 服务器。
 *
 * 为什么自己写而不是继续用 mongoose:
 *   mongoose 是 `GPL-2.0-only or commercial` 双许可。桌面版构建会**静态链接**它,
 *   于是发行二进制时触发 GPL-2.0 的传染性 —— 而主项目是 Apache-2.0,
 *   两者本身还不兼容 (Apache-2.0 兼容 GPL-3.0, 不兼容 GPL-2.0)。
 *   本程序只需要「托管几个静态文件 + 收发 JSON」, 用不着 1.2 MB 的完整网络库。
 *
 * 接口刻意与 mongoose 的那一小部分**同名同形**, 这样四个 webserver 源文件
 * 一行都不用改 (只换 include)。用到的是:
 *   mg_str / mg_strcmp / mg_match / mg_http_get_var
 *   mg_mgr_init / mg_mgr_free / mg_http_listen / mg_mgr_poll
 *   mg_http_reply / mg_http_serve_dir
 *   mg_log_set_fn / mg_log_level
 *
 * 有意**不支持**的东西 (本程序用不到): TLS、WebSocket、HTTP/2、
 * 反向代理、分块传输、multipart。
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------- 字符串 ------------------------------- */

struct mg_str
{
    const char* buf;
    size_t len;
};

/** 由 C 字符串构造 mg_str。struct 标签与函数名分属不同命名空间, 可以同名。 */
static inline struct mg_str mg_str(const char* s)
{
    struct mg_str r;
    r.buf = s;
    r.len = s ? strlen(s) : 0;
    return r;
}

/** 与 strcmp 同语义 (返回 <0 / 0 / >0) */
int mg_strcmp(struct mg_str a, struct mg_str b);

/**
 * 通配匹配: 模式里 `*` 匹配任意串, `?` 匹配单字符。
 * 本项目的调用点全部传字面量 (如 "/api/logs"), 所以绝大多数情况下就是全等比较。
 */
bool mg_match(struct mg_str str, struct mg_str pattern, void* unused);

/* ------------------------------- 请求/响应 ---------------------------- */

struct mg_connection;

struct mg_http_message
{
    struct mg_str method; /* "GET" / "POST", 指向请求缓冲区 */
    struct mg_str uri;    /* 路径, **不含**查询串 */
    struct mg_str query;  /* '?' 之后的部分, 不含 '?' */
    struct mg_str body;   /* 请求体 */
};

struct mg_http_serve_opts
{
    const char* root_dir;
    /* 其余 mongoose 字段本项目未使用 */
};

#define MG_EV_HTTP_MSG 1

/* 日志级别: 数值越大越啰嗦, 与 mongoose 的取值保持一致 */
enum
{
    MG_LL_NONE = 0,
    MG_LL_ERROR = 1,
    MG_LL_INFO = 2,
    MG_LL_DEBUG = 3,
    MG_LL_VERBOSE = 4
};

extern int mg_log_level;

/** 日志回调: 逐个字符送出 (与 mongoose 的 mg_log_set_fn 同形) */
void mg_log_set_fn(void (*fn)(char ch, void* param), void* param);

/* ------------------------------- 事件循环 ----------------------------- */

struct mg_mgr
{
    intptr_t listen_fd; /* 存 sock_t; 用 intptr_t 是因为 Windows 的 SOCKET 不是 int */
    void (*handler)(struct mg_connection* c, int ev, void* ev_data);
    void* userdata;

    struct mg_connection* conns;
    int nconn;
    int max_conn;
};

void mg_mgr_init(struct mg_mgr* mgr);

void mg_mgr_free(struct mg_mgr* mgr);

/**
 * 在 mgr 上监听 `http://host:port`。
 * @return 失败返回 NULL (端口占用 / 地址非法)
 */
struct mg_connection* mg_http_listen(struct mg_mgr* mgr, const char* url,
                                     void (*fn)(struct mg_connection*, int, void*),
                                     void* userdata);

/** 跑一轮事件循环, 最多阻塞 ms 毫秒 */
void mg_mgr_poll(struct mg_mgr* mgr, int ms);

/* ------------------------------- 应答 --------------------------------- */

/**
 * 发一个响应。headers 是原样附加的响应头字符串 (可为 "")。
 * body 由 fmt 格式化 (可为 ""), 会自动补 Content-Length。
 */
void mg_http_reply(struct mg_connection* c, int code, const char* headers,
                   const char* fmt, ...);

/** 从 root_dir 提供静态文件; 路径 "/" 映射到 index.html */
void mg_http_serve_dir(struct mg_connection* c, struct mg_http_message* hm,
                       const struct mg_http_serve_opts* opts);

/**
 * 取查询串里某个参数的值 (会做百分号解码)。
 * @return 值的长度; 未找到返回负数
 */
int mg_http_get_var(const struct mg_str* query, const char* name, char* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
