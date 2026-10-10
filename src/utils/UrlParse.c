/**
 * URL 解析实现。见 UrlParse.h 里"为什么单独一个文件"的说明。
 *
 * 本文件是纯函数: 不包含任何项目头, 不调用日志, 不使用全局状态, 不分配内存。
 * 因此它可以被离线自检单独编译, 真实的 302 Location 样本可以直接进单元测试。
 */

#include "utils/UrlParse.h"

#include <string.h>

#define HTTP_SCHEME "http://"
#define HTTP_SCHEME_LEN 7
#define HTTPS_SCHEME "https://"
#define HTTPS_SCHEME_LEN 8

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443

bool url_split_host_port(const char* url, char* host, const size_t host_len, uint16_t* port)
{
    if (host == NULL || host_len == 0) return false;

    host[0] = '\0';
    if (port != NULL) *port = 0;
    if (url == NULL) return false;

    bool https = false;
    const char* p = NULL;

    if (strncmp(url, HTTP_SCHEME, HTTP_SCHEME_LEN) == 0)
    {
        p = url + HTTP_SCHEME_LEN;
    }
    else if (strncmp(url, HTTPS_SCHEME, HTTPS_SCHEME_LEN) == 0)
    {
        https = true;
        p = url + HTTPS_SCHEME_LEN;
    }
    else
    {
        /* 相对地址或其它 scheme: 不复原, 交给调用方回退 */
        return false;
    }

    /* authority 段到 '/', '?' 或 '#' 为止 */
    const char* authority_end = p + strcspn(p, "/?#");

    /* 门户 URL 不带 userinfo; 真带了也按 RFC 3986 丢掉, 免得把 '@' 前面当成主机名 */
    for (const char* q = p; q < authority_end; ++q)
    {
        if (*q == '@') p = q + 1;
    }
    if (p >= authority_end) return false; /* 空主机 */

    const char* host_end = NULL;

    if (*p == '[')
    {
        /* IPv6 字面量: 方括号一起保留, curl 需要它才能把 [::1]:80 解析对 */
        const char* close = memchr(p, ']', (size_t)(authority_end - p));
        if (close == NULL) return false;
        host_end = close + 1;
    }
    else
    {
        host_end = p;
        while (host_end < authority_end && *host_end != ':') ++host_end;
    }

    const size_t host_size = (size_t)(host_end - p);
    if (host_size == 0 || host_size >= host_len) return false;

    /* 主机名里出现空白或控制字符, 一定是解析错了 —— 宁可回退也不要拿它去发请求 */
    for (size_t i = 0; i < host_size; ++i)
    {
        const unsigned char ch = (unsigned char)p[i];
        if (ch <= ' ' || ch == 0x7f) return false;
    }

    memcpy(host, p, host_size);
    host[host_size] = '\0';

    uint16_t parsed_port = (uint16_t)(https ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT);

    if (host_end < authority_end)
    {
        if (*host_end != ':') return false;

        const char* digits = host_end + 1;
        const size_t digit_count = (size_t)(authority_end - digits);

        /* 端口最多 5 位; 空端口 ("host:") 视为非法而不是按缺省处理 */
        if (digit_count == 0 || digit_count > 5) return false;

        uint32_t value = 0;
        for (size_t i = 0; i < digit_count; ++i)
        {
            if (digits[i] < '0' || digits[i] > '9') return false;
            value = value * 10 + (uint32_t)(digits[i] - '0');
        }

        if (value == 0 || value > 65535) return false;
        parsed_port = (uint16_t)value;
    }

    if (port != NULL) *port = parsed_port;
    return true;
}

bool url_find_query_value(const char* url, const char* name, const char** value, size_t* value_len)
{
    if (value != NULL) *value = NULL;
    if (value_len != NULL) *value_len = 0;
    if (url == NULL || name == NULL || name[0] == '\0') return false;

    const size_t name_len = strlen(name);

    for (const char* p = url; *p != '\0'; ++p)
    {
        /* 参数名只能出现在 '?' 之后或紧跟在 '&' 之后 */
        if (*p != '?' && *p != '&') continue;

        const char* candidate = p + 1;
        if (strncmp(candidate, name, name_len) != 0) continue;
        if (candidate[name_len] != '=') continue;

        const char* v = candidate + name_len + 1;
        const size_t len = strcspn(v, "&#");

        if (value != NULL) *value = v;
        if (value_len != NULL) *value_len = len;
        return true;
    }

    return false;
}
