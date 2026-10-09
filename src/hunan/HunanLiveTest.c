/**
 * 湖南联网实测工具 (自带密码层 + 报文层, 不依赖主程序的会话流程)。
 *
 * 模式:
 *   read  (默认) 只打只读端点: ticket.cgi → state.cgi → keep.cgi
 *                **不会注销, 不会断网**
 *   term         取新票 → term.cgi 注销 → 再用 state.cgi 复核会话是否真的没了
 *                ⚠️ 会断网
 *   auth         ticket.cgi → auth.cgi → state.cgi → keep.cgi
 *                用于把网重新认证上来
 *
 * 配置从 --config 指定的 config.json 读 (默认当前目录), 所以和 Python 版共用一份配置。
 *
 * 用法:
 *   hunan_live [read|term|auth] [config.json 路径]
 *
 * 退出码: 0 = 成功, 1 = 失败, 2 = 配置/参数错误
 */

#include "cipher/CipherInterface.h"
#include "cipher/CipherUtils.h"
#include "cipher/KeyData.h"

#include "hunan/HunanXml.h"

#include "utils/sim/SimEvp.h"

#include <curl/curl.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON/cJSON.h"

#define UA           "CCTP/WinSVR3/1052"
#define ALGO_ID      "FAB1DCDE-2D24-41CD-8510-2416DC7854CF"
#define CLIENT_ID    "c167f455-7b9f-4c0f-a401-df583ab269e2"
#define OSTAG        "Windows 11(26300),64 bit "
#define LOCAL_TIME   "00000000k"
#define EXCHECK_ARGS "<hello>1</hello><conn>1</conn>"

#define BODY_CAP (1 << 16)

typedef struct
{
    char   portal[64];
    int    port;
    char   user_ip[64];
    char   user_mac[64];   /* 查询串用: 12 位小写 hex */
    char   mac_dashed[32]; /* 报文里用: CC-28-AA-4B-B6-D5 */
    char   mscgip[64];
    char   gateway[64];
    char   hostname[128];
    char   username[64];
    char   password[128];
} cfg_t;

typedef struct
{
    char   body[BODY_CAP];
    size_t body_len;
    char   error_code[32];
    long   http_code;
    char   curl_error[CURL_ERROR_SIZE];
} resp_t;

static cipher_interface_t* g_cipher;

/* ------------------------------------------------------------------ 配置 */

static void json_str(const cJSON* o, const char* key, char* out, size_t cap, const char* dflt)
{
    const cJSON* v = cJSON_GetObjectItemCaseSensitive(o, key);
    const char* s = (v && cJSON_IsString(v) && v->valuestring && v->valuestring[0])
                        ? v->valuestring : dflt;
    snprintf(out, cap, "%s", s ? s : "");
}

static int load_cfg(const char* path, cfg_t* c)
{
    memset(c, 0, sizeof(*c));
    FILE* f = fopen(path, "rb");
    if (!f) { printf("✗ 打不开配置文件: %s\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0 || n > 65536) { fclose(f); printf("✗ 配置文件大小异常\n"); return 0; }
    char* buf = (char*)malloc((size_t)n + 1);
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';

    cJSON* root = cJSON_Parse(buf);
    free(buf);
    if (!root) { printf("✗ config.json 不是合法 JSON\n"); return 0; }

    json_str(root, "portal", c->portal, sizeof(c->portal), "175.12.104.1");
    const cJSON* p = cJSON_GetObjectItemCaseSensitive(root, "port");
    c->port = (p && cJSON_IsNumber(p)) ? p->valueint : 10001;
    json_str(root, "wlanuserip", c->user_ip, sizeof(c->user_ip), "");
    json_str(root, "wlanusermac", c->user_mac, sizeof(c->user_mac), "");
    json_str(root, "mscgip", c->mscgip, sizeof(c->mscgip), "");
    json_str(root, "gateway", c->gateway, sizeof(c->gateway), "");
    json_str(root, "username", c->username, sizeof(c->username), "");
    json_str(root, "password", c->password, sizeof(c->password), "");
    cJSON_Delete(root);

    /* MAC: 统一成 12 位小写 hex, 再派生出带横线的大写形式 */
    char hex[32] = "";
    size_t j = 0;
    for (size_t i = 0; c->user_mac[i] && j < 12; ++i)
    {
        if (isxdigit((unsigned char)c->user_mac[i]))
            hex[j++] = (char)tolower((unsigned char)c->user_mac[i]);
    }
    hex[j] = '\0';
    snprintf(c->user_mac, sizeof(c->user_mac), "%s", hex);

    j = 0;
    for (size_t i = 0; hex[i] && j + 2 < sizeof(c->mac_dashed); ++i)
    {
        if (i && i % 2 == 0) c->mac_dashed[j++] = '-';
        c->mac_dashed[j++] = (char)toupper((unsigned char)hex[i]);
    }
    c->mac_dashed[j] = '\0';

    if (gethostname(c->hostname, sizeof(c->hostname) - 1) != 0)
        snprintf(c->hostname, sizeof(c->hostname), "PC");
    for (char* q = c->hostname; *q; ++q) *q = (char)toupper((unsigned char)*q);

    if (!c->user_ip[0]) { printf("✗ config.json 里没有 wlanuserip\n"); return 0; }
    return 1;
}

/* ------------------------------------------------------------------ HTTP */

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* ud)
{
    resp_t* r = (resp_t*)ud;
    size_t n = size * nmemb;
    if (r->body_len + n >= BODY_CAP) n = BODY_CAP - 1 - r->body_len;
    memcpy(r->body + r->body_len, ptr, n);
    r->body_len += n;
    r->body[r->body_len] = '\0';
    return size * nmemb;
}

static size_t header_cb(char* buffer, size_t size, size_t nitems, void* ud)
{
    resp_t* r = (resp_t*)ud;
    const size_t n = size * nitems;
    if (n > 11 && strncasecmp(buffer, "error-code:", 11) == 0)
    {
        size_t i = 11, j = 0;
        while (i < n && (buffer[i] == ' ' || buffer[i] == '\t')) i++;
        while (i < n && buffer[i] != '\r' && buffer[i] != '\n' && j < sizeof(r->error_code) - 1)
            r->error_code[j++] = buffer[i++];
        r->error_code[j] = '\0';
    }
    return n;
}

static int post(const char* url, const char* wire, const char* src_ip, resp_t* r)
{
    memset(r, 0, sizeof(*r));
    CURL* c = curl_easy_init();
    if (!c) return 0;

    unsigned char md5[16];
    char checksum[33];
    simssl_md5((const unsigned char*)wire, strlen(wire), md5);
    for (int i = 0; i < 16; ++i) sprintf(checksum + i * 2, "%02x", md5[i]);

    struct curl_slist* h = NULL;
    char line[256];
    snprintf(line, sizeof(line), "User-Agent: %s", UA);         h = curl_slist_append(h, line);
    snprintf(line, sizeof(line), "Algo-ID: %s", ALGO_ID);       h = curl_slist_append(h, line);
    snprintf(line, sizeof(line), "Client-ID: %s", CLIENT_ID);   h = curl_slist_append(h, line);
    snprintf(line, sizeof(line), "CDC-Checksum: %s", checksum); h = curl_slist_append(h, line);
    h = curl_slist_append(h, "Content-Type: application/octet-stream");

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, wire);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, r);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, r);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_ERRORBUFFER, r->curl_error);
    curl_easy_setopt(c, CURLOPT_INTERFACE, src_ip);

    const CURLcode rc = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r->http_code);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);
    return rc == CURLE_OK;
}

static int xml_text(const char* xml, const char* name, char* out, size_t cap)
{
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", name);
    snprintf(close, sizeof(close), "</%s>", name);
    const char* a = strstr(xml, open);
    if (!a) return 0;
    a += strlen(open);
    const char* b = strstr(a, close);
    if (!b) return 0;
    size_t n = (size_t)(b - a);
    if (n >= cap) n = cap - 1;
    memcpy(out, a, n);
    out[n] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ 端点 */

/* 公共字段取值 */
static const hunan_field_t* common_fields(const cfg_t* c, size_t* n)
{
    static hunan_field_t f[11];
    f[0].name = "ostag";        f[0].value = OSTAG;
    f[1].name = "local-time";   f[1].value = LOCAL_TIME;
    f[2].name = "gwip";         f[2].value = c->gateway;
    f[3].name = "mac";          f[3].value = c->mac_dashed;
    f[4].name = "ipv6";         f[4].value = "";
    f[5].name = "ipv4";         f[5].value = c->user_ip;
    f[6].name = "client-id";    f[6].value = CLIENT_ID;
    f[7].name = "user-agent";   f[7].value = UA;
    f[8].name = "host-name";    f[8].value = c->hostname;
    f[9].name = "excheck-args"; f[9].value = EXCHECK_ARGS;
    f[10].name = "reason";      f[10].value = "1";
    *n = 11;
    return f;
}

/**
 * 打一个端点。extra 用于补充/覆盖字段 (如 ticket / userid / passwd)。
 * 成功 (HTTP 通) 返回解密后的响应, 调用方 free; 传输失败返回 NULL。
 * ep_code 写入 Error-Code 字符串。
 */
static char* call_ep(const cfg_t* c, hunan_endpoint_t ep,
                     const hunan_field_t* extra, size_t extra_n,
                     char* ep_code, size_t code_cap)
{
    size_t n_common = 0;
    const hunan_field_t* common = common_fields(c, &n_common);

    size_t count = 0;
    const char* const* names = hunan_endpoint_fields(ep, &count);
    const char** values = (const char**)calloc(count, sizeof(char*));
    if (!values) return NULL;

    for (size_t i = 0; i < count; ++i)
    {
        values[i] = "";
        for (size_t k = 0; k < extra_n; ++k)
            if (strcmp(names[i], extra[k].name) == 0) { values[i] = extra[k].value; break; }
        if (!values[i][0])
            for (size_t k = 0; k < n_common; ++k)
                if (strcmp(names[i], common[k].name) == 0) { values[i] = common[k].value; break; }
    }

    char* xml = hunan_build_xml_for(ep, values);
    free(values);
    if (!xml) { printf("  ✗ 拼报文失败\n"); return NULL; }

    char* wire = g_cipher->encrypt(g_cipher, xml);
    if (!wire) { printf("  ✗ 加密失败\n"); free(xml); return NULL; }

    char url[512];
    snprintf(url, sizeof(url), "http://%s:%d/%s?wlanuserip=%s&mscgip=%s&wlanusermac=%s",
             c->portal, c->port, hunan_endpoint_path(ep),
             c->user_ip, c->mscgip, c->user_mac);

    resp_t r;
    const int ok = post(url, wire, c->user_ip, &r);

    char* plain = NULL;
    if (!ok)
    {
        printf("  ✗ %-11s 传输失败: %s\n", hunan_endpoint_path(ep),
               r.curl_error[0] ? r.curl_error : "(无错误信息)");
    }
    else
    {
        if (ep_code && code_cap) snprintf(ep_code, code_cap, "%s", r.error_code);
        printf("  %-11s 明文 %3zu → 线上 %4zu hex   HTTP %ld  Error-Code=%s  响应 %zu 字节\n",
               hunan_endpoint_path(ep), strlen(xml), strlen(wire),
               r.http_code, r.error_code[0] ? r.error_code : "(无)", r.body_len);
        if (r.body_len) plain = g_cipher->decrypt(g_cipher, r.body);
    }

    free(xml);
    free(wire);
    return plain;
}

/* 取一张新票 (只读) */
static int get_ticket(const cfg_t* c, char* ticket, size_t cap)
{
    ticket[0] = '\0';
    char code[32] = "";
    char* xml = call_ep(c, HUNAN_EP_TICKET, NULL, 0, code, sizeof(code));
    if (!xml) return 0;
    const int ok = (strcmp(code, "0") == 0) && xml_text(xml, "ticket", ticket, cap);
    if (ok) printf("  → 票据 %s\n", ticket);
    else    printf("  → ✗ 取票失败 (Error-Code=%s)\n", code);
    free(xml);
    return ok;
}

/* ------------------------------------------------------------------ 模式 */

static int mode_read(const cfg_t* c)
{
    char ticket[64] = "";
    printf("① ticket.cgi  (只读)\n");
    const int got = get_ticket(c, ticket, sizeof(ticket));
    printf("\n");

    if (!got)
    {
        printf("没取到票, 跳过 state/keep。\n");
        return 1;
    }

    const hunan_field_t fx[1] = {{"ticket", ticket}};

    printf("② state.cgi   (只读)\n");
    char code[32] = "";
    char* s = call_ep(c, HUNAN_EP_STATE, fx, 1, code, sizeof(code));
    if (s) { printf("              %s\n", s); free(s); }
    printf("\n");

    printf("③ keep.cgi    (心跳, 不断开)\n");
    char* k = call_ep(c, HUNAN_EP_KEEP, fx, 1, code, sizeof(code));
    if (k) { printf("              %s\n", k); free(k); }
    printf("\n");

    printf("完成。未调用 auth.cgi / term.cgi, 连接未被改动。\n");
    return 0;
}

static int mode_term(const cfg_t* c)
{
    printf("⚠ 即将注销 (term.cgi), 本机将断网。\n\n");
    char ticket[64] = "";
    printf("① ticket.cgi  (先取一张有效票)\n");
    if (!get_ticket(c, ticket, sizeof(ticket)))
    {
        printf("\n取不到票, 放弃注销 (连接未改动)。\n");
        return 1;
    }
    printf("\n");

    const hunan_field_t fx[1] = {{"ticket", ticket}};
    char code[32] = "";
    printf("② term.cgi    (注销)\n");
    char* t = call_ep(c, HUNAN_EP_TERM, fx, 1, code, sizeof(code));
    if (t) { printf("              %s\n", t); free(t); }
    const int term_ok = (strcmp(code, "0") == 0);
    printf("\n");

    /* 用 state.cgi 复核: 会话真的没了吗 (Error-Code=0 不代表一定成功) */
    printf("③ state.cgi   (复核会话是否已消失)\n");
    char code2[32] = "";
    char* s = call_ep(c, HUNAN_EP_STATE, fx, 1, code2, sizeof(code2));
    if (s) free(s);
    const int gone = (strcmp(code2, "0") != 0);
    printf("\n");

    if (!term_ok)
    {
        printf("✗ 注销失败: term.cgi 返回 Error-Code=%s\n", code);
        return 1;
    }
    if (!gone)
    {
        printf("✗ term.cgi 返回 0, 但 state.cgi 仍能看到会话 (Error-Code=%s) —— 可能没真注销。\n", code2);
        return 1;
    }
    printf("✓ 注销成功: term.cgi=0, state.cgi=%s (会话已消失)\n", code2);
    return 0;
}

static int mode_auth(const cfg_t* c)
{
    if (!c->username[0] || !c->password[0])
    {
        printf("✗ config.json 里没有账号或密码, 无法认证\n");
        return 2;
    }

    char ticket[64] = "";
    printf("① ticket.cgi  (取票)\n");
    if (!get_ticket(c, ticket, sizeof(ticket)))
    {
        printf("\n✗ 取不到票, 无法认证\n");
        return 1;
    }
    printf("\n");

    const hunan_field_t fx[3] = {
        {"ticket", ticket}, {"userid", c->username}, {"passwd", c->password},
    };
    char code[32] = "";
    printf("② auth.cgi    (认证)\n");
    char* a = call_ep(c, HUNAN_EP_AUTH, fx, 3, code, sizeof(code));
    if (a) { printf("              %s\n", a); free(a); }
    printf("\n");
    if (strcmp(code, "0") != 0)
    {
        printf("✗ 认证被拒: Error-Code=%s\n", code);
        return 1;
    }

    printf("③ state.cgi   (验证会话)\n");
    char code2[32] = "";
    char* s = call_ep(c, HUNAN_EP_STATE, fx, 1, code2, sizeof(code2));
    const int state_ok = (s != NULL) && (strcmp(code2, "0") == 0);
    if (s) { printf("              %s\n", s); free(s); }
    printf("\n");

    printf("④ keep.cgi    (心跳)\n");
    char code3[32] = "";
    char* k = call_ep(c, HUNAN_EP_KEEP, fx, 1, code3, sizeof(code3));
    const int keep_ok = (k != NULL) && (strcmp(code3, "0") == 0);
    if (k) { printf("              %s\n", k); free(k); }
    printf("\n");

    if (!state_ok || !keep_ok)
    {
        printf("✗ auth 返回 0, 但未能证明会话建立 (state=%s keep=%s)\n", code2, code3);
        return 1;
    }
    printf("✓ 认证成功并已验证: auth=0 state=0 keep=0\n");
    return 0;
}

/* ------------------------------------------------------------------ main */

int main(int argc, char** argv)
{
    const char* mode = (argc > 1) ? argv[1] : "read";
    const char* cfg_path = (argc > 2) ? argv[2] : "config.json";

    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0)
    {
        printf("用法: hunan_live [read|term|auth] [config.json 路径]\n"
               "  read  只读端点 (默认, 不断网)\n"
               "  term  注销 (会断网)\n"
               "  auth  认证\n");
        return 0;
    }

    cfg_t cfg;
    /* curl_global_init 会做 WSAStartup; gethostname 依赖它, 所以必须先初始化 */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if (!load_cfg(cfg_path, &cfg))
    {
        curl_global_cleanup();
        return 2;
    }

    printf("湖南联网实测  模式=%s\n", mode);
    printf("------------------------------------------------------------\n");
    printf("门户   http://%s:%d\n", cfg.portal, cfg.port);
    printf("本机   %s   MAC %s\n", cfg.user_ip, cfg.mac_dashed);
    printf("mscgip %s   网关 %s   主机名 %s\n", cfg.mscgip, cfg.gateway, cfg.hostname);
    printf("账号   %s\n", cfg.username[0] ? cfg.username : "(未配置)");
    printf("------------------------------------------------------------\n");

    g_cipher = create_aes_double_cbc_hunan_cipher(
        key_FAB1DCDE_2D24_41CD_8510_2416DC7854CF,
        iv_FAB1DCDE_2D24_41CD_8510_2416DC7854CF);
    if (!g_cipher) { printf("✗ 无法创建湖南密码实例\n"); return 2; }

    int rc;
    if (strcmp(mode, "read") == 0)      rc = mode_read(&cfg);
    else if (strcmp(mode, "term") == 0) rc = mode_term(&cfg);
    else if (strcmp(mode, "auth") == 0) rc = mode_auth(&cfg);
    else { printf("✗ 未知模式: %s\n", mode); rc = 2; }

    g_cipher->destroy(g_cipher);
    curl_global_cleanup();
    printf("------------------------------------------------------------\n");
    printf("退出码 %d (%s)\n", rc, rc == 0 ? "成功" : "失败");
    return rc;
}
