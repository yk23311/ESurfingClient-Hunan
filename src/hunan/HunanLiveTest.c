/**
 * 湖南联网实测 —— **只读端点, 不会注销、不会断网**。
 *
 * 依次打三个不改变连接状态的端点:
 *   1. ticket.cgi —— 取一张新票 (不下发会话变更)
 *   2. state.cgi  —— 查会话是否存在
 *   3. keep.cgi   —— 心跳 (刷新会话, 不会断开)
 *
 * **故意不调用 auth.cgi / term.cgi** —— 那两个会真正建立或拆除会话,
 * 在远程会话里跑会把操作者的网络打断。
 *
 * 用法:
 *   hunan_live [portal_ip] [port] [wlanuserip] [wlanusermac_hex]
 *              [mscgip] [gateway] [hostname]
 * 省略则用 config.json 时实测的值。
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

#define UA           "CCTP/WinSVR3/1052"
#define ALGO_ID      "FAB1DCDE-2D24-41CD-8510-2416DC7854CF"
#define CLIENT_ID    "c167f455-7b9f-4c0f-a401-df583ab269e2"
#define OSTAG        "Windows 11(26300),64 bit "
#define LOCAL_TIME   "00000000k"
#define EXCHECK_ARGS "<hello>1</hello><conn>1</conn>"

#define BODY_CAP (1 << 16)

typedef struct
{
    char   body[BODY_CAP];
    size_t body_len;
    char   error_code[32];
    long   http_code;
    char   curl_error[CURL_ERROR_SIZE];
} resp_t;

static cipher_interface_t* g_cipher;

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    resp_t* r = (resp_t*)userdata;
    size_t n = size * nmemb;
    if (r->body_len + n >= BODY_CAP) n = BODY_CAP - 1 - r->body_len;
    memcpy(r->body + r->body_len, ptr, n);
    r->body_len += n;
    r->body[r->body_len] = '\0';
    return size * nmemb;
}

static size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata)
{
    resp_t* r = (resp_t*)userdata;
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
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_ERRORBUFFER, r->curl_error);
    curl_easy_setopt(c, CURLOPT_INTERFACE, src_ip); /* 与 run.py 一致: 显式绑定源地址 */

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

/**
 * 打一个端点。fields 按名字提供取值 (未提供的字段填空串)。
 * mscgip_hex / mac_hex 用于拼查询串 (查询串里 MAC 是不带横线的 12 位小写)。
 * 返回解密后的响应 (调用方 free), 失败返回 NULL。
 */
static char* run_endpoint(const char* base, const char* src_ip,
                          const char* mscgip_hex, const char* mac_hex,
                          hunan_endpoint_t ep,
                          const hunan_field_t* fields, const size_t field_n)
{
    size_t count = 0;
    const char* const* names = hunan_endpoint_fields(ep, &count);
    const char** values = (const char**)calloc(count, sizeof(char*));
    if (!values) return NULL;
    for (size_t i = 0; i < count; ++i)
    {
        values[i] = "";
        for (size_t k = 0; k < field_n; ++k)
        {
            if (strcmp(names[i], fields[k].name) == 0)
            {
                values[i] = fields[k].value ? fields[k].value : "";
                break;
            }
        }
    }

    char* xml = hunan_build_xml_for(ep, values);
    free(values);
    if (!xml) { printf("  ✗ 拼报文失败\n"); return NULL; }

    char* wire = g_cipher->encrypt(g_cipher, xml);
    if (!wire) { printf("  ✗ 加密失败\n"); free(xml); return NULL; }

    char url[512];
    snprintf(url, sizeof(url), "%s/%s?wlanuserip=%s&mscgip=%s&wlanusermac=%s",
             base, hunan_endpoint_path(ep), src_ip, mscgip_hex, mac_hex);

    resp_t r;
    const int ok = post(url, wire, src_ip, &r);

    printf("  %-11s 明文 %3zu 字节 → 线上 %4zu hex", hunan_endpoint_path(ep),
           strlen(xml), strlen(wire));

    char* plain = NULL;
    if (!ok)
    {
        printf("   ✗ 传输失败: %s\n", r.curl_error[0] ? r.curl_error : "(无错误信息)");
    }
    else
    {
        printf("   HTTP %ld  Error-Code=%s  响应 %zu 字节\n",
               r.http_code, r.error_code[0] ? r.error_code : "(无)", r.body_len);
        if (r.body_len)
        {
            plain = g_cipher->decrypt(g_cipher, r.body);
            if (plain) printf("             解密后: %s\n", plain);
            else       printf("             ✗ 响应解密失败\n");
        }
    }

    free(xml);
    free(wire);
    return plain;
}

int main(int argc, char** argv)
{
    const char* portal   = (argc > 1) ? argv[1] : "175.12.104.1";
    const int   port     = (argc > 2) ? atoi(argv[2]) : 10001;
    const char* user_ip  = (argc > 3) ? argv[3] : "100.67.223.57";
    const char* user_mac = (argc > 4) ? argv[4] : "cc28aa4bb6d5";
    const char* mscgip   = (argc > 5) ? argv[5] : "218.75.255.245";
    const char* gateway  = (argc > 6) ? argv[6] : "100.67.192.1";
    char        hostname[128] = "TX5P";
    if (argc > 7) snprintf(hostname, sizeof(hostname), "%s", argv[7]);

    char mac_dashed[32] = "";
    {
        size_t j = 0;
        for (size_t i = 0; user_mac[i] && j + 2 < sizeof(mac_dashed); ++i)
        {
            if (i && i % 2 == 0) mac_dashed[j++] = '-';
            mac_dashed[j++] = (char)toupper((unsigned char)user_mac[i]);
        }
        mac_dashed[j] = '\0';
    }
    for (char* p = hostname; *p; ++p) *p = (char)toupper((unsigned char)*p);

    char base[128];
    snprintf(base, sizeof(base), "http://%s:%d", portal, port);

    printf("湖南联网实测 (只读端点, 不会断开当前连接)\n");
    printf("------------------------------------------------------------\n");
    printf("门户      %s\n", base);
    printf("本机 IP   %s\n", user_ip);
    printf("MAC       %s  (查询串里用 %s)\n", mac_dashed, user_mac);
    printf("mscgip    %s\n", mscgip);
    printf("网关      %s\n", gateway);
    printf("主机名    %s\n", hostname);
    printf("------------------------------------------------------------\n");

    curl_global_init(CURL_GLOBAL_DEFAULT);
    g_cipher = create_aes_double_cbc_hunan_cipher(
        key_FAB1DCDE_2D24_41CD_8510_2416DC7854CF,
        iv_FAB1DCDE_2D24_41CD_8510_2416DC7854CF);
    if (!g_cipher) { printf("✗ 无法创建湖南密码实例\n"); return 1; }

    const hunan_field_t f_common[] = {
        {"ostag", OSTAG}, {"local-time", LOCAL_TIME}, {"gwip", gateway},
        {"mac", mac_dashed}, {"ipv6", ""}, {"ipv4", user_ip},
        {"client-id", CLIENT_ID}, {"user-agent", UA}, {"host-name", hostname},
        {"excheck-args", EXCHECK_ARGS}, {"reason", "1"},
    };
    const size_t n_common = sizeof(f_common) / sizeof(f_common[0]);

    printf("① ticket.cgi  (取新票, 只读)\n");
    char* tk = run_endpoint(base, user_ip, mscgip, user_mac,
                            HUNAN_EP_TICKET, f_common, n_common);

    char ticket[64] = "";
    if (tk) xml_text(tk, "ticket", ticket, sizeof(ticket));
    printf("   → 票据: %s\n\n", ticket[0] ? ticket : "(未取到)");

    if (ticket[0])
    {
        hunan_field_t* fx = (hunan_field_t*)calloc(n_common + 1, sizeof(hunan_field_t));
        memcpy(fx, f_common, sizeof(f_common));
        fx[n_common].name = "ticket";
        fx[n_common].value = ticket;

        printf("② state.cgi   (查会话, 只读)\n");
        char* s = run_endpoint(base, user_ip, mscgip, user_mac,
                               HUNAN_EP_STATE, fx, n_common + 1);
        free(s);
        printf("\n");

        printf("③ keep.cgi    (心跳, 不断开)\n");
        char* k = run_endpoint(base, user_ip, mscgip, user_mac,
                               HUNAN_EP_KEEP, fx, n_common + 1);
        free(k);
        printf("\n");
        free(fx);
    }
    else
    {
        printf("②③ 跳过: 没取到票 (ticket.cgi 的响应已在上方, 那本身就说明了协议是否通)\n\n");
    }

    free(tk);
    g_cipher->destroy(g_cipher);
    curl_global_cleanup();
    printf("------------------------------------------------------------\n");
    printf("完成。**未调用 auth.cgi / term.cgi, 当前连接未被改动。**\n");
    return 0;
}
