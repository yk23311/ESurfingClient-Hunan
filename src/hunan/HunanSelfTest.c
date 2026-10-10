/**
 * 湖南离线自检 —— 用官方抓包 (32 份) 做逐字节验收。
 *
 * 两项独立检查, 每个样本都跑:
 *   A. 密码层: hex → 解密 → 回加密, 必须与原始 hex 逐字节相同。
 *   B. 报文层: 从解密出的明文里取出各字段值, 按端点规定的顺序重新拼一遍,
 *      必须与官方明文逐字节相同 (验证字段顺序、换行、收尾格式)。
 *
 * 全程不联网。任何一项失败都会打印出差异位置, 便于定位。
 *
 * 用法: hunan_selftest [样本目录]
 */

#include "cipher/CipherInterface.h"
#include "cipher/CipherUtils.h"
#include "cipher/KeyData.h"

#include "hunan/HunanXml.h"

#include "utils/UrlParse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

#define MAX_SAMPLES 512
#define MAX_BYTES   65536

typedef struct
{
    int total;
    int crypto_ok;
    int xml_ok;
    int plain_len; /* 首个样本的明文长度, 用于识别补零分歧 */
} ep_stat_t;

static int read_file(const char* path, char* buf, size_t cap, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* 去掉尾部空白/换行 */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
    {
        buf[--n] = '\0';
    }
    *out_len = n;
    return 1;
}

/* 从 plain 里取出 <name>...</name> 之间的内容; 返回新分配的字符串, 找不到返回 NULL */
static char* extract_tag(const char* plain, const char* name)
{
    char open[128], close[128];
    snprintf(open, sizeof(open), "<%s>", name);
    snprintf(close, sizeof(close), "</%s>", name);
    const char* a = strstr(plain, open);
    if (!a) return NULL;
    a += strlen(open);
    const char* b = strstr(a, close);
    if (!b) return NULL;
    size_t n = (size_t)(b - a);
    char* v = (char*)malloc(n + 1);
    if (!v) return NULL;
    memcpy(v, a, n);
    v[n] = '\0';
    return v;
}

/* 文件名 req_<endpoint>.cgi_<frame>.bin → 端点枚举 */
static int endpoint_from_name(const char* name, hunan_endpoint_t* out)
{
    for (int i = 0; i < HUNAN_EP_COUNT; ++i)
    {
        const char* p = hunan_endpoint_path((hunan_endpoint_t)i);
        char pat[64];
        snprintf(pat, sizeof(pat), "req_%s_", p);
        if (strncmp(name, pat, strlen(pat)) == 0)
        {
            *out = (hunan_endpoint_t)i;
            return 1;
        }
    }
    return 0;
}

/* 检查 A: 密码层往返 */
static int check_crypto(cipher_interface_t* c, const char* hex, char** plain_out)
{
    char* plain = c->decrypt(c, hex);
    if (!plain) return 0;
    char* again = c->encrypt(c, plain);
    if (!again)
    {
        free(plain);
        return 0;
    }
    int ok = (strcmp(again, hex) == 0);
    if (!ok)
    {
        printf("      [密码层] 回加密不一致: 原始 %zu hex, 得到 %zu hex\n",
               strlen(hex), strlen(again));
        size_t m = strlen(hex) < strlen(again) ? strlen(hex) : strlen(again);
        for (size_t i = 0; i < m; ++i)
        {
            if (hex[i] != again[i])
            {
                printf("               首个差异在第 %zu 个字符 (原始 '%c' vs 得到 '%c')\n",
                       i, hex[i], again[i]);
                break;
            }
        }
    }
    free(again);
    if (!ok)
    {
        free(plain);
        return 0;
    }
    if (plain_out) *plain_out = plain;
    else free(plain);
    return 1;
}

/* 检查 B: 报文层重建 */
static int check_xml(const char* plain, hunan_endpoint_t ep)
{
    size_t count = 0;
    const char* const* names = hunan_endpoint_fields(ep, &count);
    if (!names) return 0;

    const char** values = (const char**)calloc(count, sizeof(char*));
    char** owned = (char**)calloc(count, sizeof(char*));
    if (!values || !owned)
    {
        free(values);
        free(owned);
        return 0;
    }

    int ok = 1;
    for (size_t i = 0; i < count; ++i)
    {
        owned[i] = extract_tag(plain, names[i]);
        if (!owned[i])
        {
            printf("      [报文层] 明文里找不到字段 <%s>\n", names[i]);
            ok = 0;
            break;
        }
        values[i] = owned[i];
    }

    if (ok)
    {
        char* rebuilt = hunan_build_xml_for(ep, values);
        if (!rebuilt) ok = 0;
        else
        {
            if (strcmp(rebuilt, plain) != 0)
            {
                ok = 0;
                printf("      [报文层] 重建结果与官方明文不一致 "
                       "(官方 %zu 字节, 重建 %zu 字节)\n",
                       strlen(plain), strlen(rebuilt));
                size_t m = strlen(plain) < strlen(rebuilt) ? strlen(plain) : strlen(rebuilt);
                for (size_t i = 0; i < m; ++i)
                {
                    if (plain[i] != rebuilt[i])
                    {
                        printf("               首个差异在第 %zu 字节 (官方 0x%02X '%c' vs 重建 0x%02X '%c')\n",
                               i, (unsigned char)plain[i],
                               (plain[i] >= 32 && plain[i] < 127) ? plain[i] : '.',
                               (unsigned char)rebuilt[i],
                               (rebuilt[i] >= 32 && rebuilt[i] < 127) ? rebuilt[i] : '.');
                        break;
                    }
                }
            }
            free(rebuilt);
        }
    }

    for (size_t i = 0; i < count; ++i) free(owned[i]);
    free(owned);
    free(values);
    return ok;
}

/* ------------------------------------------------------------------
 * 门户地址解析: 纯函数, 不联网。
 *
 * 样本取自真实日志。未认证时 BAS 会把明文 HTTP 劫持成 302, 那个 Location 里
 * 直接带着门户地址与 mscgip —— 门户地址因此是"接入设备送上门"的, 既不用配置
 * 也不用扫网段 (实测门户和 mscgip 都在公网段, 扫本地网段毫无意义):
 *   2026-10-09 21:50 / 22:04 / 22:14 / 22:36 / 22:45   五份日志
 *   2026-10-10 12:16                                    run.log
 *
 * 解析错了会把 ticket/auth 发到不存在的地址上, 所以这里逐条钉死。
 * ------------------------------------------------------------------ */

typedef struct
{
    const char* url;
    const char* host; /* NULL = 应当解析失败 */
    unsigned    port;
} url_case_t;

typedef struct
{
    const char* url;
    const char* name;
    const char* value; /* NULL = 应当取不到 */
} query_case_t;

static int check_portal_parse()
{
    static const url_case_t urls[] = {
        /* --- 真实样本 (同一台接入设备, 三次不同客户端 IP) --- */
        { "http://175.12.104.1:10001/index.cgi?wlanuserip=100.67.199.113"
          "&mscgip=218.75.255.245&wlanusermac=aa-bb-cc-dd-ee-ff", "175.12.104.1", 10001 },
        { "http://175.12.104.1:10001/index.cgi?wlanuserip=100.67.199.113"
          "&mscgip=218.75.255.245&wlanusermac=aa-bb-cc-dd-ee-ff", "175.12.104.1", 10001 },
        { "http://175.12.104.1:10001/index.cgi?wlanuserip=100.67.205.124"
          "&mscgip=218.75.255.245&wlanusermac=e8-b0-c5-18-31-8e", "175.12.104.1", 10001 },
        /* --- 缺省端口 / https / 主机名 --- */
        { "http://10.0.0.1/index.cgi", "10.0.0.1", 80 },
        { "https://portal.example.com/x", "portal.example.com", 443 },
        { "http://portal.example.com:8080/x", "portal.example.com", 8080 },
        /* --- userinfo 要丢掉 --- */
        { "http://user:pw@10.0.0.1:8080/x", "10.0.0.1", 8080 },
        /* --- IPv6 字面量: 方括号要保留, curl 需要它 --- */
        { "http://[2001:db8::1]:8080/x", "[2001:db8::1]", 8080 },
        /* --- 以下都应解析失败 --- */
        { "", NULL, 0 },
        { "/index.cgi?wlanuserip=1.2.3.4", NULL, 0 }, /* 相对地址: 宁可不猜 */
        { "ftp://10.0.0.1/x", NULL, 0 },
        { "http:///index.cgi", NULL, 0 }, /* 空主机 */
        { "http://:10001/x", NULL, 0 },
        { "http://10.0.0.1:/x", NULL, 0 }, /* 空端口 */
        { "http://10.0.0.1:0/x", NULL, 0 },
        { "http://10.0.0.1:65536/x", NULL, 0 },
        { "http://10.0.0.1:abc/x", NULL, 0 },
        { "http://10.0.0.1:12a/x", NULL, 0 },
        { "http://a b/x", NULL, 0 }, /* 主机名里有空白 */
    };

    static const query_case_t queries[] = {
        { "http://h/i.cgi?wlanuserip=100.67.199.113&mscgip=218.75.255.245"
          "&wlanusermac=aa-bb-cc-dd-ee-ff", "mscgip", "218.75.255.245" },
        /* 第一个参数 (紧跟 '?') 也要取得到 */
        { "http://h/i.cgi?wlanuserip=100.67.199.113&mscgip=218.75.255.245",
          "wlanuserip", "100.67.199.113" },
        /* 广东的写法 */
        { "http://h/i.cgi?wlanacip=1.2.3.4", "wlanacip", "1.2.3.4" },
        /* 不能把 xmscgip 当成 mscgip */
        { "http://h/i.cgi?xmscgip=9.9.9.9", "mscgip", NULL },
        /* 值的结束符是 '&' 或 '#' */
        { "http://h/i.cgi?mscgip=1.1.1.1#frag", "mscgip", "1.1.1.1" },
        /* 空值 = "取到了但长度为 0", 调用方据此保留配置值 */
        { "http://h/i.cgi?mscgip=&x=1", "mscgip", "" },
        /* 压根没有这个参数 */
        { "http://h/i.cgi?wlanuserip=1.2.3.4", "mscgip", NULL },
        /* 参数名只出现在路径里, 不算 */
        { "http://h/mscgip=1.1.1.1", "mscgip", NULL },
    };

    const size_t url_count = sizeof(urls) / sizeof(urls[0]);
    const size_t query_count = sizeof(queries) / sizeof(queries[0]);
    size_t url_pass = 0;
    size_t query_pass = 0;

    printf("\n门户地址解析 (BAS 注入的 302 Location)\n");
    printf("------------------------------------------------------------\n");

    for (size_t i = 0; i < url_count; ++i)
    {
        char host[64] = {0};
        uint16_t port = 0;
        const bool got = url_split_host_port(urls[i].url, host, sizeof(host), &port);

        const bool pass = (urls[i].host == NULL)
                              ? (got == false)
                              : (got && strcmp(host, urls[i].host) == 0 && port == urls[i].port);

        if (pass)
        {
            url_pass++;
            continue;
        }

        char actual[96];
        if (got) snprintf(actual, sizeof(actual), "%s:%u", host, (unsigned)port);
        else snprintf(actual, sizeof(actual), "(解析失败)");

        if (urls[i].host == NULL)
            printf("  ✗ %-58.58s 期望失败, 实际 %s\n", urls[i].url, actual);
        else
            printf("  ✗ %-58.58s 期望 %s:%u, 实际 %s\n",
                   urls[i].url, urls[i].host, urls[i].port, actual);
    }

    for (size_t i = 0; i < query_count; ++i)
    {
        const char* value = NULL;
        size_t value_len = 0;
        const bool got = url_find_query_value(queries[i].url, queries[i].name, &value, &value_len);

        const bool pass = (queries[i].value == NULL)
                              ? (got == false)
                              : (got && value_len == strlen(queries[i].value)
                                 && strncmp(value, queries[i].value, value_len) == 0);

        if (pass)
        {
            query_pass++;
            continue;
        }

        char actual[64];
        if (got)
            snprintf(actual, sizeof(actual), "\"%.*s\"", (int)(value_len > 40 ? 40 : value_len), value);
        else
            snprintf(actual, sizeof(actual), "(取不到)");

        if (queries[i].value == NULL)
            printf("  ✗ %-50.50s %-10s 期望取不到, 实际 %s\n",
                   queries[i].url, queries[i].name, actual);
        else
            printf("  ✗ %-50.50s %-10s 期望 \"%s\", 实际 %s\n",
                   queries[i].url, queries[i].name, queries[i].value, actual);
    }

    printf("主机端口 %zu/%zu, 查询参数 %zu/%zu  %s\n",
           url_pass, url_count, query_pass, query_count,
           (url_pass == url_count && query_pass == query_count) ? "✓" : "✗");

    return (url_pass == url_count && query_pass == query_count) ? 1 : 0;
}

int main(int argc, char** argv)
{
    /*
     * 样本默认取仓库内归档的那 32 份官方抓包, 相对**当前目录**解析 ——
     * 原来写死的是 C:\temp\zx\extracted, 那个临时目录已经不存在了。
     * 用 scripts\run-selftest.bat 跑最省事 (它会 cd 到仓库根再调用)。
     */
    const char* dir = (argc > 1) ? argv[1] : "re-artifacts/extracted";
    const char* algo = "FAB1DCDE-2D24-41CD-8510-2416DC7854CF";

    printf("湖南离线自检 (不联网)\n");
    printf("样本目录: %s\n", dir);
    printf("Algo-ID : %s\n", algo);
    printf("------------------------------------------------------------\n");

    /* 门户解析不依赖样本目录, 先跑 —— 样本缺失时它的结论照样有效 */
    const int portal_ok = check_portal_parse();

    printf("\n官方抓包逐字节验收\n");
    printf("------------------------------------------------------------\n");

    cipher_interface_t* c = create_aes_double_cbc_hunan_cipher(
        key_FAB1DCDE_2D24_41CD_8510_2416DC7854CF,
        iv_FAB1DCDE_2D24_41CD_8510_2416DC7854CF);
    if (!c)
    {
        printf("  ✗ 无法创建湖南密码实例\n");
        return 1;
    }

    char** files = (char**)calloc(MAX_SAMPLES, sizeof(char*));
    int nfiles = 0;

#ifdef _WIN32
    {
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s\\req_*.bin", dir);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pattern, &fd);
        if (h == INVALID_HANDLE_VALUE)
        {
            printf("  ✗ 找不到样本: %s\n", pattern);
            c->destroy(c);
            free(files);
            return portal_ok ? 0 : 1;
        }
        do
        {
            if (nfiles < MAX_SAMPLES) files[nfiles++] = _strdup(fd.cFileName);
        } while (FindNextFileA(h, &fd) && nfiles < MAX_SAMPLES);
        FindClose(h);
    }
#else
    {
        DIR* d = opendir(dir);
        if (!d)
        {
            printf("  ✗ 打不开样本目录\n");
            c->destroy(c);
            free(files);
            return 1;
        }
        struct dirent* e;
        while ((e = readdir(d)) != NULL && nfiles < MAX_SAMPLES)
        {
            if (strncmp(e->d_name, "req_", 4) == 0) files[nfiles++] = strdup(e->d_name);
        }
        closedir(d);
    }
#endif

    if (nfiles == 0)
    {
        printf("  ✗ 目录里没有 req_*.bin 样本\n");
        c->destroy(c);
        free(files);
        return portal_ok ? 0 : 1;
    }

    /* 简单插入排序, 让输出稳定 */
    for (int i = 1; i < nfiles; ++i)
    {
        char* k = files[i];
        int j = i - 1;
        while (j >= 0 && strcmp(files[j], k) > 0)
        {
            files[j + 1] = files[j];
            --j;
        }
        files[j + 1] = k;
    }

    ep_stat_t stat[HUNAN_EP_COUNT];
    memset(stat, 0, sizeof(stat));

    char* hexbuf = (char*)malloc(MAX_BYTES);
    int total = 0, crypto_ok = 0, xml_ok = 0;

    for (int i = 0; i < nfiles; ++i)
    {
        hunan_endpoint_t ep;
        if (!endpoint_from_name(files[i], &ep)) continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
        size_t hlen = 0;
        if (!read_file(path, hexbuf, MAX_BYTES, &hlen))
        {
            printf("  ✗ 读不到 %s\n", files[i]);
            continue;
        }

        stat[ep].total++;
        total++;

        char* plain = NULL;
        int a = check_crypto(c, hexbuf, &plain);
        if (a)
        {
            stat[ep].crypto_ok++;
            crypto_ok++;
        }
        if (plain)
        {
            if (stat[ep].plain_len == 0) stat[ep].plain_len = (int)strlen(plain);
            int b = check_xml(plain, ep);
            if (b)
            {
                stat[ep].xml_ok++;
                xml_ok++;
            }
            free(plain);
        }
        else
        {
            printf("  ✗ %s 解密失败\n", files[i]);
        }
    }

    printf("\n%-12s %5s %10s %10s %10s\n", "端点", "样本", "明文长度", "密码层", "报文层");
    printf("------------------------------------------------------------\n");
    for (int i = 0; i < HUNAN_EP_COUNT; ++i)
    {
        if (stat[i].total == 0) continue;
        printf("%-12s %5d %10d %6d/%-3d %6d/%-3d  %s\n",
               hunan_endpoint_path((hunan_endpoint_t)i), stat[i].total, stat[i].plain_len,
               stat[i].crypto_ok, stat[i].total,
               stat[i].xml_ok, stat[i].total,
               (stat[i].crypto_ok == stat[i].total && stat[i].xml_ok == stat[i].total)
                   ? "✓" : "✗");
    }
    printf("------------------------------------------------------------\n");
    printf("合计 %d 份样本: 密码层 %d/%d, 报文层 %d/%d\n",
           total, crypto_ok, total, xml_ok, total);
    printf("%s\n", (crypto_ok == total && xml_ok == total && portal_ok) ? "✓ 全部通过" : "✗ 存在失败项");

    for (int i = 0; i < nfiles; ++i) free(files[i]);
    free(files);
    free(hexbuf);
    c->destroy(c);
    return (crypto_ok == total && xml_ok == total && portal_ok) ? 0 : 1;
}
