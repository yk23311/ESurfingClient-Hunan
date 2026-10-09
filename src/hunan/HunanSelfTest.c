/**
 * 湖南离线自检 —— 用 C:\temp\zx\extracted 里的官方抓包做逐字节验收。
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

int main(int argc, char** argv)
{
    const char* dir = (argc > 1) ? argv[1] : "C:\\temp\\zx\\extracted";
    const char* algo = "FAB1DCDE-2D24-41CD-8510-2416DC7854CF";

    printf("湖南离线自检 (不联网)\n");
    printf("样本目录: %s\n", dir);
    printf("Algo-ID : %s\n", algo);
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
            return 1;
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
        return 1;
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
    printf("%s\n", (crypto_ok == total && xml_ok == total) ? "✓ 全部通过" : "✗ 存在失败项");

    for (int i = 0; i < nfiles; ++i) free(files[i]);
    free(files);
    free(hexbuf);
    c->destroy(c);
    return (crypto_ok == total && xml_ok == total) ? 0 : 1;
}
