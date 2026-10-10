#include "utils/PlatformUtils.h"

#include "states/States.h"

#include "utils/PlatformInternal.h"
#include "utils/Logger.h"

#include "cJSON/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    char ip[IP_LEN];
    char name[NAME_LENGTH];
    char mac[MAC_ADDR_LEN];   /* 大写、横线分隔: AA-BB-CC-DD-EE-FF */
    char gateway[IP_LEN];
} adapter_t;

static adapter_t* s_adaptor = NULL;
static uint8_t s_adaptor_count = 0;

/* 把 6 字节 MAC 写成 AA-BB-CC-DD-EE-FF (湖南报文要的形式) */
static void mac_to_dashed(const unsigned char* raw, const unsigned raw_len, char* out, const size_t cap)
{
    out[0] = '\0';
    if (raw == NULL || raw_len < 6 || cap < 18) return;
    snprintf(out, cap, "%02X-%02X-%02X-%02X-%02X-%02X",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
}

static int ip_usable(const char* ip)
{
    if (ip == NULL || ip[0] == '\0') return 0;
    if (strcmp(ip, "0.0.0.0") == 0) return 0;
    if (strncmp(ip, "127.", 4) == 0) return 0;
    if (strncmp(ip, "169.254.", 8) == 0) return 0;
    return 1;
}

static void get_adapters()
{
#ifdef _WIN32
    PIP_ADAPTER_INFO p_adapter_info = NULL;
    ULONG ul_out_buf_len = 0;
    if (GetAdaptersInfo(p_adapter_info, &ul_out_buf_len) == ERROR_BUFFER_OVERFLOW)
    {
        p_adapter_info = (PIP_ADAPTER_INFO)malloc(ul_out_buf_len);
        if (p_adapter_info && GetAdaptersInfo(p_adapter_info, &ul_out_buf_len) == NO_ERROR)
        {
            PIP_ADAPTER_INFO p_adapter = p_adapter_info;
            uint8_t cnt = 0;
            while (p_adapter)
            {
                adapter_t* new_adaptor = realloc(s_adaptor, sizeof(adapter_t) * (cnt + 1));
                if (!new_adaptor)
                {
                    LOG_ERROR("分配内存失败");
                    break;
                }
                s_adaptor = new_adaptor;
                memset(&s_adaptor[cnt], 0, sizeof(adapter_t));
                snprintf(s_adaptor[cnt].name, NAME_LENGTH, "%s", p_adapter->Description);
                snprintf(s_adaptor[cnt].ip, IP_LEN, "%s", p_adapter->IpAddressList.IpAddress.String);
                mac_to_dashed(p_adapter->Address, p_adapter->AddressLength,
                              s_adaptor[cnt].mac, MAC_ADDR_LEN);
                if (p_adapter->GatewayList.IpAddress.String[0])
                {
                    snprintf(s_adaptor[cnt].gateway, IP_LEN, "%s",
                             p_adapter->GatewayList.IpAddress.String);
                }
                LOG_VERBOSE("IP: %s  MAC: %s  GW: %s",
                            p_adapter->IpAddressList.IpAddress.String,
                            s_adaptor[cnt].mac, s_adaptor[cnt].gateway);
                p_adapter = p_adapter->Next;
                cnt++;
            }
            s_adaptor_count = cnt;
        }
    }
    if (p_adapter_info) free(p_adapter_info);
#else
    struct ifaddrs* ifaddrs_ptr, *ifa;
    if (getifaddrs(&ifaddrs_ptr) == 0)
    {
        uint8_t cnt = 0;
        for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next)
        {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            char ip[INET_ADDRSTRLEN];
            struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)))
            {
                adapter_t* new_adaptor = realloc(s_adaptor, sizeof(adapter_t) * (cnt + 1));
                if (!new_adaptor)
                {
                    LOG_ERROR("分配内存失败");
                    break;
                }
                s_adaptor = new_adaptor;
                memset(&s_adaptor[cnt], 0, sizeof(adapter_t));
                snprintf(s_adaptor[cnt].name, NAME_LENGTH, "%s", ifa->ifa_name);
                snprintf(s_adaptor[cnt].ip, IP_LEN, "%s", ip);
                cnt++;
            }
        }
        s_adaptor_count = cnt;
        freeifaddrs(ifaddrs_ptr);
    }
#endif
}

/**
 * 挑一块「像校园网出口」的网卡: 有可用 IPv4、且**有网关**。
 *
 * 为什么要有网关: 湖南报文里的 <gwip> 用的就是默认网关, 而虚拟网卡
 * (Hyper-V / WSL / VMware) 通常没有网关 —— 用这个条件就能把它们排除掉,
 * 不需要按名字硬编码「以太网」。
 *
 * 广东版是随机生成 MAC、也没有网关查询; 湖南官方客户端发的是真实值,
 * 所以这里必须给真值。
 */
/** 取真实计算机名 (湖南的 <host-name> 用它; 广东是随机生成的假名) */
bool get_host_name(char* out, size_t cap)
{
    if (!out || cap == 0) return false;
    out[0] = '\0';
#ifdef _WIN32
    DWORD len = (DWORD)cap;
    if (!GetComputerNameA(out, &len)) return false;
#else
    if (gethostname(out, cap) != 0) return false;
#endif
    out[cap - 1] = '\0';
    return out[0] != '\0';
}

bool get_campus_identity(char* ip, size_t ip_cap, char* mac, size_t mac_cap,
                         char* gateway, size_t gw_cap)
{
    get_adapters();
    for (uint8_t i = 0; i < s_adaptor_count; i++)
    {
        if (!ip_usable(s_adaptor[i].ip)) continue;
        if (s_adaptor[i].gateway[0] == '\0') continue;
        if (s_adaptor[i].mac[0] == '\0') continue;
        snprintf(ip, ip_cap, "%s", s_adaptor[i].ip);
        snprintf(mac, mac_cap, "%s", s_adaptor[i].mac);
        snprintf(gateway, gw_cap, "%s", s_adaptor[i].gateway);
        LOG_INFO("校园网出口: %s  IP=%s  MAC=%s  网关=%s",
                 s_adaptor[i].name, ip, mac, gateway);
        return true;
    }
    LOG_ERROR("找不到像校园网出口的网卡 (需要: 有 IPv4 且有网关)");
    return false;
}

char* get_adapters_json()
{
    get_adapters();
    cJSON* root = cJSON_CreateObject();
    cJSON* adapters = cJSON_CreateArray();
    for (uint8_t i = 0; i < s_adaptor_count; i++)
    {
        if (strlen(s_adaptor[i].name) == 0) break;
        cJSON* adapter = cJSON_CreateObject();
        cJSON_AddStringToObject(adapter, "name", s_adaptor[i].name);
        cJSON_AddStringToObject(adapter, "ip", s_adaptor[i].ip);
        cJSON_AddItemToArray(adapters, adapter);
    }
    cJSON_AddItemToObject(root, "adapters", adapters);
    cJSON_AddStringToObject(root, "school_network_symbol", g_school_network_symbol);
    char* json = cJSON_Print(root);
    cJSON_Delete(root);
    return json;
}
