#include "states/States.h"

#include "utils/PlatformUtils.h"
#include "utils/Logger.h"

#include "hunan/Hunan.h"

#include <ctype.h>

static void reset_host_name()
{
    auth_cfg_t* auth_cfg = &g_prog_status[tl_thread_idx].auth_cfg;

    if (g_prog_status[tl_thread_idx].login_cfg.chn == 4)
    {
        snprintf(auth_cfg->host_name, HOST_NAME_LEN, "iPhone 14");
        snprintf(auth_cfg->ostag, OSTAG_LEN, "iPhone iOS 17.0");
        LOG_DEBUG("iOS 主机名: %s", auth_cfg->host_name);
        LOG_DEBUG("iOS ostag: %s", auth_cfg->ostag);
        return;
    }
    if (g_prog_status[tl_thread_idx].login_cfg.chn == 5)
    {
        snprintf(auth_cfg->host_name, HOST_NAME_LEN, "MacBookPro");
        snprintf(auth_cfg->ostag, OSTAG_LEN, "macOS,14.4");
        LOG_DEBUG("macOS 主机名: %s", auth_cfg->host_name);
        LOG_DEBUG("macOS ostag: %s", auth_cfg->ostag);
        return;
    }

    char host_name[16];
    unsigned char host_bytes[10];
    get_rand_bytes(host_bytes, 10);
    host_bytes[0] = host_bytes[0] & 0xFEU;
    sprintf(host_name, "%02x%02x%02x%02x%02x",
    host_bytes[0], host_bytes[1],
    host_bytes[2], host_bytes[3],
    host_bytes[4]);
    LOG_DEBUG("新的主机名: %s", host_name);
    snprintf(auth_cfg->host_name, HOST_NAME_LEN, "%s", safe_str(host_name));
    snprintf(auth_cfg->ostag, OSTAG_LEN, "%s", safe_str(host_name));
}

static void reset_client_id()
{
    char client_id[40];
    unsigned char client_bytes[16];
    get_rand_bytes(client_bytes, 16);
    sprintf(client_id,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        client_bytes[0], client_bytes[1],
        client_bytes[2], client_bytes[3],
        client_bytes[4], client_bytes[5],
        (client_bytes[6] & 0x0F) | 0x40,
        (client_bytes[7] & 0x3F) | 0x80,
        client_bytes[8], client_bytes[9],
        client_bytes[10], client_bytes[11],
        client_bytes[12],client_bytes[13],
        client_bytes[14], client_bytes[15]);
    for (int i = 0; client_id[i]; i++) client_id[i] = (char)tolower((unsigned char)client_id[i]);
    LOG_DEBUG("新的 Client Id: %s", client_id);
    snprintf(g_prog_status[tl_thread_idx].auth_cfg.client_id, CLIENT_ID_LEN, "%s", safe_str(client_id));
}

static void reset_mac_addr()
{
    char mac_addr[20];
    unsigned char mac_bytes[6];
    get_rand_bytes(mac_bytes, 6);
    mac_bytes[0] = mac_bytes[0] & 0xFEU;
    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
    mac_bytes[0], mac_bytes[1],
    mac_bytes[2], mac_bytes[3],
    mac_bytes[4], mac_bytes[5]);
    LOG_DEBUG("新的 MAC 地址: %s", mac_addr);
    snprintf(g_prog_status[tl_thread_idx].auth_cfg.mac_addr, MAC_ADDR_LEN, "%s", safe_str(mac_addr));
}

/**
 * 湖南身份: 真实网卡 MAC / IP / 网关 + 固定的算法档与 client-id。
 *
 * 与广东的关键差别 (全部有官方抓包与实测支撑):
 *   · Algo-ID  **固定** FAB1DCDE-…, 不做算法协商 (门户不下发 ZSM)
 *   · client-id 官方是固定值, 不是随机 UUID
 *   · mac 是**真实网卡** MAC, 格式 CC-28-AA-4B-B6-D5 (广东是随机值、冒号分隔)
 *   · host-name 是真实计算机名大写 (广东随机 10 位十六进制)
 *   · ac_ip 填**真实默认网关** —— 湖南报文的 <gwip> 就是它
 */
static void reset_hunan_identity()
{
    login_cfg_t* lc = &g_prog_status[tl_thread_idx].login_cfg;
    auth_cfg_t* ac = &g_prog_status[tl_thread_idx].auth_cfg;

    snprintf(ac->algo_id, ALGO_ID_LEN, "%s", HUNAN_ALGO_ID);
    snprintf(ac->client_id, CLIENT_ID_LEN, "%s", HUNAN_CLIENT_ID);
    snprintf(ac->ostag, OSTAG_LEN, "%s", HUNAN_OSTAG);

    char host[128];
    if (get_host_name(host, sizeof(host)))
    {
        for (char* p = host; *p; ++p) *p = (char)toupper((unsigned char)*p);
        /* 显式限长: 主机名比 HOST_NAME_LEN 长时按长度截断, 不让编译器猜 */
        snprintf(ac->host_name, HOST_NAME_LEN, "%.*s", HOST_NAME_LEN - 1, host);
        LOG_DEBUG("湖南: 主机名 %s", ac->host_name);
    }
    else
    {
        snprintf(ac->host_name, HOST_NAME_LEN, "%s", "PC");
        LOG_WARN("湖南: 取不到计算机名, 用一个占位值");
    }

    char ip[IP_LEN], mac[MAC_ADDR_LEN], gw[IP_LEN];
    if (get_campus_identity(ip, sizeof(ip), mac, sizeof(mac), gw, sizeof(gw)))
    {
        snprintf(ac->mac_addr, MAC_ADDR_LEN, "%s", mac);
        snprintf(ac->client_ip, IP_LEN, "%s", ip);
        snprintf(ac->ac_ip, IP_LEN, "%s", gw);
        LOG_INFO("湖南: IP=%s MAC=%s 网关=%s algo=%s",
                 ac->client_ip, ac->mac_addr, ac->ac_ip, ac->algo_id);
    }
    else
    {
        LOG_ERROR("湖南: 拿不到真实网卡身份 (需要一块有 IPv4 且有网关的网卡)");
    }
    LOG_DEBUG("湖南: UA=%s", lc->user_agent);
}

void refresh_states()
{
    if (g_prog_status[tl_thread_idx].login_cfg.province == PROVINCE_HUNAN)
    {
        reset_hunan_identity();
        return;
    }

    snprintf(g_prog_status[tl_thread_idx].auth_cfg.algo_id, ALGO_ID_LEN, "00000000-0000-0000-0000-000000000000"); // 初始化 algo_id
    reset_host_name(); // 重置 hostname
    reset_client_id(); // 重置 client_id
    reset_mac_addr(); // 重置 mac_address
}
