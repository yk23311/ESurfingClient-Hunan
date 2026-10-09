#include "clients/net/NetClient.h"

#include "states/States.h"

#include "utils/Logger.h"

#include <stdio.h>

#define GENERATE_URL "http://connect.rom.miui.com/generate_204"
#define GENERATE_BAK_URL "http://1.1.1.1"
/* 广东的认证服务器。仅在"连 HTTP 响应都拿不到"时用来探活, 湖南用配置里的门户替换 */
#define AUTH_URL "http://14.146.227.141:7001"
#define AUTH_BAK_URL "http://121.8.177.212:7001"

/**
 * 探活用的认证服务器地址。
 *
 * 正常情况下用不到它 —— 未认证时门户会劫持 generate_204 并回 302,
 * 直接就能判定 STATUS_NEED_AUTH。只有连 HTTP 响应都收不到时才会走到这里。
 * 但那时若仍去探广东的 IP, 湖南这边必然全失败 → 被误判成 CONNECT_ERROR,
 * 于是程序认定"网络有问题", 根本不会去认证。
 */
static const char* auth_probe_url(char* buf, const size_t cap)
{
    const login_cfg_t* lc = &g_prog_status[tl_thread_idx].login_cfg;
    if (lc->province == PROVINCE_HUNAN && lc->portal[0])
    {
        snprintf(buf, cap, "http://%s:%" PRIu16, lc->portal, lc->portal_port);
        return buf;
    }
    return AUTH_URL;
}

network_status_t check_network_status(const bool connect_only)
{
    curl_resp_t resp = {0};
    connection_status_t conn_status = 0;

    /*
     * MIUI IP generate_204 URL
     * 204 正常联网
     * 302 需要认证
     * 其他则是非正常状态
     */

    resp = get(GENERATE_URL, connect_only);

    conn_status = CONNECT_INTERNET;

    if (resp.curl_code != CURLE_OK) // 主检测 URL 无法连通
    {
        /*
         * generate 服务器错误时备用方案
         * http://1.1.1.1
         * 301 正常联网
         * 302 需要认证
         * 其他则是非正常状态
         */

        LOG_WARN("主检测 URL 无法连通, 使用备用 IP URL");
        resp = get(GENERATE_BAK_URL, connect_only);

        conn_status = CONNECT_INTERNET;

        if (resp.curl_code != CURLE_OK) // 备用 IP URL 无法连通
        {
            /*
             * 外部网络无法连通, 进一步检查能否连通认证服务器
             * 200 正常连通
             * 302 可能是需要认证
             * 其他则是非正常状态
             */

            LOG_ERROR("备用 IP 地址 URL 无法连通, 初步判定为无法连通外部互联网");
            LOG_INFO("正在检测认证服务器连通性");

            conn_status = CONNECT_AUTH_SERVER;

            char probe[128];
            resp = get(auth_probe_url(probe, sizeof(probe)), connect_only);

            if (resp.curl_code != CURLE_OK) // 认证服务器 1 无法连通
            {
                /*
                 * 认证服务器 1 无法连通, 检测认证服务器 2
                 * 200 正常连通
                 * 302 可能是需要认证
                 * 其他则是非正常状态
                 */

                LOG_WARN("认证服务器 1 无法连通, 正在检测认证服务器 2 连通性");

                const login_cfg_t* lc = &g_prog_status[tl_thread_idx].login_cfg;
                resp = get((lc->province == PROVINCE_HUNAN) ? auth_probe_url(probe, sizeof(probe))
                                                            : AUTH_BAK_URL, connect_only);

                conn_status = CONNECT_AUTH_SERVER;

                if (resp.curl_code != CURLE_OK) // 认证服务器 2 无法连通
                {
                    /*
                     * 认证服务器 2 无法连通, 确认为网络连接错误
                     */

                    LOG_ERROR("认证服务器 2 无法连通, 建议检查外部网络连接情况");

                    conn_status = CONNECT_ERROR;
                }
            }
        }
    }

    if (conn_status == CONNECT_INTERNET && (resp.http_code == HTTP_NO_CONTENT || resp.http_code == HTTP_MOVED_PERMANENTLY))
    {
        // 正常联网
        return STATUS_OK;
    }
    if (resp.http_code == HTTP_FOUND)
    {
        // 需要认证
        return STATUS_NEED_AUTH;
    }
    // 网络错误
    return STATUS_ERROR;
}
