#include "clients/dialer/DialerInternal.h"

#include "clients/net/NetClient.h"

#include "cipher/CipherInterface.h"

#include "states/States.h"

#include "utils/PlatformUtils.h"
#include "utils/Logger.h"

#include "hunan/Hunan.h"

#include <string.h>

static void clean_session()
{
    LOG_DEBUG("清除会话初始化状态");
    destroy_cipher_factory();
    g_prog_status[tl_thread_idx].runtime_status.is_initialized = 0;
}

bool init_session()
{
    LOG_DEBUG("init_session 函数入口检查, 使用配置: %" PRIu8 ", 下标: %" PRIu8, g_prog_status[tl_thread_idx].login_cfg.idx, tl_thread_idx);

    /**
     * 湖南: **不做算法协商**。
     *
     * 广东的流程是 POST Algo-ID 到 ticket_url, 服务端回一个 ZSM 块,
     * 客户端解包出 Algo-ID 再查本地密钥表。湖南门户不下发 ZSM ——
     * ticket.cgi 直接返回加密的 XML 票据 (实测响应 352 字节),
     * 而此刻 algo_id 还是全 0 UUID, 照广东那条路走必然失败。
     *
     * 所以这里跳过 ZSM 拉取, 直接用固定的 Algo-ID 初始化本地密钥表。
     * 身份 (client_ip / mac / ac_ip) 已在 refresh_states() 里从真实网卡取好。
     */
    if (g_prog_status[tl_thread_idx].login_cfg.province == PROVINCE_HUNAN)
    {
        if (init_cipher(HUNAN_ALGO_ID) == false)
        {
            LOG_ERROR("湖南: 初始化 %s 的加解密工厂失败", HUNAN_ALGO_ID);
            return false;
        }
        snprintf(g_prog_status[tl_thread_idx].auth_cfg.algo_id, ALGO_ID_LEN, "%s", HUNAN_ALGO_ID);
        LOG_INFO("湖南: 使用固定 Algo-ID %s (跳过 ZSM 拉取)", HUNAN_ALGO_ID);
        g_prog_status[tl_thread_idx].runtime_status.is_initialized = 1;
        return true;
    }

    /**
     * 向 ticket_url POST 获取 ZSM.
     * iOS/macOS 没有本地模块时 Algo-ID 为零 UUID, 首次用空 POST.
     * Android/Linux 仍 POST 全 0 UUID.
     */
    const char* ticket_body = g_prog_status[tl_thread_idx].auth_cfg.algo_id;
    if (g_prog_status[tl_thread_idx].login_cfg.chn == 4 || g_prog_status[tl_thread_idx].login_cfg.chn == 5)
    {
        ticket_body = "";
        LOG_INFO("iOS/macOS 通道首次拉取 ZSM 使用空 POST");
    }
    const curl_resp_t resp = post(g_prog_status[tl_thread_idx].auth_cfg.ticket_url, ticket_body);
    if (resp.http_code != HTTP_OK || resp.body_size == 0 || resp.body_data == NULL) // 响应错误或无响应数据, 则返回 false
    {
        LOG_ERROR("初始化会话失败");
        free(resp.body_data);
        return false;
    }
    LOG_DEBUG("会话响应长度: %zu", resp.body_size);
    {
        const bytes_t zsm = {
            .data = (uint8_t*)resp.body_data,
            .len = resp.body_size
        };

        LOG_DEBUG("开始初始化会话");

        /**
         * 加载加解密工厂
         * 如果失败, 返回 false
         */
        if (load_cipher(zsm) == false)
        {
            LOG_DEBUG("初始化会话失败");
            g_prog_status[tl_thread_idx].runtime_status.is_initialized = 0;
            free(resp.body_data);
            return false;
        }
    }
    LOG_DEBUG("初始化会话成功");
    g_prog_status[tl_thread_idx].runtime_status.is_initialized = 1;
    free(resp.body_data);
    return true;
}

void clean()
{
    // 时间控制禁用状态是跨线程的“外部闸门”，线程退出清理时不能把它清掉，
    // 否则线程守护会立刻把刚下线的账号重新拉起来。
    const bool time_disabled = g_prog_status[tl_thread_idx].runtime_status.is_time_disabled;

    /**
     * 用户主动断开同理, 而且更硬: 清掉它等于"用户点了断开, 程序立刻自己连回去"。
     * 这里正是登出发生的地方 —— 标志活过一次 clean(), 线程守护才不会重启线程。
     */
    const bool manual_offline = g_prog_status[tl_thread_idx].runtime_status.is_manual_offline;

    /**
     * 手动认证请求同理: 它由**网页线程**置上、由**认证线程**消费, 而两者之间隔着
     * 一次线程退出 —— 就被这里的 memset 抹掉的话, 用户点了没反应。
     * 用掉的时机见 DialerClient.c 的线程守护 (一次请求只放行一次尝试)。
     */
    const bool manual_auth_pending = g_prog_status[tl_thread_idx].runtime_status.is_manual_auth_pending;
    const bool manual_auth_force = g_prog_status[tl_thread_idx].runtime_status.is_manual_auth_force;

    if (g_prog_status[tl_thread_idx].runtime_status.is_initialized == true) // 如果已经初始化会话, 则进入
    {
        if (g_prog_status[tl_thread_idx].runtime_status.is_authed == true) // 如果已经认证, 则进入
        {
            LOG_INFO("配置 %" PRIu8 " 登出, 下标: %" PRId8,
                g_prog_status[tl_thread_idx].login_cfg.idx,
                tl_thread_idx);
            term(); // 登出
        }
        clean_session(); // 清理会话
    }
    memset(&g_prog_status[tl_thread_idx].auth_cfg, 0, sizeof(auth_cfg_t)); // 清除 auth_cfg 的内容, 并置零
    memset(&g_prog_status[tl_thread_idx].runtime_status, 0, sizeof(runtime_status_t)); // 清除 runtime_status 的内容, 并置零
    g_prog_status[tl_thread_idx].runtime_status.is_time_disabled = time_disabled; // 恢复时间控制禁用状态
    g_prog_status[tl_thread_idx].runtime_status.is_manual_offline = manual_offline; // 恢复"用户已断开"状态
    g_prog_status[tl_thread_idx].runtime_status.is_manual_auth_pending = manual_auth_pending; // 恢复"手动认证请求未消费"
    g_prog_status[tl_thread_idx].runtime_status.is_manual_auth_force = manual_auth_force; // 恢复"跳过网络等待"
}

void reset()
{
    clean(); // 清理数据
    refresh_states(); // 重置指定数据
}

/**
 * @brief 监管进程是否已经不在了
 *
 * 只在被监管的角色下判断: 单进程模式的父进程是终端或服务管理器,
 * 它们退出并不意味着本程序该退出。
 * Linux 上子进程登记了 PR_SET_PDEATHSIG, 内核会直接通知, 这里恒为 false
 */
bool supervisor_gone()
{
    if (g_prog_role != ROLE_AUTH && g_prog_role != ROLE_WEB) return false;
    return parent_process_alive() == false;
}
