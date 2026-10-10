#include "clients/dialer/DialerInternal.h"

#include "clients/net/NetClient.h"

#include "states/States.h"

#include "utils/PlatformUtils.h"
#include "utils/UrlParse.h"
#include "utils/TimeControl.h"
#include "utils/LogoutState.h"
#include "utils/Shutdown.h"
#include "utils/Watchdog.h"
#include "utils/Logger.h"
#include "utils/sim/SimThread.h"

#include "hunan/Hunan.h"
#include "hunan/HunanXml.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#ifndef __OPENWRT__
#include "control/Control.h"
#endif

/**
 * 湖南: 端点靠约定, 身份靠网卡, **门户地址靠接入设备下发**。
 *
 * 广东要从门户页里的 campus.js 注释块挖 auth-url / ticket-url,
 * 再从挖到的 ticket-url 的查询串里取 wlanuserip / wlanacip。
 * 湖南门户没有这套 —— 端点名和身份都是已知的:
 *   · 端点 = 固定的 .cgi 名 (HunanXml 里的字段顺序表)
 *   · 每个请求都要自带查询串 wlanuserip=&mscgip=&wlanusermac=
 *   · 身份 (client_ip / mac_addr / ac_ip=网关) 由 refresh_states() 从真实网卡填好
 *
 * 门户地址**不是**写死的: 未认证时 BAS 会把明文 HTTP 劫持成 302, 那个 Location
 * 里直接带着门户地址与 mscgip (见 CheckNetwork.c 的 remember_portal_hint)。
 * 配置里的 portal/mscgip 因此退化成"接入设备没下发时的回退值", 换接入设备不再失效。
 * 广东分支本来就是这个机制 (discover_guangdong 读 last_location), 这里只是把它
 * 补回湖南 —— 湖南适配时曾经把它改成了读配置。
 *
 * keep-url / term-url **不用预填** —— 湖南 auth.cgi 的响应里会返回这两个
 * (实测), 后面的 login() 会把它们解析出来。
 */
static bool discover_hunan()
{
    login_cfg_t* lc = &g_prog_status[tl_thread_idx].login_cfg;
    auth_cfg_t* ac = &g_prog_status[tl_thread_idx].auth_cfg;

    if (ac->client_ip[0] == '\0')
    {
        LOG_ERROR("湖南: 没有本机 IP (refresh_states 没能从网卡取到身份)");
        return false;
    }

    /**
     * 用"判定需要认证那一刻"的快照, 不是 get_last_location() 跟随重定向之后的
     * last_location —— 后者可能停在一个被动态防护挡着的网页门户上 (实测那个地址
     * 根路径 412、index.cgi 403, 拿它当 API 基址必然全失败)。
     * 快照缺失时才退回 last_location。
     */
    const char* hint = g_prog_status[tl_thread_idx].portal_hint;
    if (hint[0] == '\0') hint = g_prog_status[tl_thread_idx].last_location;

    char portal[64];
    uint16_t portal_port = 0;
    bool from_device = false;

    if (hint[0] != '\0' && url_split_host_port(hint, portal, sizeof(portal), &portal_port))
    {
        from_device = true;

        if (strcmp(portal, lc->portal) != 0 || portal_port != lc->portal_port)
        {
            LOG_INFO("湖南: 门户改用接入设备下发的 %s:%" PRIu16 " (配置里是 %s:%" PRIu16 ")",
                     portal, portal_port, safe_str(lc->portal), lc->portal_port);
        }
    }
    else if (lc->portal[0] != '\0')
    {
        snprintf(portal, sizeof(portal), "%s", lc->portal);
        portal_port = lc->portal_port;
        LOG_WARN("湖南: 接入设备未下发门户地址, 回退配置 %s:%" PRIu16, portal, portal_port);
    }
    else
    {
        LOG_ERROR("湖南: 没有门户地址 (接入设备未下发, 配置里也没有)");
        return false;
    }

    /**
     * 把"这次实际用哪个门户"记成只读快照, 供网页界面显示。
     *
     * 注意这**不是**写回 login_cfg.portal —— 那会让网页保存时把发现值固化成
     * 配置文件里的死值 (见 States.h 里 runtime_portal 的注释)。
     * 页面因此能如实告诉用户"程序在连 175.x, 而你配置里填的是 10.x"。
     */
    snprintf(g_prog_status[tl_thread_idx].runtime_portal,
             sizeof(g_prog_status[tl_thread_idx].runtime_portal), "%s", portal);
    g_prog_status[tl_thread_idx].runtime_portal_port = portal_port;
    snprintf(g_prog_status[tl_thread_idx].portal_source,
             sizeof(g_prog_status[tl_thread_idx].portal_source),
             "%s", from_device ? "dhcp" : "config");

    /**
     * mscgip 同样优先用接入设备下发的。
     *
     * 注意它**不是**默认网关: 查询串里的 mscgip 是接入设备地址 (实测
     * 218.75.255.245), 而报文 <gwip> 用的是真实默认网关 (实测 100.67.192.1)。
     * 两个值不同, 不能互相替代。
     */
    char mscgip[IP_LEN];
    snprintf(mscgip, sizeof(mscgip), "%s", safe_str(lc->mscgip));

    if (hint[0] != '\0')
    {
        const char* found = NULL;
        size_t found_len = 0;

        /* 广东的习惯是 wlanacip, 湖南是 mscgip; 两个都认 */
        if (url_find_query_value(hint, "mscgip", &found, &found_len) == false)
        {
            url_find_query_value(hint, "wlanacip", &found, &found_len);
        }

        if (found != NULL && found_len > 0)
        {
            if (found_len > sizeof(mscgip) - 1) found_len = sizeof(mscgip) - 1;

            if (found_len != strlen(mscgip) || strncmp(found, mscgip, found_len) != 0)
            {
                LOG_INFO("湖南: mscgip 改用接入设备下发的 %.*s (配置里是 %s)",
                         (int)found_len, found, mscgip[0] ? mscgip : "(空)");
            }

            memcpy(mscgip, found, found_len);
            mscgip[found_len] = '\0';
        }
    }

    if (mscgip[0] == '\0')
    {
        LOG_WARN("湖南: 没有 mscgip, 查询串里会留空 (实测留空也能过)");
    }

    /* 查询串里的 MAC 是不带分隔符的 12 位小写 */
    char mac_hex[MAC_ADDR_LEN];
    size_t j = 0;
    for (size_t i = 0; ac->mac_addr[i] && j < sizeof(mac_hex) - 1; ++i)
    {
        if (isxdigit((unsigned char)ac->mac_addr[i]))
            mac_hex[j++] = (char)tolower((unsigned char)ac->mac_addr[i]);
    }
    mac_hex[j] = '\0';
    if (j != 12)
    {
        LOG_ERROR("湖南: MAC 不是 12 位十六进制 (\"%s\")", ac->mac_addr);
        return false;
    }

    /* 每个字段都显式限长: 查询串最长 74 字节, 保证拼出来的 URL 塞得下 */
    char query[128];
    snprintf(query, sizeof(query), "wlanuserip=%.15s&mscgip=%.15s&wlanusermac=%.12s",
             ac->client_ip, mscgip, mac_hex);

    snprintf(ac->ticket_url, TICKET_URL_LEN, "http://%s:%" PRIu16 "/%s?%s",
             portal, portal_port, hunan_endpoint_path(HUNAN_EP_TICKET), query);
    snprintf(ac->auth_url, AUTH_URL_LEN, "http://%s:%" PRIu16 "/%s?%s",
             portal, portal_port, hunan_endpoint_path(HUNAN_EP_AUTH), query);

    LOG_INFO("湖南 Ticket URL: %s", ac->ticket_url);
    LOG_INFO("湖南 Auth URL  : %s", ac->auth_url);
    LOG_INFO("湖南身份: IP=%s MAC=%s 网关=%s", ac->client_ip, ac->mac_addr, ac->ac_ip);
    return true;
}

static bool discover_guangdong()
{
    const char portal_start_tag[] = "<!--//config.campus.js.chinatelecom.com";
    const char portal_end_tag[] = "//config.campus.js.chinatelecom.com-->";

    const curl_resp_t resp = get(g_prog_status[tl_thread_idx].last_location, false); // curl GET last_location 获取认证配置
    if (resp.http_code != HTTP_OK || resp.body_size == 0 || resp.body_data == NULL) // 如果响应体没有内容 (非 200 响应码), 则返回
    {
        LOG_ERROR("响应体为空, 无法提取认证配置");
        return false;
    }

    char* portal_config = extract_between_tags(resp.body_data, portal_start_tag, portal_end_tag); // 从响应体内容中提取指定内容
    free(resp.body_data);
    if (portal_config == NULL)
    {
        LOG_ERROR("提取门户配置失败");
        return false;
    }

    char* auth_url = xml_parser(portal_config, "auth-url"); // 提取 auth_url (包含 CDATA 等字符)
    if (auth_url == NULL)
    {
        LOG_ERROR("提取 Auth URL 失败");
        return false;
    }

    char* cleaned_auth_url = clean_CDATA(auth_url); // 提取 auth_url (纯 url, 用于登录函数)
    free(auth_url);
    if (cleaned_auth_url == NULL)
    {
        LOG_ERROR("清除 Auth URL 失败");
        return false;
    }
    snprintf(g_prog_status[tl_thread_idx].auth_cfg.auth_url, AUTH_URL_LEN, "%s", safe_str(cleaned_auth_url)); // 将 auth_url 填入认证配置变量中
    LOG_INFO("Auth URL: %s", g_prog_status[tl_thread_idx].auth_cfg.auth_url);
    free(cleaned_auth_url);

    char* ticket_url = xml_parser(portal_config, "ticket-url"); // 提取 ticket_url (包含 CDATA 等字符)
    free(portal_config);
    if (ticket_url == NULL)
    {
        LOG_ERROR("提取 Ticket URL 失败");
        return false;
    }

    char* cleaned_ticket_url = clean_CDATA(ticket_url); // 提取 ticket_url (纯 url, 用于获取 ticket)
    free(ticket_url);
    if (cleaned_ticket_url == NULL)
    {
        LOG_ERROR("清除 Ticket URL CDATA 失败");
        return false;
    }
    snprintf(g_prog_status[tl_thread_idx].auth_cfg.ticket_url, TICKET_URL_LEN, "%s", safe_str(cleaned_ticket_url)); // 将 ticket_url 填入认证配置变量中
    LOG_INFO("Ticket URL: %s", g_prog_status[tl_thread_idx].auth_cfg.ticket_url);

    char* client_ip = extract_url_param(cleaned_ticket_url, "wlanuserip"); // 提取 client_ip
    if (client_ip == NULL)
    {
        LOG_ERROR("提取 Client IP 失败");
        return false;
    }
    snprintf(g_prog_status[tl_thread_idx].auth_cfg.client_ip, IP_LEN, "%s", safe_str(client_ip)); // 将 client_ip 填入认证配置变量中
    LOG_INFO("Client IP: %s", g_prog_status[tl_thread_idx].auth_cfg.client_ip);
    free(client_ip);

    char* ac_ip = extract_url_param(cleaned_ticket_url, "wlanacip"); // 提取 ac_ip
    /*
     * 部分省份(如湖南)的门户不返回 wlanacip, 只返回 mscgip(网关/接入设备地址),
     * 两者在 ticket 请求里同样填入 <gwip>, 所以这里做一次回退.
     */
    if (ac_ip == NULL)
    {
        ac_ip = extract_url_param(cleaned_ticket_url, "mscgip");
        if (ac_ip != NULL)
        {
            LOG_INFO("未找到 wlanacip, 回退使用 mscgip 作为 AC IP");
        }
    }
    free(cleaned_ticket_url);
    if (ac_ip == NULL)
    {
        LOG_ERROR("提取 AC IP 失败 (wlanacip 与 mscgip 均缺失)");
        return false;
    }
    snprintf(g_prog_status[tl_thread_idx].auth_cfg.ac_ip, IP_LEN, "%s", safe_str(ac_ip)); // 将 ac_ip 填入认证配置变量中
    LOG_INFO("AC IP: %s", g_prog_status[tl_thread_idx].auth_cfg.ac_ip);
    free(ac_ip);
    return true;
}

AuthStatus auth()
{
    LOG_DEBUG("auth 函数入口检查, 使用配置: %" PRIu8 ", 下标: %" PRId8, g_prog_status[tl_thread_idx].login_cfg.idx, tl_thread_idx);

    /**
     * 手动认证请求的消费点在 DialerClient.c 的 dialer_app() (线程启动时) ——
     * 那里读完就清, 因为"跳过 get_last_location()"这个决定必须在**更早**的地方生效。
     * 这里只兜底清一次: 正常路径走到这里时它已经是假了。
     */
    g_prog_status[tl_thread_idx].runtime_status.is_manual_auth_force = false;

    /* 端点与身份: 湖南查配置+网卡, 广东从门户页发现 */
    const bool province = g_prog_status[tl_thread_idx].login_cfg.province;
    LOG_INFO("省份模式: %s", (province == PROVINCE_HUNAN) ? "湖南" : "广东");
    const bool found = (province == PROVINCE_HUNAN) ? discover_hunan() : discover_guangdong();
    if (found == false)
    {
        LOG_ERROR("准备认证参数失败");
        return AUTH_FAILED;
    }

    /**
     * 初始化会话
     * 如果失败, 清除会话并返回 INIT_SESSION_FAILED
     */
    if (init_session() == false)
    {
        LOG_FATAL("初始化会话失败");
        return INIT_SESSION_FAILED;
    }
    LOG_DEBUG("初始化会话完成");

    /**
     * 获取 ticket
     * 如果失败, 清除会话并返回 GET_TICKET_FAILED
     */
    if (get_ticket() == false)
    {
        LOG_FATAL("获取 Ticket 失败");
        return GET_TICKET_FAILED;
    }
    LOG_DEBUG("完成获取 Ticket");

    /**
     * 登录认证
     * 如果失败, 清除会话并返回 LOGIN_FAILED
     */
    if (login() == false)
    {
        LOG_ERROR("登录失败");
        return LOGIN_FAILED;
    }
    LOG_DEBUG("完成登录");

    g_prog_status[tl_thread_idx].auth_cfg.tick = get_cur_tm_ms(); // 获取当前 tick
    g_prog_status[tl_thread_idx].auth_cfg.auth_time = get_cur_tm_ms(); // 获取认证时间
    LOG_DEBUG("登录时间戳: %" PRIu64, g_prog_status[tl_thread_idx].auth_cfg.auth_time);

    g_prog_status[tl_thread_idx].runtime_status.is_authed = true;
    LOG_INFO("已认证登录");

    /**
     * 把"以后要登出所需要的现场"存下来。
     *
     * 存下来之后, 即使进程被强杀 (断电 / 看门狗 / 端口撞车), 下次启动也能
     * 先把这次会话登出掉 —— 否则账号会挂在服务端在线, 下次只能一直刷
     * "已连接至互联网", 等服务器把它踢下线。登出成功时会把存档删掉。
     */
    logout_state_save(&g_prog_status[tl_thread_idx]);

    sleep_ms(5000, false);
    return AUTH_SUCCESS;
}

/**
 * @brief 认证进程主流程
 *
 * 一个进程只负责一个配置 (由 --account 指定), 与单进程模式的区别:
 * - 不启动 Web 服务器
 * - 不启动线程守护: 认证失败直接退出, 由外部监管者 (procd / systemd / 服务管理器) 重新拉起.
 *   崩溃回环保护交给监管者, 比这里的无限重启可靠
 * - 时间控制由认证线程自己在循环里校正, 不需要单独的定时线程
 * @return 进程退出码
 */
int work_auth()
{
    g_thread_keep_alive = true;

    g_prog_status = calloc(1, sizeof(prog_status_t));
    init_shutdown_hook();

    if (init_logger() == false) return 1;

    print_banner();

    if (load_cfg() == false) shut(1);

    if (g_prog_cnt != 1)
    {
        LOG_FATAL("认证进程需要且只需要一个配置, 当前加载了 %" PRId8 " 个, 请检查 --account", g_prog_cnt);
        shut(1);
    }

    LOG_INFO("以认证进程运行, 负责配置 %" PRIu8, g_prog_status[0].login_cfg.idx);

    /**
     * 记下本进程的线程 ID, 让日志能标出这是哪个账号的进程
     * 必须放在 load_cfg 之后: 日志标识用的是配置序号
     */
    g_prog_status[0].thread_id = sim_thread_cur_id();

#ifndef __OPENWRT__

    /**
     * 启动控制通道, 供 Web 进程查询状态与下发动作.
     * 端口被占用不算致命: 认证本身不需要它, 降级为不提供远程控制即可
     */
    if (control_server_start(g_control_port) == false)
    {
        /**
         * 说清后果: 控制服务起不来, 监管者停止本进程时就只能用强杀的办法,
         * 那样跑不到 clean(), 也就不会登出 —— 账号会停在服务端在线状态。
         * 最常见的原因是端口被别的程序占了 (监管者按 g_control_port + 账号下标分配)
         */
        LOG_WARN("控制通道启动失败 (端口 %" PRIu16 " 可能被占用), 本实例将不提供远程控制, "
                 "停止时也无法被请求优雅退出 (会被直接结束, 不会登出)", g_control_port);
    }

#endif

    /**
     * 启动看门狗
     *
     * 外部监管者只能看到"进程退出了没有": 进程卡死 (死锁 / 无超时的阻塞调用 /
     * 绕不出来的死循环) 时它照样活着, 监管者永远不会重启它。
     * OpenWrt 上尤其明显 —— 那边连监管进程都没有, 只有 procd 在看进程在不在。
     *
     * 放在配置加载之后: 打卡预算要用配置里的网络超时来算
     */
    watchdog_start();

    /**
     * 先把上次没做完的登出补上, 再走正常流程
     *
     * 必须排在网络检测之前: 会话还挂在服务端时, 网络检测会认为"已连接至互联网"
     * 而一直空转, 要等服务器把会话踢下线才能重新认证
     */
    logout_previous_session();

    /**
     * 认证循环
     * dialer_app 内部已处理登录/心跳/登出/重试, 这里只决定"什么时候再跑一轮":
     * - 不在允许时段: 不做任何网络动作, 等下一次时间窗口
     * - 需要重新认证: 立刻重来
     * - 认证失败: 进程退出, 交给外部监管者
     */
    bool network_ready = false;

    while (g_need_exit == false && g_stop_requested == 0)
    {
        if (supervisor_gone())
        {
            LOG_WARN("守护进程已退出, 本进程一并退出");
            break;
        }

        time_control_sync();

        if (g_prog_status[0].runtime_status.is_time_disabled)
        {
            /**
             * 不在允许时段, 此时没有会话需要登出.
             * 必须把这两个标志复位, 否则 sleep_ms 会因为 is_need_reauth 立刻返回造成忙等
             */
            g_prog_status[0].runtime_status.is_running = true;
            g_prog_status[0].runtime_status.is_need_reauth = false;
            network_ready = false; // 换到下一个允许时段后重新做一次网络检测

            const uint64_t wait_ms = time_control_wait_ms();
            LOG_INFO("配置 %" PRIu8 " 不在允许时段, 等待 %" PRIu64 " 毫秒后重新检查",
                g_prog_status[0].login_cfg.idx, wait_ms);

            // 这是全流程里最长的合法静默 (可能几小时), sleep_ms 会按这个时长打卡
            sleep_ms(wait_ms, true);
            continue;
        }

        /**
         * 用户主动断开: 会话已经登出, 在这里等「连接」指令。
         *
         * 必须排在 wait_need_auth 之前 —— 断开之后网络本来就处于"需要认证"状态,
         * 不拦一下会立刻重新认证, 用户看到的"断开"就只是一次瞬断。
         * 这段等待期间不发任何网络请求。
         */
        if (g_prog_status[0].runtime_status.is_manual_offline)
        {
            LOG_INFO("已断开连接, 等待「连接」指令");

            while (g_prog_status[0].runtime_status.is_manual_offline
                   && g_need_exit == false && g_stop_requested == 0 && supervisor_gone() == false)
            {
                sleep_ms(1000, false);
            }

            network_ready = false; // 重新走一次网络检测再认证
            continue;
        }

        /**
         * 配置还不足以认证 (账号为空 / 被停用)。
         *
         * 本角色没有网页界面, 用户只能改配置文件, 所以这里定期重读一遍等它变好。
         * **不能直接退出**: 退出会被监管者当成崩溃反复重启, 变成重启风暴;
         * 也不能就这么往下走 —— 那会拿空用户名去认证。
         */
        if (g_cfg_ready == false)
        {
            LOG_INFO("【待配置】账号或省份尚未填好, 本进程不会发起认证");
            LOG_INFO("请编辑 %s 填好账号与省份 (enabled 需要为 true)", get_config_path());

            while (g_cfg_ready == false
                   && g_need_exit == false && g_stop_requested == 0 && supervisor_gone() == false)
            {
                sleep_ms(10000, false);
                if (load_cfg() == false) shut(1);
            }

            network_ready = false; // 配好了重新走一次网络检测
            continue;
        }

        /**
         * 启动时先等网络进入需要认证的状态 (与单进程模式一致).
         * 等待过程中若允许时段关闭, wait_need_auth 会把控制权交回来
         */
        if (network_ready == false)
        {
            const WaitResult wait_result = wait_need_auth();

            if (wait_result == WAIT_RETRY_EXHAUSTED) shut(1);
            if (wait_result == WAIT_EXIT) break;
            if (wait_result == WAIT_TIME_CLOSED) continue;

            network_ready = true;
        }

        const int auth_code = dialer_app((void*)(intptr_t)0);

        /**
         * 收到退出请求 (信号只置了标志): dialer_app 的循环会随之退出,
         * 正常返回并跑完 clean() —— 登出就在这里发生
         */
        if (g_need_exit || g_stop_requested) break;

        if (auth_code != 0)
        {
            LOG_ERROR("配置 %" PRIu8 " 认证失败, 进程退出, 由外部监管者重新拉起", g_prog_status[0].login_cfg.idx);
            return auth_code;
        }

        /**
         * Web 端请求"应用新配置"时会把 g_cfg_loaded 置为 false,
         * 这里重新加载. 配置里若已经没有本实例负责的账号, load_cfg 会失败并让进程退出,
         * 由外部监管者按 respawn 策略处理
         */
        if (g_cfg_loaded == false)
        {
            LOG_INFO("配置已变更, 重新加载");
            if (load_cfg() == false) shut(1);

            network_ready = false; // 换过配置后重新做网络检测
            continue;
        }

        LOG_INFO("配置 %" PRIu8 " 需要重新认证, 重新开始认证流程", g_prog_status[0].login_cfg.idx);
    }

    LOG_INFO("认证进程退出");
    shut(0); // 停控制通道、收尾日志, 不会返回
    return 0;
}
