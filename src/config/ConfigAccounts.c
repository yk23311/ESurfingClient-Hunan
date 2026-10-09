#include "utils/PlatformUtils.h"

#include "states/States.h"

#include "config/ConfigInternal.h"

#include "utils/Logger.h"

#include "hunan/Hunan.h"

#include "cJSON/cJSON.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define WINDOWS_UA "CCTP/WinSVR5/1068"
#define LINUX_UA "CCTP/Linux64/1003"
#define OLD_ANDROID_UA "CCTP/android64_vpn/2093"
#define ANDROID_UA "CCTP/android11_64/2104"
#define IOS_UA "CCTP/iOSdy/4023"
#define MACOS_UA "CCTP/macdy/5019"

static bool channel_str_eq(const char* a, const char* b)
{
#ifdef _WIN32
    return _stricmp(a, b) == 0;
#else
    return strcasecmp(a, b) == 0;
#endif
}

uint8_t parse_channel_json(const cJSON* chn, const uint8_t cfg_no)
{
    if (chn == NULL)
    {
        LOG_WARN("配置 %" PRIu8 " channel 参数不存在, 使用默认通道 3 (Android)", cfg_no);
        return 3;
    }

    if (cJSON_IsNumber(chn))
    {
        const int value = chn->valueint;
        if (value >= 1 && value <= 5)
        {
            return (uint8_t)value;
        }
        LOG_WARN("配置 %" PRIu8 " channel 参数错误, 使用默认通道 3 (Android)", cfg_no);
        return 3;
    }

    if (cJSON_IsString(chn) && chn->valuestring != NULL)
    {
        const char* value = chn->valuestring;
        if (channel_str_eq(value, "windows") || channel_str_eq(value, "1"))
        {
            return 1;
        }
        if (channel_str_eq(value, "linux") || channel_str_eq(value, "2"))
        {
            return 2;
        }
        if (channel_str_eq(value, "android") || channel_str_eq(value, "3"))
        {
            return 3;
        }
        if (channel_str_eq(value, "ios") || channel_str_eq(value, "iphone") || channel_str_eq(value, "4"))
        {
            return 4;
        }
        if (channel_str_eq(value, "macos") || channel_str_eq(value, "mac") || channel_str_eq(value, "osx") || channel_str_eq(value, "5"))
        {
            return 5;
        }
    }

    LOG_WARN("配置 %" PRIu8 " channel 参数错误, 使用默认通道 3 (Android)", cfg_no);
    return 3;
}

void apply_channel_ua(login_cfg_t* cfg, uint8_t cfg_no)
{
    switch (cfg->chn)
    {
    case 1:
        LOG_INFO("使用通道 1: Windows");
        snprintf(cfg->user_agent, USER_AGENT_LEN, WINDOWS_UA);
        break;
    case 2:
        LOG_INFO("使用通道 2: Linux");
        snprintf(cfg->user_agent, USER_AGENT_LEN, LINUX_UA);
        break;
    case 3:
        LOG_INFO("使用通道 3: Android");
        snprintf(cfg->user_agent, USER_AGENT_LEN, ANDROID_UA);
        break;
    case 4:
        LOG_INFO("使用通道 4: iOS");
        snprintf(cfg->user_agent, USER_AGENT_LEN, IOS_UA);
        break;
    case 5:
        LOG_INFO("使用通道 5: macOS");
        snprintf(cfg->user_agent, USER_AGENT_LEN, MACOS_UA);
        break;
    default:
        LOG_WARN("配置 %" PRIu8 " channel 参数错误, 使用默认通道 3 (Android)", cfg_no);
        cfg->chn = 3;
        snprintf(cfg->user_agent, USER_AGENT_LEN, ANDROID_UA);
        break;
    }
}

static bool prov_str_eq(const char* a, const char* b)
{
    if (!a || !b) return false;
    while (*a && *b)
    {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

/**
 * 读取省份相关配置。
 *
 * 广东: 全部靠运行时发现 (门户页里挖 auth-url/ticket-url), 这里什么都不用给。
 * 湖南: 门户是固定的, 端点也是固定的 .cgi, 所以要从配置里拿门户地址;
 *       而且 UA / ostag / client-id 都用官方客户端的固定值, 覆盖掉通道给的那套。
 *
 * 必须在 apply_channel_ua 之后调用。
 */
void apply_province_json(login_cfg_t* cfg, const cJSON* account, const uint8_t cfg_no)
{
    cfg->province = DEFAULT_PROVINCE;
    snprintf(cfg->portal, sizeof(cfg->portal), "%s", HUNAN_DEFAULT_PORTAL);
    cfg->portal_port = HUNAN_DEFAULT_PORT;
    cfg->mscgip[0] = '\0';

    const cJSON* pv = cJSON_GetObjectItem(account, "province");
    if (pv && cJSON_IsString(pv) && pv->valuestring && pv->valuestring[0])
    {
        if (prov_str_eq(pv->valuestring, "hunan"))
        {
            cfg->province = PROVINCE_HUNAN;
        }
        else if (prov_str_eq(pv->valuestring, "guangdong") || prov_str_eq(pv->valuestring, "gd"))
        {
            cfg->province = PROVINCE_GUANGDONG;
        }
        else
        {
            LOG_WARN("配置 %" PRIu8 " province 参数无法识别 (\"%s\"), 按广东处理",
                     cfg_no, pv->valuestring);
        }
    }

    const cJSON* portal = cJSON_GetObjectItem(account, "portal");
    if (portal && cJSON_IsString(portal) && portal->valuestring && portal->valuestring[0])
    {
        snprintf(cfg->portal, sizeof(cfg->portal), "%s", portal->valuestring);
    }

    const cJSON* pport = cJSON_GetObjectItem(account, "portal_port");
    if (pport && cJSON_IsNumber(pport) && pport->valueint > 0 && pport->valueint < 65536)
    {
        cfg->portal_port = (uint16_t)pport->valueint;
    }

    const cJSON* msc = cJSON_GetObjectItem(account, "mscgip");
    if (msc && cJSON_IsString(msc) && msc->valuestring && msc->valuestring[0])
    {
        snprintf(cfg->mscgip, sizeof(cfg->mscgip), "%s", msc->valuestring);
    }

    if (cfg->province == PROVINCE_HUNAN)
    {
        snprintf(cfg->user_agent, USER_AGENT_LEN, "%s", HUNAN_UA);
        LOG_INFO("配置 %" PRIu8 " 使用湖南模式: 门户 %s:%" PRIu16 "  UA %s",
                 cfg_no, cfg->portal, cfg->portal_port, cfg->user_agent);
    }
    else
    {
        LOG_DEBUG("配置 %" PRIu8 " 使用广东模式 (运行时发现门户与端点)", cfg_no);
    }
}

int list_accounts()
{
    /**
     * stdout 要留给账号列表, 日志一行都不落盘 (全部改写到 stderr).
     *
     * 查询模式必须在 init_logger / load_cfg 之前打开: 这两个调用本身就会写日志,
     * 而写进 run.log 的那几行会被 OpenWrt 的启动脚本当成上一轮运行留下的日志
     * 归档走 (见 set_logger_query_mode 的说明)
     */
    set_logger_query_mode(true);
    set_logger_console(false);

    if (init_logger() == false)
    {
        fprintf(stderr, "[ERROR] 日志系统初始化失败\n");
        return -1;
    }

    /**
     * 复用 load_cfg 的整套校验:
     * 列举出来的账号与真正会被加载的必须完全一致, 否则 init 脚本会起出跑不起来的实例
     */
    s_list_only = true;
    const bool loaded = load_cfg();
    s_list_only = false;

    if (loaded == false)
    {
        // 配置有问题时 load_cfg 已经把原因写到 stderr 了
        return -1;
    }

    for (uint8_t i = 0; i < g_prog_cnt; i++)
    {
        printf("%" PRIu8 "\n", g_prog_status[i].login_cfg.idx);
    }
    fflush(stdout);

    // 这里不调用 clean_logger: 它会把 run.log 改名收尾,
    // 而多实例下 run.log 是所有进程共用的, 每次列举都改名会破坏其它实例的写入
    return g_prog_cnt;
}
