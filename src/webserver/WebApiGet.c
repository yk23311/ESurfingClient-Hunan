#include "webserver/WebInternal.h"

#include <minihttp/minihttp.h>

#include "clients/net/NetClient.h"

#include "config/Config.h"

#include "control/Control.h"

#include "states/States.h"

#include "utils/PlatformUtils.h"
#include "utils/Logger.h"

#include <cJSON/cJSON.h>

#define LOG_FILE_MAX 64
#define LOG_READ_MAX (256 * 1024)

/**
 * @brief 查询认证状态
 * @param out 是否已认证
 * @return 是否查询成功 (Web 进程连不上认证进程时为 false)
 */
bool query_is_authed(bool* out)
{
    if (s_local_state)
    {
        if (g_prog_status == NULL || g_prog_cnt <= 0) return false;
        *out = g_prog_status[0].runtime_status.is_authed;
        return true;
    }

    control_status_t status;
    if (control_query_status(&status) == false) return false;

    *out = status.is_authed;
    return true;
}

/**
 * @brief 查询"用户是否已主动断开连接"
 * @param out 是否处于主动断开状态
 * @return 是否查询成功 (Web 进程连不上认证进程时为 false)
 */
bool query_is_manual_offline(bool* out)
{
    if (out == NULL) return false;

    if (s_local_state)
    {
        if (g_prog_status == NULL || g_prog_cnt <= 0) return false;
        *out = g_prog_status[0].runtime_status.is_manual_offline;
        return true;
    }

    control_status_t status;
    if (control_query_status(&status) == false) return false;

    *out = status.is_manual_offline;
    return true;
}

/**
 * @brief 读取日志文件内容
 * @param name 日志文件名
 * @param out 输出内容 (需要 free)
 * @param out_len 输出内容长度
 * @param truncated 是否被截断
 * @return 是否读取成功
 */
static bool read_log_file(const char* name, char** out, size_t* out_len, bool* truncated)
{
    const char* dir = get_logger_dir();
    if (dir == NULL || dir[0] == '\0') return false;
    if (is_log_file_name(name) == false) return false;

    char path[PATH_MAX];
    const int path_len = snprintf(path, sizeof(path), "%s%c%s", dir, SEP, name);
    if (path_len <= 0 || (size_t)path_len >= sizeof(path)) return false;

    FILE* file = fopen(path, "rb");
    if (file == NULL) return false;

    fseek(file, 0, SEEK_END);
    const long file_size = ftell(file);
    const size_t size = file_size > 0 ? (size_t)file_size : 0;

    size_t want = size;
    *truncated = false;
    if (want > LOG_READ_MAX)
    {
        want = LOG_READ_MAX;
        *truncated = true;
        fseek(file, (long)(size - want), SEEK_SET);
    }
    else
    {
        fseek(file, 0, SEEK_SET);
    }

    char* buffer = malloc(want + 1);
    if (buffer == NULL)
    {
        fclose(file);
        LOG_ERROR("读取日志时分配内存失败");
        return false;
    }

    const size_t read_len = fread(buffer, 1, want, file);
    fclose(file);
    buffer[read_len] = '\0';

    if (*truncated)
    {
        char* first_break = strchr(buffer, '\n');
        if (first_break != NULL) memmove(buffer, first_break + 1, strlen(first_break + 1) + 1);
    }

    *out = buffer;
    *out_len = strlen(buffer);
    return true;
}

/**
 * @brief 读取"上一次认证实际采用的门户地址"
 *
 * 网页界面用它如实显示程序在连哪 —— 配置里的 portal 只是**回退值**, 未认证时
 * 真实地址由接入设备在 302 里下发 (见 DialerAuth.c 的 discover_hunan)。
 * 用户看到设置页写着 175.12.104.1, 自然会以为那就是程序在用的地址, 其实不是。
 *
 * 多账号取启动最早的那个有值的账号: 页面本来也只编辑第 0 个账号。
 *
 * 无锁读: 写方只有认证线程, 且写进去的字符串要么是完整 IP 要么是空 —— 页面
 * 读到一半的极端情况最多显示一个畸形地址, 不影响任何控制流 (凭据不在此列)。
 *
 * @param portal 输出: 门户地址, 没值时为 ""
 * @param cap    输出缓冲长度
 * @param port   输出: 门户端口, 没值时为 0
 * @param source 输出: "dhcp" / "config" / ""
 * @param src_cap 输出缓冲长度
 * @return 是否取到值
 */
static bool query_live_portal(char* portal, size_t cap, uint16_t* port,
                              char* source, size_t src_cap)
{
    portal[0] = '\0';
    source[0] = '\0';
    *port = 0;

    if (g_prog_status == NULL || g_prog_cnt <= 0) return false;

    for (int8_t i = 0; i < g_prog_cnt; i++)
    {
        const prog_status_t* ps = &g_prog_status[i];
        if (ps->portal_source[0] == '\0' || ps->runtime_portal[0] == '\0') continue;

        snprintf(portal, cap, "%s", ps->runtime_portal);
        *port = ps->runtime_portal_port;
        snprintf(source, src_cap, "%s", ps->portal_source);
        return true;
    }

    return false;
}

/**
 * @brief 处理 GET API 请求
 * @return 是否已处理 (未处理时需要继续走静态文件逻辑)
 */
bool handle_api_get(struct mg_connection* c, struct mg_http_message* hm)
{
    // 根目录转发到 index.html
    if (mg_match(hm->uri, mg_str("/"), NULL))
    {
        mg_http_reply(c, 302, "Location: /index.html\r\n", "");
        return true;
    }

    // 获取认证状态
    if (mg_match(hm->uri, mg_str("/api/status/auth"), NULL))
    {
        bool is_authed = false;
        const bool reachable = query_is_authed(&is_authed);

        bool offline = false;
        query_is_manual_offline(&offline);

        cJSON* auth = cJSON_CreateObject();
        cJSON_AddBoolToObject(auth, "status", is_authed);
        // 认证进程不可达时额外标出来, 前端可据此提示 (不认这个字段的前端会忽略它)
        cJSON_AddBoolToObject(auth, "reachable", reachable);
        // 用户主动断开中: 已认证为假是"预期行为", 前端不该提示异常
        cJSON_AddBoolToObject(auth, "offline", offline);
        char* status_str = cJSON_Print(auth);
        mg_http_reply(c, 200, HEADER_JSON, "%s", status_str);
        free(status_str);
        cJSON_Delete(auth);
        return true;
    }

    // 获取联网状态
    if (mg_match(hm->uri, mg_str("/api/status/online"), NULL))
    {
        switch (check_network_status(true))
        {
        case STATUS_OK:
            mg_http_reply(c, 204, "", "");
            break;
        case STATUS_NEED_AUTH:
            mg_http_reply(c, 302, "", "");
            break;
        default:
            mg_http_reply(c, 503, "", "");
        }
        return true;
    }

    // 获取程序运行信息
    if (mg_match(hm->uri, mg_str("/api/status/sys"), NULL))
    {
        cJSON* info = cJSON_CreateObject();
        cJSON_AddStringToObject(info, "version", PROGRAM_FULL_VERSION);
        cJSON_AddNumberToObject(info, "uptime_ms", (double)(get_cur_tm_ms() - g_start_run_tm));
        cJSON_AddNumberToObject(info, "log_level", get_logger_level());
        cJSON_AddStringToObject(info, "log_dir", safe_str(get_logger_dir()));
        cJSON_AddStringToObject(info, "config_file", safe_str(get_config_file_path()));
        cJSON_AddBoolToObject(info, "program_enabled", g_prog_enabled);

        /**
         * 配置是否已就绪到可以认证。为假时程序只提供网页界面 (首次运行、
         * 账号还没填、或被用户停用) —— 前端据此直接把用户引导到「设置」页。
         */
        cJSON_AddBoolToObject(info, "configured", g_cfg_ready);

        /* 配置文件存在但解析不了: 此时保存会覆盖原文件, 前端要先提示用户 */
        cJSON_AddBoolToObject(info, "config_corrupt", g_cfg_corrupt);

        cJSON_AddBoolToObject(info, "restart_pending", g_need_restart);
        cJSON_AddNumberToObject(info, "account_count", g_prog_cnt);
        cJSON_AddNumberToObject(info, "thread_count", g_prog_cnt);

        /**
         * 上一次认证实际采用的门户。设置页那两栏是**回退值**, 用户很容易误以为
         * 那就是程序在用的地址 —— 这里把真实值单独给出来, 让界面能并排显示。
         */
        {
            char live_portal[64];
            char live_source[8];
            uint16_t live_port = 0;

            if (query_live_portal(live_portal, sizeof(live_portal), &live_port,
                                  live_source, sizeof(live_source)))
            {
                cJSON_AddStringToObject(info, "portal_live", live_portal);
                cJSON_AddNumberToObject(info, "portal_live_port", live_port);
                cJSON_AddStringToObject(info, "portal_source", live_source);
            }
            else
            {
                /* 尚未判定过: 程序刚起来, 或本来就已认证 (没有 302 可看) */
                cJSON_AddStringToObject(info, "portal_live", "");
                cJSON_AddNumberToObject(info, "portal_live_port", 0);
                cJSON_AddStringToObject(info, "portal_source", "");
            }
        }

        char* info_str = cJSON_Print(info);
        mg_http_reply(c, 200, HEADER_JSON, "%s", info_str);
        free(info_str);
        cJSON_Delete(info);
        return true;
    }

    // 获取配置
    if (mg_match(hm->uri, mg_str("/api/getConfigs"), NULL))
    {
        cJSON* configs = cJSON_CreateObject();

        cJSON_AddBoolToObject(configs, "enabled", g_prog_enabled);
        cJSON_AddBoolToObject(configs, "web_external_acc", g_web_external_acc);
        cJSON_AddNumberToObject(configs, "log_lv", get_logger_level());
        /**
         * 这里给的是配置里的原文 (没写时是 "./"), 不是解析后的绝对路径:
         * 页面上的输入框要原样回显, 保存时也原样写回去, 不能把它改写成绝对路径
         * (看实际用的是哪个目录请走 /api/status/sys 的 log_dir)
         */
        cJSON_AddStringToObject(configs, "log_dir", get_logger_dir_cfg());
        cJSON_AddNumberToObject(configs, "conn_timeout", (double)g_conn_timeout);
        cJSON_AddNumberToObject(configs, "op_timeout", (double)g_op_timeout);
        cJSON_AddNumberToObject(configs, "web_port", g_web_port);

        cJSON* accounts = cJSON_CreateArray();
        cJSON* account = cJSON_CreateObject();

        cJSON_AddStringToObject(account, "username", g_prog_status[0].login_cfg.usr);
        cJSON_AddStringToObject(account, "password", g_prog_status[0].login_cfg.pwd);
        {
            const char* channel_name = "android";
            switch (g_prog_status[0].login_cfg.chn)
            {
            case 1:
                channel_name = "windows";
                break;
            case 2:
                channel_name = "linux";
                break;
            case 3:
                channel_name = "android";
                break;
            case 4:
                channel_name = "ios";
                break;
            case 5:
                channel_name = "macos";
                break;
            default:
                channel_name = "android";
                break;
            }
            cJSON_AddStringToObject(account, "channel", channel_name);
        }

        /**
         * 省份相关字段必须回给网页界面。
         *
         * 网页界面保存配置走的是 /api/saveConfigs, 而落盘是**原样写**
         * (见 Config.c 的 write_cfg_json) —— 页面读不到什么, 保存时就会写丢什么。
         * 少了这几个字段, 湖南配置会在用户点一次"保存"后静默退回广东模式:
         * 下次启动 apply_province_json 读不到 province, 默认就是 guangdong。
         */
        cJSON_AddStringToObject(account, "province",
                                g_prog_status[0].login_cfg.province == PROVINCE_HUNAN
                                    ? "hunan" : "guangdong");
        cJSON_AddStringToObject(account, "portal", g_prog_status[0].login_cfg.portal);
        cJSON_AddNumberToObject(account, "portal_port", g_prog_status[0].login_cfg.portal_port);
        cJSON_AddStringToObject(account, "mscgip", g_prog_status[0].login_cfg.mscgip);

        cJSON* time_windows = cJSON_CreateArray();
        for (uint8_t i = 0; i < g_prog_status[0].login_cfg.time_window_count; i++)
        {
            const time_window_t* win = &g_prog_status[0].login_cfg.time_windows[i];
            char start_str[TIME_WINDOW_STR_LEN];
            char end_str[TIME_WINDOW_STR_LEN];
            format_week_min(win->start_week_min, start_str);
            format_week_min(win->end_week_min, end_str);

            cJSON* window_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(window_obj, "start", start_str);
            cJSON_AddStringToObject(window_obj, "end", end_str);
            cJSON_AddItemToArray(time_windows, window_obj);
        }
        cJSON_AddItemToObject(account, "time_windows", time_windows);

        cJSON_AddItemToArray(accounts, account);
        cJSON_AddItemToObject(configs, "accounts", accounts);

        char* config_str = cJSON_Print(configs);

        mg_http_reply(c, 200, HEADER_JSON, "%s", config_str);

        free(config_str);
        cJSON_Delete(configs);
        return true;
    }

    // 获取日志文件列表 / 日志内容
    if (mg_match(hm->uri, mg_str("/api/logs"), NULL))
    {
        char file_name[LOG_NAME_LEN];
        const int name_len = mg_http_get_var(&hm->query, "file", file_name, sizeof(file_name));

        // 带 file 参数: 返回文件内容
        if (name_len > 0)
        {
            if (is_safe_log_name(file_name) == false)
            {
                mg_http_reply(c, 400, HEADER_TEXT, "非法的日志文件名\n");
                return true;
            }

            char* content = NULL;
            size_t content_len = 0;
            bool truncated = false;
            if (read_log_file(file_name, &content, &content_len, &truncated) == false)
            {
                mg_http_reply(c, 404, HEADER_TEXT, "日志文件不存在或已被轮转\n");
                return true;
            }

            LOG_DEBUG("Web 读取日志文件 %s (%zu 字节%s)", file_name, content_len, truncated ? ", 已截断" : "");
            mg_http_reply(c, 200, truncated ? HEADER_TEXT_TRUNCATED : HEADER_TEXT, "%s", content);
            free(content);
            return true;
        }

        // 不带参数: 返回文件列表
        log_file_entry_t entries[LOG_FILE_MAX];
        const int count = list_log_files(entries, LOG_FILE_MAX);
        if (count > 1) qsort(entries, (size_t)count, sizeof(log_file_entry_t), cmp_log_files);

        cJSON* root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "dir", safe_str(get_logger_dir()));
        cJSON* files = cJSON_CreateArray();
        for (int i = 0; i < count; i++)
        {
            cJSON* file = cJSON_CreateObject();
            cJSON_AddStringToObject(file, "name", entries[i].name);
            cJSON_AddNumberToObject(file, "size", (double)entries[i].size);
            cJSON_AddNumberToObject(file, "mtime", (double)entries[i].mtime);
            cJSON_AddBoolToObject(file, "current", entries[i].current);
            cJSON_AddItemToArray(files, file);
        }
        cJSON_AddItemToObject(root, "files", files);

        char* files_str = cJSON_Print(root);
        mg_http_reply(c, 200, HEADER_JSON, "%s", files_str);
        free(files_str);
        cJSON_Delete(root);
        return true;
    }

    return false;
}
