#include "utils/PlatformUtils.h"

#include "states/States.h"

#include "config/ConfigInternal.h"

#include "utils/Logger.h"

#include "cJSON/cJSON.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __OPENWRT__
static const char config_file[] = "/etc/config/esurfingclient";
#else
#define DIALER_CONFIG_FILE "ESurfingClient.json"
static char config_file[PATH_MAX + 1 + sizeof(DIALER_CONFIG_FILE)];
#endif

/**
 * 首次运行时生成的默认配置。
 *
 * 两处刻意的选择:
 *  · enabled = true —— 用户填完账号就不必再去管"启用"开关;
 *    账号为空时程序本来就不会去认证, 所以这里是安全的
 *  · province = hunan —— 本分支是湖南适配版, 而下面的 portal 一直填的就是湖南门户;
 *    以前这里写 guangdong (与 portal 自相矛盾), 用户很容易漏改, 然后
 *    认证失败却报"提取门户配置失败", 极难定位
 */
static const char s_default_cfg[] = "{\n"
                                    "   \"enabled\": true,\n"
                                    "   \"web_external_acc\": false,\n"
                                    "   \"log_lv\": 4,\n"
                                    "   \"log_dir\": \"./\",\n"
                                    "   \"conn_timeout\": 7,\n"
                                    "   \"op_timeout\": 10,\n"
                                    "   \"web_port\": 8888,\n"
                                    "   \"accounts\": [\n"
                                    "       {\n"
                                    "           \"username\": \"\",\n"
                                    "           \"password\": \"\",\n"
                                    "           \"channel\": 3,\n"
                                    "           \"mark\": \"\",\n"
                                    "           \"province\": \"hunan\",\n"
                                    "           \"portal\": \"175.12.104.1\",\n"
                                    "           \"portal_port\": 10001,\n"
                                    "           \"mscgip\": \"\",\n"
                                    "           \"time_windows\": []\n"
                                    "       }\n"
                                    "   ]\n"
                                    "}\n";

/* ------------------------------------------------------------------
 * 配置文件的读写与补全
 * ------------------------------------------------------------------ */

/**
 * @brief 把配置对象写回配置文件
 *
 * 网页界面保存与"启动时补全配置"都走这里: 输出的是 cJSON 的格式 (Tab 缩进),
 * 与网页界面保存出来的完全一致
 * @param cfg_json 配置对象
 * @return 是否写成功
 */
static bool write_cfg_json(const cJSON* cfg_json)
{
    char* cfg_text = cJSON_Print(cfg_json);
    if (cfg_text == NULL)
    {
        LOG_ERROR("配置内容序列化失败");
        return false;
    }

    FILE* cfg_file = fopen(config_file, "w");
    if (!cfg_file)
    {
        LOG_ERROR("无法生成文件: %s", config_file);
        free(cfg_text);
        return false;
    }
    fprintf(cfg_file, "%s", cfg_text);
    fclose(cfg_file);

    free(cfg_text);
    return true;
}

#ifndef __OPENWRT__

bool save_cfg(const char* configs_str)
{
    LOG_INFO("保存配置中");
    LOG_INFO("仅会保存第一个可用配置");

    cJSON* configs = cJSON_Parse(configs_str);
    if (!configs)
    {
        LOG_ERROR("配置 JSON 解析失败");
        return false;
    }

    const bool saved = write_cfg_json(configs);
    cJSON_Delete(configs);

    return saved;
}

const char* get_config_file_path(void)
{
    return config_file;
}

#endif

bool s_list_only = false;

/**
 * @brief 处理无法继续的配置问题
 *
 * 单进程模式下挂起等待人工处理: 配置没填好时反复重启只会刷屏,
 * 等用户改完配置手动重启即可。
 *
 * 挂起期间必须仍然能被 Ctrl+C / 关窗口 / 服务停止打断 —— 有专门的回归用例
 * 盯着这一点 (test-windows-runtime.sh 第 8 节), 因为漏掉时会表现成
 * "程序假死 + 日志不落盘", 只能去任务管理器杀进程。
 *
 * 以下情况直接返回失败, 由调用方退出:
 * - 列举账号: init 脚本调用, 挂起会卡住开机
 * - 认证 / Web / 监管进程: 它们都在外部监管者 (procd / systemd / SCM) 之下,
 *   退出后按 respawn 或重启策略处理。挂住的进程监管者是不会重启的,
 *   那样只会看起来"服务在跑"却什么都不干
 */
void cfg_halt()
{
    if (s_list_only ||
        g_prog_role == ROLE_AUTH ||
        g_prog_role == ROLE_WEB ||
        g_prog_role == ROLE_SUPERVISOR)
    {
        return;
    }

    while (true)
    {
        if (g_need_exit) return;

        /**
         * 信号处理函数现在只置 g_stop_requested (不再直接调 shut() —— 那里面的
         * join / 打日志 / rename / exit 都不是 async-signal-safe 的),
         * 而 g_need_exit 只有 shut() 会置。单进程模式下 shut() 要等 load_cfg()
         * 返回之后才调用, 所以这里只等 g_need_exit 的话会永远等不到:
         * Ctrl+C 毫无反应, 关窗口被系统强杀, 日志也就不会被改名。
         * 返回后由调用方 (work() 里的 shut(1)) 走正常关闭流程。
         */
        if (g_stop_requested) return;

        sleep_ms(10000, true);
    }
}

const char* get_config_path(void)
{
    return config_file;
}

/**
 * @brief 给 g_prog_status[0] 填一份"可显示"的默认账号配置
 *
 * 没有可用账号时, 网页表单也得有东西可显示 (通道 / 省份 / 门户), 所以尽量把
 * 用户已经写在文件里的那几个字段读出来; 读不到 (account 为 NULL, 或文件根本
 * 解析不了) 就用内置默认值。
 *
 * 只填"能让表单显示正确"的字段, 不填 username / password —— 那两个为空正是
 * 程序判定"还没配置好"的依据。
 */
static void fill_default_login_cfg(const cJSON* account)
{
    login_cfg_t* lc = &g_prog_status[0].login_cfg;

    lc->chn = DEFAULT_CHANNEL;
    apply_channel_ua(lc, 1);
    apply_province_json(lc, account, 1);
    lc->idx = 1;
}

bool load_cfg()
{
    g_cfg_loaded = false;
    g_cfg_ready = false;
    g_cfg_corrupt = false;
    /**
     * 桌面分支直接写 g_prog_status[0], 这里保证至少有一格可用
     * (OpenWrt 分支后面会按配置数重新分配)
     */
    if (g_prog_status == NULL)
    {
        g_prog_status = calloc(1, sizeof(prog_status_t));
        if (g_prog_status == NULL)
        {
            LOG_FATAL("分配内存失败");
            cfg_halt();
            return false;
        }
    }
#ifndef __OPENWRT__

    char dir[PATH_MAX];
    if (get_exec_dir(dir) == false)
    {
        LOG_ERROR("获取可执行文件路径失败, 请检查权限后重启");
        cfg_halt();
        return false;
    }
    snprintf(config_file, PATH_MAX + 1 + sizeof(DIALER_CONFIG_FILE), "%s%c%s", safe_str(dir), SEP, DIALER_CONFIG_FILE);

#endif

    /**
     * 配置文件缺失 / 为空 / 语法坏掉时**不再退出或挂起**, 改用内置默认值继续跑起来:
     * 网页界面照常启动, 用户在网页上填完账号即可使用, 不需要先去手工编辑这个文件。
     * 这正是"第一次双击就能配好"的关键。
     */
    FILE* cfg_file = fopen(config_file, "r");
    char* cfg_data = NULL;

    if (!cfg_file || fgetc(cfg_file) == EOF)
    {
        if (cfg_file != NULL) fclose(cfg_file);

        LOG_WARN("配置文件不存在或为空: %s", config_file);
        LOG_INFO("已生成默认配置文件; 接下来请在网页界面上填写账号与省份 (无需手工编辑该文件)");

        FILE* new_cfg = fopen(config_file, "w");
        if (new_cfg == NULL)
        {
            /* 连默认文件都写不出来 (目录只读?)。仍然继续 —— 网页照样能起来,
               只是用户点"保存"时会失败并看到提示 */
            LOG_ERROR("无法生成默认配置文件: %s (目录是否只读?), 本次运行使用内置默认值", config_file);
        }
        else
        {
            fprintf(new_cfg, "%s", s_default_cfg);
            fclose(new_cfg);
        }

        cfg_data = malloc(sizeof(s_default_cfg));
        if (cfg_data != NULL) snprintf(cfg_data, sizeof(s_default_cfg), "%s", s_default_cfg);
    }
    else
    {
        fseek(cfg_file, 0, SEEK_END);
        const long len = ftell(cfg_file);
        fseek(cfg_file, 0, SEEK_SET);

        cfg_data = malloc((size_t)len + 1);
        if (cfg_data != NULL)
        {
            const size_t got = fread(cfg_data, 1, (size_t)len, cfg_file);
            cfg_data[got] = '\0';
        }
        fclose(cfg_file);
    }

    if (cfg_data == NULL)
    {
        LOG_FATAL("读取配置时分配内存失败");
        cfg_halt();
        return false;
    }

    cJSON* cfg_json = cJSON_Parse(cfg_data);
    free(cfg_data);

    if (!cfg_json)
    {
        /**
         * 文件在, 但内容不是合法 JSON。**不覆盖**用户的文件, 只标记出来:
         * 内存里改用默认值继续跑, 网页上会提示"保存会覆盖它", 由用户决定。
         * 这样既不会卡住, 也不会悄悄吃掉别人手工写的配置。
         */
        LOG_ERROR("配置文件无法解析 (JSON 语法错误?): %s", config_file);
        LOG_WARN("本次运行改用内置默认值; 在网页界面上保存配置会覆盖该文件");
        g_cfg_corrupt = true;

        cfg_json = cJSON_Parse(s_default_cfg);
        if (!cfg_json)
        {
            LOG_FATAL("内置默认配置解析失败 (程序内部错误)");
            cfg_halt();
            return false;
        }
    }

    /**
     * 先把配置补全, 再往下解析
     *
     * 放在这里是为了后面每一处解析都能拿到完整的对象; 补全后的内容要写回文件,
     * 用户下次打开配置就能看见自己漏了什么 (写不回去也不影响本次运行, 值已经在内存里)
     */
    const uint8_t completed = complete_cfg(cfg_json);
    if (completed > 0)
    {
        LOG_INFO("配置文件缺少参数, 已按默认值补全 %" PRIu8 " 个", completed);
        if (write_cfg_json(cfg_json))
        {
            LOG_INFO("补全后的配置已写回 %s", config_file);
        }
        else
        {
            LOG_WARN("补全后的配置写回失败 (配置文件可能是只读的?), 本次仍按补全后的值运行");
        }
    }

    /**
     * 下面这些"参数不存在"的分支现在基本走不到了 (上面已经补全),
     * 留着是给补全时分配内存失败之类的极端情况兜底
     */
    const cJSON* enabled = cJSON_GetObjectItem(cfg_json, "enabled");
    if (enabled == NULL)
    {
        LOG_WARN("enabled 参数不存在, 按未启用处理 (可在网页界面上开启)");
        g_prog_enabled = false;
    }
    else if (cJSON_IsFalse(enabled))
    {
        LOG_INFO("配置里已停用认证 (可在网页界面上重新启用)");
        g_prog_enabled = false;
    }
    else
    {
        g_prog_enabled = true;
    }

    const cJSON* log_lv = cJSON_GetObjectItem(cfg_json, "log_lv");
    if (log_lv)
    {
        if (cJSON_IsNumber(log_lv))
        {
            set_logger_level(log_lv->valueint);
        }
        else
        {
            LOG_WARN("log_lv 参数不正确, 使用默认参数 (INFO)");
        }
    }
    else
    {
        LOG_WARN("log_lv 参数不存在, 使用默认参数 (INFO)");
    }

    /**
     * 日志目录
     *
     * 配置里的 log_dir 是【基目录】, 日志放在它下面的 logs 里 (默认就是程序所在目录下的
     * logs, OpenWrt 上则固定为 /var/log/esurfing/logs)。
     * 必须在这里才能定下来: 日志系统是先起来再读配置的 (配置读错了更要有日志),
     * set_logger_dir 会把已经写下的那几行一起搬到新目录去。
     * OpenWrt 上基目录是写死的, 那边只有写了别的目录才会提一句。
     */
    const cJSON* log_dir = cJSON_GetObjectItem(cfg_json, "log_dir");
    if (log_dir)
    {
        if (cJSON_IsString(log_dir) && log_dir->valuestring != NULL)
        {
            set_logger_dir(log_dir->valuestring);
        }
        else
        {
            LOG_WARN("log_dir 参数不正确, 使用默认值 (%s)", get_logger_dir_cfg());
        }
    }
    else
    {
        LOG_DEBUG("log_dir 参数不存在, 使用默认值 (%s)", get_logger_dir_cfg());
    }

    const cJSON* conn_timeout = cJSON_GetObjectItem(cfg_json, "conn_timeout");
    if (conn_timeout)
    {
        if (cJSON_IsNumber(conn_timeout))
        {
            g_conn_timeout = conn_timeout->valueint;
        }
        else
        {
            LOG_WARN("conn_timeout 参数不正确, 使用默认参数 (%d 秒)", DEFAULT_CONN_TIMEOUT);
        }
    }
    else
    {
        LOG_WARN("conn_timeout 参数不存在, 使用默认参数 (%d 秒)", DEFAULT_CONN_TIMEOUT);
    }

    const cJSON* op_timeout = cJSON_GetObjectItem(cfg_json, "op_timeout");
    if (op_timeout)
    {
        if (cJSON_IsNumber(op_timeout))
        {
            g_op_timeout = op_timeout->valueint;
        }
        else
        {
            LOG_WARN("op_timeout 参数不正确, 使用默认参数 (%d 秒)", DEFAULT_OP_TIMEOUT);
        }
    }
    else
    {
        LOG_WARN("op_timeout 参数不存在, 使用默认参数 (%d 秒)", DEFAULT_OP_TIMEOUT);
    }

    /**
     * Web 服务端口与是否允许外部访问
     *
     * 只有桌面端有 Web 服务 (OpenWrt 版不带 Web 服务), 那边这两个参数
     * 解析出来也没人用, 但配置文件的格式是同一套, 这里就一起读掉
     */
    const cJSON* web_port = cJSON_GetObjectItem(cfg_json, "web_port");
    if (web_port)
    {
        if (cJSON_IsNumber(web_port) && web_port->valueint >= 1 && web_port->valueint <= 65535)
        {
            g_web_port = (uint16_t)web_port->valueint;
        }
        else
        {
            LOG_WARN("web_port 参数不正确 (应为 1 - 65535), 使用默认参数 (%d)", DEFAULT_WEB_PORT);
        }
    }
    else
    {
        LOG_DEBUG("web_port 参数不存在, 使用默认参数 (%d)", DEFAULT_WEB_PORT);
    }

    const cJSON* web_external_acc = cJSON_GetObjectItem(cfg_json, "web_external_acc");
    if (web_external_acc)
    {
        if (cJSON_IsBool(web_external_acc))
        {
            g_web_external_acc = cJSON_IsTrue(web_external_acc);
        }
        else
        {
            LOG_WARN("web_external_acc 参数不正确 (应为 true / false), 使用默认参数 (关闭)");
        }
    }
    else
    {
        LOG_DEBUG("web_external_acc 参数不存在, 使用默认参数 (关闭)");
    }

    const cJSON* accounts = cJSON_GetObjectItem(cfg_json, "accounts");
    if (accounts == NULL || cJSON_IsArray(accounts) == false || cJSON_GetArraySize(accounts) == 0)
    {
        LOG_FATAL("没有找到账号数据, 请添加后重启程序");
        cJSON_Delete(cfg_json);
        cfg_halt();
        return false;
    }

    const uint8_t cnt = cJSON_GetArraySize(accounts);

    int8_t valid_cnt = 0;

    /* 没有可用账号时, 是否已经用文件里的字段把默认值填过一遍 */
    bool defaults_filled = false;

#ifdef __OPENWRT__
    if (g_prog_account != 0)
    {
        LOG_INFO("OpenWRT 环境, 本次仅使用配置 %" PRIu8, g_prog_account);
    }
    else
    {
        LOG_INFO("OpenWRT 环境, 会尝试加载所有有效配置");
    }

    prog_status_t* new_prog_status = realloc(g_prog_status, sizeof(prog_status_t) * cnt);
    if (new_prog_status)
    {
        g_prog_status = new_prog_status;
        memset(g_prog_status, 0, sizeof(prog_status_t) * cnt);
    }
    else
    {
        LOG_FATAL("重分配内存失败");
        return false;
    }

    bool use_cus_mark = false;

    for (uint8_t i = 0, valid_i = 0; i < cnt; i++)
    {
        const cJSON* account = cJSON_GetArrayItem(accounts, i);

        const cJSON* usr = cJSON_GetObjectItem(account, "username");
        const cJSON* pwd = cJSON_GetObjectItem(account, "password");
        const cJSON* chn = cJSON_GetObjectItem(account, "channel");
        const cJSON* mark = cJSON_GetObjectItem(account, "mark");
        const cJSON* time_windows_item = cJSON_GetObjectItem(account, "time_windows");

        // 检查账号
        if (usr == NULL)
        {
            LOG_WARN("配置 %" PRIu8 " username 参数不存在, 跳过当前配置", i + 1);
            continue;
        }
        if (usr->valuestring[0] == '\0')
        {
            LOG_WARN("配置 %" PRIu8 " username 参数为空, 跳过当前配置", i + 1);
            continue;
        }

        // 检查密码
        if (pwd == NULL)
        {
            LOG_WARN("配置 %" PRIu8 " password 参数不存在, 跳过当前配置", i + 1);
            continue;
        }
        if (pwd->valuestring[0] == '\0')
        {
            LOG_WARN("配置 %" PRIu8 " password 参数为空, 跳过当前配置", i + 1);
            continue;
        }

        // 检查时间控制字段
        if (apply_time_windows(time_windows_item, &g_prog_status[valid_i].login_cfg) == false)
        {
            LOG_FATAL("配置 %" PRIu8 " time_windows 非法, 应为 [{ \"start\": \"mon 08:13\", \"end\": \"mon 23:57\" }, ...]", i + 1);
            cJSON_Delete(cfg_json);
            return false;
        }

        snprintf(g_prog_status[valid_i].login_cfg.usr, USR_LEN, "%s", safe_str(usr->valuestring));
        snprintf(g_prog_status[valid_i].login_cfg.pwd, PWD_LEN, "%s", safe_str(pwd->valuestring));

        g_prog_status[valid_i].login_cfg.chn = parse_channel_json(chn, i + 1);
        apply_channel_ua(&g_prog_status[valid_i].login_cfg, i + 1);
        apply_province_json(&g_prog_status[valid_i].login_cfg, account, i + 1);

        LOG_DEBUG("使用 UA: %s", g_prog_status[valid_i].login_cfg.user_agent);
        LOG_DEBUG("当前使用下标: %" PRIu8, valid_i);

        // 检查标记值
        if (mark == NULL)
        {
            if (use_cus_mark)
            {
                LOG_WARN("其它配置使用了自定义标记值, 但配置 %" PRIu8 " 未填写, 将跳过该配置", i + 1);
                continue;
            }
            g_prog_status[valid_i].login_cfg.mark = 0x100 + valid_i * 0x100;
            LOG_DEBUG("使用自动标记值: %" PRIu32 " (0x%x)", g_prog_status[valid_i].login_cfg.mark, g_prog_status[valid_i].login_cfg.mark);
            LOG_DEBUG("当前使用下标: %" PRIu8, valid_i);
        }
        else
        {
            if (use_cus_mark && mark->valuestring[0] == '\0')
            {
                LOG_WARN("其它配置使用了自定义标记值, 但配置 %" PRIu8 " 未填写, 将跳过该配置", i + 1);
                continue;
            }
            if (mark->valuestring[0] != '\0')
            {
                g_prog_status[valid_i].login_cfg.mark = strtoul(mark->valuestring, NULL, 16);
                g_prog_status[valid_i].login_cfg.use_cus_mark = true;
                use_cus_mark = true;
                LOG_DEBUG("使用自定义标记值: %" PRIu32 " (0x%x)", g_prog_status[valid_i].login_cfg.mark, g_prog_status[valid_i].login_cfg.mark);
                LOG_DEBUG("当前使用下标: %" PRIu8, valid_i);
            }
            else
            {
                g_prog_status[valid_i].login_cfg.mark = 0x100 + valid_i * 0x100;
                LOG_DEBUG("使用自动标记值: %" PRIu32 " (0x%x)", g_prog_status[valid_i].login_cfg.mark, g_prog_status[valid_i].login_cfg.mark);
                LOG_DEBUG("当前使用下标: %" PRIu8, valid_i);
            }
        }

        // g_prog_status[valid_i].login_cfg.auto_start = auto_start->valueint;

        g_prog_status[valid_i].login_cfg.idx = i + 1;
        LOG_INFO("配置 %" PRIu8 " 可用, 将会尝试使用", i + 1);
        valid_cnt++;
        valid_i++;
    }

#else

    if (g_prog_account != 0)
    {
        LOG_INFO("非 OpenWRT 环境, 将尝试加载配置 %" PRIu8, g_prog_account);
    }
    else
    {
        LOG_INFO("非 OpenWRT 环境, 仅会尝试加载第一个有效配置");
    }

    for (uint8_t i = 0; i < cnt; i++)
    {
        /**
         * 指定了 --account 时只加载对应序号的配置,
         * 未指定时保持原有行为 (取第一个有效配置)
         */
        if (g_prog_account != 0 && i + 1 != g_prog_account)
        {
            continue;
        }

        const cJSON* account = cJSON_GetArrayItem(accounts, i);

        const cJSON* usr = cJSON_GetObjectItem(account, "username");
        const cJSON* pwd = cJSON_GetObjectItem(account, "password");
        const cJSON* chn = cJSON_GetObjectItem(account, "channel");
        const cJSON* time_windows_item = cJSON_GetObjectItem(account, "time_windows");

        // 检查账号
        if (usr == NULL)
        {
            LOG_WARN("配置 %" PRIu8 " username 参数不存在, 跳过当前配置", i + 1);
            continue;
        }
        if (usr->valuestring[0] == '\0')
        {
            LOG_WARN("配置 %" PRIu8 " username 参数为空, 跳过当前配置", i + 1);
            continue;
        }

        // 检查密码
        if (pwd == NULL)
        {
            LOG_WARN("配置 %" PRIu8 " password 参数不存在, 跳过当前配置", i + 1);
            continue;
        }
        if (pwd->valuestring[0] == '\0')
        {
            LOG_WARN("配置 %" PRIu8 " password 参数为空, 跳过当前配置", i + 1);
            continue;
        }

        // 检查时间控制字段
        if (apply_time_windows(time_windows_item, &g_prog_status[0].login_cfg) == false)
        {
            LOG_FATAL("配置 %" PRIu8 " time_windows 非法, 应为 [{ \"start\": \"mon 08:13\", \"end\": \"mon 23:57\" }, ...]", i + 1);
            cJSON_Delete(cfg_json);
            return false;
        }

        snprintf(g_prog_status[0].login_cfg.usr, USR_LEN, "%s", safe_str(usr->valuestring));
        snprintf(g_prog_status[0].login_cfg.pwd, PWD_LEN, "%s", safe_str(pwd->valuestring));

        g_prog_status[0].login_cfg.chn = parse_channel_json(chn, i + 1);
        apply_channel_ua(&g_prog_status[0].login_cfg, i + 1);
        apply_province_json(&g_prog_status[0].login_cfg, account, i + 1);

        LOG_DEBUG("使用 UA: %s", g_prog_status[0].login_cfg.user_agent);
        LOG_DEBUG("当前使用下标: 0");

        // 记真实序号: 首个配置可能不可用而被跳过, 写死 1 会让日志报错配置号
        g_prog_status[0].login_cfg.idx = i + 1;
        LOG_INFO("配置 %" PRIu8 " 可用, 将会尝试使用", i + 1);
        valid_cnt++;
        break;
    }

    if (valid_cnt == 0)
    {
        /**
         * 一个可用账号都没有 (首次运行就是这个情况: username / password 都是空的)。
         * 以前这里是致命错误, 于是"第一次双击"永远进不到网页界面。
         * 现在改成: 用第一份账号里已经填过的省份 / 门户把表单撑起来, 继续往下走,
         * 由网页界面负责让用户把账号填完。
         */
        LOG_WARN("配置里还没有填账号 (username / password 为空)");

        fill_default_login_cfg(cJSON_GetArrayItem(accounts, 0));
        defaults_filled = true;
    }

#endif

    /**
     * 必须在 `--account` 挑选**之前**记下来: 下面那段会把 valid_cnt 改成 1,
     * 而那个 1 是"挑中了一份配置"的意思, 不代表这份配置里有真账号。
     * 顺序反了的话, "--account 1 + 空账号" 会被当成已配置, 然后拿空用户名去认证。
     */
    const bool has_usable_account = (valid_cnt > 0);

    cJSON_Delete(cfg_json);

    /**
     * 指定了 --account 时只保留该序号的配置
     *
     * 挑选必须放在全部配置加载完成之后:
     * 自动标记值是按"可用配置"的顺序算出来的 (0x100 + valid_i * 0x100),
     * 若在遍历时就跳过其它配置, valid_i 会从头计数, 标记值就会全部错位
     */
    if (g_prog_account != 0)
    {
        int8_t pick = -1;
        for (uint8_t i = 0; i < valid_cnt; i++)
        {
            if (g_prog_status[i].login_cfg.idx == g_prog_account)
            {
                pick = (int8_t)i;
                break;
            }
        }

        if (pick < 0)
        {
            LOG_FATAL("配置 %" PRIu8 " 不存在或该配置不可用, 请检查配置文件", g_prog_account);
            cfg_halt();
            return false;
        }

        if (pick != 0)
        {
            g_prog_status[0] = g_prog_status[pick];
        }

        valid_cnt = 1;

        // 单账号进程用不到其余配置的空间, 按实际情况回收
        prog_status_t* shrunk = realloc(g_prog_status, sizeof(prog_status_t));
        if (shrunk != NULL)
        {
            g_prog_status = shrunk;
        }

        LOG_INFO("仅加载配置 %" PRIu8 ", 标记值: 0x%x", g_prog_account, g_prog_status[0].login_cfg.mark);
    }

    /**
     * 一个可用账号都没有时**不再退出或挂起**。
     *
     * 以前这里直接返回失败, 于是"第一次双击"永远到不了网页界面 ——
     * 而网页界面才是唯一能让用户把账号填进去的地方 (用户不该被要求手工编辑 JSON)。
     *
     * 现在: 保证 g_prog_status[0] 有一份可显示的默认值, 程序继续跑,
     * 只是 g_cfg_ready 为假 → 主循环只开网页、不起认证线程。
     * 用户在网页上填完并「保存并应用」后, 这个标志就会翻成真。
     */
    if (!has_usable_account)
    {
        if (!defaults_filled)
        {
            /* OpenWrt 分支没有上面的兜底, 这里补一次 (拿不到账号就纯用内置默认) */
            fill_default_login_cfg(NULL);
        }

        LOG_WARN("还没有可用账号, 程序将只提供网页界面, 请在网页上填写账号与省份");
        valid_cnt = 1;
    }

    g_prog_cnt = valid_cnt;

    g_cfg_loaded = true;

    /* 只有"已启用 + 有可用账号"才允许进入认证流程 */
    g_cfg_ready = (has_usable_account && g_prog_enabled);

    if (!g_cfg_ready)
    {
        LOG_INFO("当前处于【待配置】状态 (enabled=%s, 账号=%s): 只启动网页界面, 不发起认证",
                 g_prog_enabled ? "true" : "false",
                 has_usable_account ? "已填" : "未填");
    }

    return true;
}
