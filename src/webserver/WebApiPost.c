#include "webserver/WebInternal.h"

#include <minihttp/minihttp.h>

#include "config/Config.h"

#include "control/Control.h"

#include "states/States.h"

#include "utils/Logger.h"

#include <cJSON/cJSON.h>

/**
 * @brief 请求重新认证
 * @return 是否成功
 */
static bool request_restart_auth()
{
    if (s_local_state)
    {
        if (g_prog_status == NULL || g_prog_cnt <= 0) return false;
        g_prog_status[0].runtime_status.is_need_reauth = true;
        return true;
    }

    return control_restart_auth();
}

/**
 * @brief 请求重新加载配置并重新认证
 * @return 是否成功
 */
static bool request_apply_config()
{
    if (s_local_state)
    {
        if (g_prog_status == NULL || g_prog_cnt <= 0) return false;
        g_cfg_loaded = false;
        g_prog_status[0].runtime_status.is_need_reauth = true;
        return true;
    }

    return control_apply_config();
}

/**
 * @brief 请求断开连接 (登出并停止自动重连)
 * @return 是否成功
 */
static bool request_disconnect()
{
    if (s_local_state)
    {
        if (g_prog_status == NULL || g_prog_cnt <= 0) return false;
        g_prog_status[0].runtime_status.is_manual_offline = true;
        g_prog_status[0].runtime_status.is_need_reauth = true;
        return true;
    }

    return control_disconnect();
}

/**
 * @brief 请求重新连接 (解除断开状态)
 * @return 是否成功
 */
static bool request_connect()
{
    if (s_local_state)
    {
        if (g_prog_status == NULL || g_prog_cnt <= 0) return false;
        g_prog_status[0].runtime_status.is_manual_offline = false;
        return true;
    }

    return control_connect();
}

/**
 * @brief 处理 POST API 请求
 * @return 是否已处理
 */
bool handle_api_post(struct mg_connection* c, struct mg_http_message* hm)
{
    // 从 Web 线程读取请求体
    char* data = NULL;
    if (hm->body.len > 0)
    {
        data = malloc(hm->body.len + 1);
        if (data == NULL)
        {
            mg_http_reply(c, 500, "", "");
            return true;
        }
        memcpy(data, hm->body.buf, hm->body.len);
        data[hm->body.len] = '\0';
    }

    // 仅保存
    if (mg_match(hm->uri, mg_str("/api/saveConfigs"), NULL))
    {
        if (data == NULL)
        {
            mg_http_reply(c, 400, "", "");
            return true;
        }
        if (save_cfg(data))
        {
            mg_http_reply(c, 204, "", "");
        }
        else
        {
            mg_http_reply(c, 500, "", "");
        }
        free(data);
        return true;
    }

    // 仅应用
    if (mg_match(hm->uri, mg_str("/api/applyConfigs"), NULL))
    {
        if (data == NULL)
        {
            mg_http_reply(c, 400, "", "");
            return true;
        }

        cJSON* operation_json = cJSON_Parse(data);
        if (operation_json == NULL)
        {
            mg_http_reply(c, 500, "", "");
            free(data);
            return true;
        }

        const cJSON* apply = cJSON_GetObjectItem(operation_json, "apply");
        if (apply)
        {
            if (cJSON_IsBool(apply))
            {
                if (g_prog_status == NULL)
                {
                    LOG_WARN("收到 Web 应用配置文件请求, 但程序尚未加载完成, 拒绝操作");
                    mg_http_reply(c, 403, "", "");
                }
                else
                {
                    bool is_authed = false;
                    const bool reachable = query_is_authed(&is_authed);

                    if (reachable == false)
                    {
                        LOG_WARN("收到 Web 应用配置文件请求, 但认证进程不可达");
                        mg_http_reply(c, 503, "", "");
                    }
                    else if (is_authed == false)
                    {
                        LOG_WARN("收到 Web 应用配置文件请求, 但没有线程在认证, 拒绝操作");
                        mg_http_reply(c, 403, "", "");
                    }
                    else if (request_apply_config() == false)
                    {
                        LOG_WARN("收到 Web 应用配置文件请求, 但下发到认证进程失败");
                        mg_http_reply(c, 503, "", "");
                    }
                    else
                    {
                        LOG_INFO("收到 Web 应用配置文件请求, 程序将重新加载配置文件并进行认证");
                        mg_http_reply(c, 204, "", "");
                    }
                }
            }
            else
            {
                mg_http_reply(c, 500, "", "");
            }
        }
        else
        {
            mg_http_reply(c, 500, "", "");
        }

        free(data);
        cJSON_Delete(operation_json);
        return true;
    }

    // 重新认证
    if (mg_match(hm->uri, mg_str("/api/restartAuth"), NULL))
    {
        if (g_prog_status == NULL || g_cfg_loaded == false)
        {
            LOG_WARN("收到 Web 重新认证请求, 但程序尚未加载配置, 拒绝操作");
            mg_http_reply(c, 503, "", "");
        }
        else
        {
            bool is_authed = false;
            const bool reachable = query_is_authed(&is_authed);

            if (reachable == false)
            {
                LOG_WARN("收到 Web 重新认证请求, 但认证进程不可达");
                mg_http_reply(c, 503, "", "");
            }
            else if (is_authed == false)
            {
                LOG_WARN("收到 Web 重新认证请求, 但没有线程在认证, 拒绝操作");
                mg_http_reply(c, 403, "", "");
            }
            else if (request_restart_auth() == false)
            {
                LOG_WARN("收到 Web 重新认证请求, 但下发到认证进程失败");
                mg_http_reply(c, 503, "", "");
            }
            else
            {
                LOG_INFO("收到 Web 重新认证请求, 认证线程将重新进行认证");
                mg_http_reply(c, 204, "", "");
            }
        }

        free(data);
        return true;
    }

    // 断开连接 / 重新连接
    if (mg_match(hm->uri, mg_str("/api/disconnect"), NULL) ||
        mg_match(hm->uri, mg_str("/api/connect"), NULL))
    {
        const bool want_offline = mg_match(hm->uri, mg_str("/api/disconnect"), NULL);

        if (g_prog_status == NULL || g_cfg_loaded == false)
        {
            LOG_WARN("收到 Web %s请求, 但程序尚未加载配置, 拒绝操作",
                     want_offline ? "断开连接" : "连接");
            mg_http_reply(c, 503, "", "");
        }
        else
        {
            bool offline = false;

            /**
             * 不要求"当前已认证": 断开还有一个真实用途是**喊停重试** ——
             * 账号密码错时认证线程会按 1/5/10/20/30 分钟的退避一直重试,
             * 用户要能把它停下来。那种状态下 is_authed 本来就是假。
             */
            if (query_is_manual_offline(&offline) == false)
            {
                LOG_WARN("收到 Web %s请求, 但认证进程不可达",
                         want_offline ? "断开连接" : "连接");
                mg_http_reply(c, 503, "", "");
            }
            else if (offline == want_offline)
            {
                // 已经是目标状态: 幂等返回, 不当作错误
                mg_http_reply(c, 204, "", "");
            }
            else if ((want_offline ? request_disconnect() : request_connect()) == false)
            {
                LOG_WARN("收到 Web %s请求, 但下发到认证进程失败",
                         want_offline ? "断开连接" : "连接");
                mg_http_reply(c, 503, "", "");
            }
            else
            {
                if (want_offline)
                    LOG_INFO("收到 Web 断开连接请求, 将登出并停止自动重连");
                else
                    LOG_INFO("收到 Web 连接请求, 将重新认证");

                mg_http_reply(c, 204, "", "");
            }
        }

        free(data);
        return true;
    }

    free(data);

    // 未知的 POST 路径
    mg_http_reply(c, 404, HEADER_TEXT, "Not found\n");
    return true;
}
