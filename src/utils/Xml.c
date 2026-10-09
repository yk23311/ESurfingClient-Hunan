#include "utils/PlatformUtils.h"

#include "states/States.h"

#include "utils/Logger.h"

#include "hunan/Hunan.h"
#include "hunan/HunanXml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* xml_parser(const char* xml_data, const char* tag)
{
    if (xml_data == NULL || tag == NULL) return NULL;

    char start_tag[256];
    snprintf(start_tag, sizeof(start_tag), "<%s>", tag);

    char end_tag[256];
    snprintf(end_tag, sizeof(end_tag), "</%s>", tag);

    const char* start_pos = strstr(xml_data, start_tag);
    if (!start_pos) return NULL;
    start_pos += strlen(start_tag);

    const char* end_pos = strstr(start_pos, end_tag);
    if (!end_pos) return NULL;

    const size_t content_length = end_pos - start_pos;
    if (content_length <= 0) return NULL;

    char* content = malloc(content_length + 1);
    if (!content) return NULL;

    strncpy(content, start_pos, content_length);
    content[content_length] = '\0';
    return content;
}

/* ---------------------------------------------------------------- 湖南 */

/**
 * 湖南报文的字段取值。
 *
 * 注意 local-time: 湖南**不用**真实时间戳 (广东才用 cur_tm),
 * 而是那个 9 字符的占位值 —— 实测五个端点用 00000000k 全部通过。
 */
static const char* hunan_field_value(const char* name)
{
    login_cfg_t* lc = &g_prog_status[tl_thread_idx].login_cfg;
    auth_cfg_t* ac = &g_prog_status[tl_thread_idx].auth_cfg;

    if (strcmp(name, "ostag") == 0)        return HUNAN_OSTAG;
    if (strcmp(name, "local-time") == 0)   return HUNAN_LOCAL_TIME;
    if (strcmp(name, "gwip") == 0)         return safe_str(ac->ac_ip);
    if (strcmp(name, "mac") == 0)          return safe_str(ac->mac_addr);
    if (strcmp(name, "ipv6") == 0)         return "";
    if (strcmp(name, "ipv4") == 0)         return safe_str(ac->client_ip);
    if (strcmp(name, "client-id") == 0)    return safe_str(ac->client_id);
    if (strcmp(name, "user-agent") == 0)   return safe_str(lc->user_agent);
    if (strcmp(name, "host-name") == 0)    return safe_str(ac->host_name);
    if (strcmp(name, "excheck-args") == 0) return HUNAN_EXCHECK_ARGS;
    if (strcmp(name, "ticket") == 0)       return safe_str(ac->ticket);
    if (strcmp(name, "passwd") == 0)       return safe_str(lc->pwd);
    if (strcmp(name, "userid") == 0)       return safe_str(lc->usr);
    if (strcmp(name, "reason") == 0)       return HUNAN_TERM_REASON;
    LOG_WARN("湖南报文出现未知字段 <%s>, 按空值处理", name);
    return "";
}

static char* create_hunan_xml(const hunan_endpoint_t ep)
{
    /* 返回静态缓冲区: 调用方 (DialerTicket/DialerNet) 不负责 free,
     * 与广东那条路径的语义保持一致 */
    static char hunan_xml[XML_BUFFER_SIZE];

    size_t count = 0;
    const char* const* names = hunan_endpoint_fields(ep, &count);
    if (!names || count == 0)
    {
        LOG_ERROR("湖南端点字段表为空");
        return NULL;
    }

    const char** values = calloc(count, sizeof(char*));
    if (!values)
    {
        LOG_ERROR("分配内存失败");
        return NULL;
    }
    for (size_t i = 0; i < count; ++i) values[i] = hunan_field_value(names[i]);

    char* built = hunan_build_xml_for(ep, values);
    free(values);
    if (!built)
    {
        LOG_ERROR("拼湖南报文失败");
        return NULL;
    }
    const size_t len = strlen(built);
    if (len + 1 > XML_BUFFER_SIZE)
    {
        LOG_ERROR("湖南报文过长 (%zu 字节, 缓冲区 %d)", len + 1, XML_BUFFER_SIZE);
        free(built);
        return NULL;
    }
    memcpy(hunan_xml, built, len + 1);
    free(built);

    LOG_DEBUG("湖南报文 (%s, %zu 字节):\n%s", hunan_endpoint_path(ep), len, hunan_xml);
    return hunan_xml;
}

char* create_xml_payload(const XmlChoose choose)
{
    /* ---- 省份分流: 湖南是另一套方言 ---- */
    if (g_prog_status[tl_thread_idx].login_cfg.province == PROVINCE_HUNAN)
    {
        switch (choose)
        {
        case GET_TICKET:  return create_hunan_xml(HUNAN_EP_TICKET);
        case LOGIN:       return create_hunan_xml(HUNAN_EP_AUTH);
        case HEART_BEAT:  return create_hunan_xml(HUNAN_EP_KEEP);
        case TERM:        return create_hunan_xml(HUNAN_EP_TERM);
        default:
            LOG_ERROR("湖南不支持的 XML 选择代码: %d", choose);
            return NULL;
        }
    }

    char cur_tm[32];
    get_fmt_time(cur_tm, CONSOLE_FORMAT);
    static char xml[XML_BUFFER_SIZE] = "";
    LOG_DEBUG("XML 选择代码: %d", choose);
    uint16_t xml_len = 0;
    switch (choose)
    {
    case GET_TICKET:
        xml_len = snprintf(xml, XML_BUFFER_SIZE,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<request>\n"
            "    <user-agent>%s</user-agent>\n"
            "    <client-id>%s</client-id>\n"
            "    <local-time>%s</local-time>\n"
            "    <host-name>%s</host-name>\n"
            "    <ipv4>%s</ipv4>\n"
            "    <ipv6></ipv6>\n"
            "    <mac>%s</mac>\n"
            "    <ostag>%s</ostag>\n"
            "    <gwip>%s</gwip>\n"
            "</request>\n",
            safe_str(g_prog_status[tl_thread_idx].login_cfg.user_agent),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.client_id),
            safe_str(cur_tm),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.host_name),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.client_ip),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.mac_addr),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.ostag),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.ac_ip)
        );
        break;
    case LOGIN:
        xml_len = snprintf(xml, XML_BUFFER_SIZE,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<request>\n"
            "    <user-agent>%s</user-agent>\n"
            "    <client-id>%s</client-id>\n"
            "    <ticket>%s</ticket>\n"
            "    <local-time>%s</local-time>\n"
            "    <userid>%s</userid>\n"
            "    <passwd>%s</passwd>\n"
            "</request>\n",
            safe_str(g_prog_status[tl_thread_idx].login_cfg.user_agent),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.client_id),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.ticket),
            safe_str(cur_tm),
            safe_str(g_prog_status[tl_thread_idx].login_cfg.usr),
            safe_str(g_prog_status[tl_thread_idx].login_cfg.pwd)
        );
        break;
    case HEART_BEAT:
    case TERM:
        xml_len = snprintf(xml, XML_BUFFER_SIZE,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<request>\n"
            "    <user-agent>%s</user-agent>\n"
            "    <client-id>%s</client-id>\n"
            "    <local-time>%s</local-time>\n"
            "    <host-name>%s</host-name>\n"
            "    <ipv4>%s</ipv4>\n"
            "    <ticket>%s</ticket>\n"
            "    <ipv6></ipv6>\n"
            "    <mac>%s</mac>\n"
            "    <ostag>%s</ostag>\n"
            "</request>\n",
            safe_str(g_prog_status[tl_thread_idx].login_cfg.user_agent),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.client_id),
            safe_str(cur_tm),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.host_name),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.client_ip),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.ticket),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.mac_addr),
            safe_str(g_prog_status[tl_thread_idx].auth_cfg.ostag)
        );
        break;
    default:
        LOG_ERROR("XML 选择代码错误");
        return NULL;
    }
    if (xml_len <= 0)
    {
        LOG_ERROR("XML 创建失败");
        return NULL;
    }
    if (xml_len >= XML_BUFFER_SIZE)
    {
        LOG_ERROR("XML 内容过长 (需要 %d 字节，但缓冲区只有 %d 字节)", xml_len + 1, XML_BUFFER_SIZE);
        return NULL;
    }
    LOG_DEBUG("创建 XML 完成");
    if (choose != LOGIN)
    {
        LOG_DEBUG("XML 内容为:\n%s", xml);
    }
    return xml;
}

char* extract_between_tags(const char* text, const char* start_tag, const char* end_tag)
{
    if (!text)
    {
        LOG_ERROR("传入文本为空");
        return NULL;
    }
    char* start = strstr(text, start_tag);
    if (!start)
    {
        LOG_ERROR("未找到开头标签: %s", start_tag);
        return NULL;
    }
    start += strlen(start_tag);
    char* end = strstr(start, end_tag);
    if (!end)
    {
        LOG_WARN("未找到结尾标签: %s, 返回", end_tag);
        return NULL;
    }
    const size_t len = end - start;
    if (len == 0) LOG_WARN("提取到空内容 (标签: %s...%s)", start_tag, end_tag);
    char* result = malloc(len + 1);
    if (!result)
    {
        LOG_ERROR("分配内存失败");
        return NULL;
    }
    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}

char* clean_CDATA(const char* text)
{
    return extract_between_tags(text, "<![CDATA[", "]]>");
}
