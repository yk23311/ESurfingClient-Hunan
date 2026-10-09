#include "hunan/HunanXml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HUNAN_XML_HEADER "<?xml version=\"1.0\" encoding=\"utf-8\"?><request>"
#define HUNAN_XML_FOOTER "</request>"

/* 各端点的字段顺序 —— 与官方抓包逐字节核对过, 不要随意重排。 */
static const char* const s_fields_ticket[] = {
    "ostag", "local-time", "gwip", "mac", "ipv6", "ipv4",
    "client-id", "user-agent", "host-name"
};
static const char* const s_fields_auth[] = {
    "local-time", "ticket", "passwd", "userid", "client-id", "user-agent"
};
static const char* const s_fields_state[] = {
    "local-time", "ticket", "client-id", "user-agent"
};
static const char* const s_fields_keep[] = {
    "local-time", "excheck-args", "mac", "ipv6", "ipv4",
    "ticket", "client-id", "user-agent"
};
static const char* const s_fields_term[] = {
    "reason", "local-time", "ticket", "client-id", "user-agent"
};

const char* hunan_endpoint_path(const hunan_endpoint_t ep)
{
    switch (ep)
    {
        case HUNAN_EP_TICKET: return "ticket.cgi";
        case HUNAN_EP_AUTH:   return "auth.cgi";
        case HUNAN_EP_STATE:  return "state.cgi";
        case HUNAN_EP_KEEP:   return "keep.cgi";
        case HUNAN_EP_TERM:   return "term.cgi";
        default:              return NULL;
    }
}

const char* const* hunan_endpoint_fields(const hunan_endpoint_t ep, size_t* count)
{
    switch (ep)
    {
        case HUNAN_EP_TICKET:
            if (count) *count = sizeof(s_fields_ticket) / sizeof(s_fields_ticket[0]);
            return s_fields_ticket;
        case HUNAN_EP_AUTH:
            if (count) *count = sizeof(s_fields_auth) / sizeof(s_fields_auth[0]);
            return s_fields_auth;
        case HUNAN_EP_STATE:
            if (count) *count = sizeof(s_fields_state) / sizeof(s_fields_state[0]);
            return s_fields_state;
        case HUNAN_EP_KEEP:
            if (count) *count = sizeof(s_fields_keep) / sizeof(s_fields_keep[0]);
            return s_fields_keep;
        case HUNAN_EP_TERM:
            if (count) *count = sizeof(s_fields_term) / sizeof(s_fields_term[0]);
            return s_fields_term;
        default:
            if (count) *count = 0;
            return NULL;
    }
}

char* hunan_build_xml(const hunan_field_t* fields, const size_t count)
{
    if (!fields && count) return NULL;

    /* 头部 + '\n' + 每个 <k>v</k> + '\n' + </request> + '\0' */
    size_t need = strlen(HUNAN_XML_HEADER) + 1 + strlen(HUNAN_XML_FOOTER) + 1;
    for (size_t i = 0; i < count; ++i)
    {
        const char* n = fields[i].name ? fields[i].name : "";
        const char* v = fields[i].value ? fields[i].value : "";
        need += strlen(n) * 2 + strlen(v) + 5 + 1; /* <n>v</n> + '\n' */
    }

    char* buf = (char*)malloc(need);
    if (!buf) return NULL;

    size_t off = 0;
    off += (size_t)sprintf(buf + off, "%s\n", HUNAN_XML_HEADER);
    for (size_t i = 0; i < count; ++i)
    {
        const char* n = fields[i].name ? fields[i].name : "";
        const char* v = fields[i].value ? fields[i].value : "";
        off += (size_t)sprintf(buf + off, "<%s>%s</%s>\n", n, v, n);
    }
    off += (size_t)sprintf(buf + off, "%s", HUNAN_XML_FOOTER);
    buf[off] = '\0';
    return buf;
}

char* hunan_build_xml_for(const hunan_endpoint_t ep, const char* const* values)
{
    size_t count = 0;
    const char* const* names = hunan_endpoint_fields(ep, &count);
    if (!names || !values) return NULL;

    hunan_field_t* fields = (hunan_field_t*)malloc(sizeof(hunan_field_t) * count);
    if (!fields) return NULL;
    for (size_t i = 0; i < count; ++i)
    {
        fields[i].name = names[i];
        fields[i].value = values[i] ? values[i] : "";
    }
    char* out = hunan_build_xml(fields, count);
    free(fields);
    return out;
}
