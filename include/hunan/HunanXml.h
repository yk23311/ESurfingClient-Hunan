#ifndef ESURFINGCLIENT_HUNANXML_H
#define ESURFINGCLIENT_HUNANXML_H

#include <stddef.h>

/**
 * 湖南天翼校园门户的请求报文格式。
 *
 * 与广东版 (PlatformUtils.c 的 create_xml_payload) 是**同一套字段名、不同的方言**:
 *   - 广东: 元素之间无换行, 字段顺序按端点各自定义, <ipv6> 恒为空;
 *   - 湖南: 每个元素后跟一个 '\n', </request> 之后**没有**换行, 且:
 *       · keep 用 <excheck-args> 占位, 没有 <host-name>/<ostag>;
 *       · term 用 <reason>, 结构比广东简单得多;
 *       · state.cgi 是湖南特有的端点, 广东没有对应实现。
 *
 * 精确格式 (来自 C:\temp\zx\extracted 的 32 份官方抓包, 逐字节核对):
 *
 *     <?xml version="1.0" encoding="utf-8"?><request>\n
 *     <name1>value1</name1>\n
 *     ...
 *     <nameN>valueN</nameN>\n
 *     </request>
 *
 * 即: 头部 + '\n', 然后每个元素 + '\n', 最后 </request> 收尾且不带换行。
 */

typedef struct
{
    const char* name;
    const char* value;
} hunan_field_t;

/** 湖南端点标识 */
typedef enum
{
    HUNAN_EP_TICKET = 0,
    HUNAN_EP_AUTH,
    HUNAN_EP_STATE,
    HUNAN_EP_KEEP,
    HUNAN_EP_TERM,
    HUNAN_EP_COUNT
} hunan_endpoint_t;

/** 端点对应的 `.cgi` 名字 (不含前导 '/') */
const char* hunan_endpoint_path(hunan_endpoint_t ep);

/** 端点对应的字段名顺序表; *count 写入字段个数。顺序即为官方线上的顺序。 */
const char* const* hunan_endpoint_fields(hunan_endpoint_t ep, size_t* count);

/**
 * 按官方格式拼报文。
 * @param fields 字段数组, 顺序即输出顺序
 * @param count  字段个数
 * @return 新分配的 NUL 结尾字符串 (不含结尾换行), 失败返回 NULL; 调用方负责 free()
 */
char* hunan_build_xml(const hunan_field_t* fields, size_t count);

/**
 * 便捷入口: 按端点规定的字段顺序拼报文。
 * @param values 与 hunan_endpoint_fields(ep) 一一对应的值数组 (个数必须匹配)
 */
char* hunan_build_xml_for(hunan_endpoint_t ep, const char* const* values);

#endif
