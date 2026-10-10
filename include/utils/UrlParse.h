#ifndef ESURFINGCLIENT_URLPARSE_H
#define ESURFINGCLIENT_URLPARSE_H

/**
 * URL 解析 —— 从门户劫持的 302 Location 里取出主机与端口。
 *
 * 为什么单独一个头/源文件, 而不是并进 StrUtil.c:
 *   StrUtil.c 里的 extract_url_param() 会打日志, 链接时要把整套日志系统拖进来。
 *   湖南的离线自检 (hunan_selftest) 只编几个文件、不联网, 编不进日志系统。
 *   这里的函数是**纯函数** (无日志、无全局、无内存分配), 自检可以直接编它,
 *   于是真实的 Location 样本能进单元测试。
 *
 * 只支持**绝对** URL。相对地址 (以 '/' 开头) 返回 false, 由调用方自行回退 ——
 * 门户劫持给的是绝对地址, 而这个函数宁可不猜也不猜错。
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief 拆出绝对 URL 的主机与端口
 *
 * @param url      输入 URL, 例如 "http://175.12.104.1:10001/index.cgi?x=1"
 * @param host     输出主机 (IPv6 字面量保留方括号, curl 需要它), 失败时置空串
 * @param host_len 主机缓冲长度
 * @param port     输出端口; 缺省按 scheme 补 (http=80, https=443); 失败时置 0
 * @return 解析成功返回 true
 *
 * 失败的情形: url 为空、非 http(s) 绝对地址、主机为空或超长、端口非法。
 * 任何一项不合法都整体失败, 不返回"半个"结果。
 */
bool url_split_host_port(const char* url, char* host, size_t host_len, uint16_t* port);

/**
 * @brief 取出查询串里某个参数的值 (不复制、不分配)
 *
 * 与 StrUtil.c 的 extract_url_param() 的区别: 那个会打日志、返回 malloc 出来的
 * 字符串 (广东分支在用, 不要动); 这个是纯函数, 把值的起止位置指回 url 内部,
 * 因此没有长度上限, 也能被离线自检直接测。
 *
 * 比 extract_url_param() 严格: 只认"位于 '?' 之后或紧跟在 '&' 之后"的参数名,
 * 不会把 "xmscgip=" 里的 "mscgip=" 误当成目标参数。
 *
 * @param url      输入 URL
 * @param name     参数名 (不带 '=')
 * @param value    输出: 值的起点 (指向 url 内部; 调用方自己限长复制)
 * @param value_len 输出: 值的长度 (值可以为空, 此时返回 true)
 * @return 找到返回 true; url/name 为空或没找到返回 false
 */
bool url_find_query_value(const char* url, const char* name, const char** value, size_t* value_len);

#endif
