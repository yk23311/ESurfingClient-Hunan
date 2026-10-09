#ifndef ESURFINGCLIENT_HUNAN_H
#define ESURFINGCLIENT_HUNAN_H

/**
 * 湖南天翼校园的固定参数。
 *
 * 与广东最大的不同: 湖南**不做算法协商**。门户不下发 ZSM, Algo-ID 由客户端定死,
 * 密钥在本地 (见 KeyData.c 的 FAB1DCDE 那一档)。
 *
 * 下面这些值全部来自真实抓包与实测 (见 路线B-进展.md):
 *   32 份官方样本逐字节核对, 以及 2026-10-09 对真实门户的联网实测,
 *   五个端点 (ticket/auth/state/keep/term) 均返回 Error-Code=0。
 */

#define HUNAN_ALGO_ID   "FAB1DCDE-2D24-41CD-8510-2416DC7854CF"

/* 官方客户端用的 UA, 与广东各档都不同 (广东是 WinSVR5/1068 等) */
#define HUNAN_UA        "CCTP/WinSVR3/1052"

/* 注意: **结尾有一个空格**。官方抓包如此, 别顺手 strip 掉 */
#define HUNAN_OSTAG     "Windows 11(26300),64 bit "

/* 官方客户端用的是固定值, 不是随机 UUID (广东是随机生成) */
#define HUNAN_CLIENT_ID "c167f455-7b9f-4c0f-a401-df583ab269e2"

/**
 * local-time 是 9 字符的怪东西, 官方抓包里出现过 j/k/l/m 和 013/014。
 * 生成规则尚未破解 —— 但实测用固定值 00000000k 打**全部五个端点**
 * 服务端都收 (Error-Code=0), 所以先固定。
 */
#define HUNAN_LOCAL_TIME "00000000k"

/* keep.cgi 的占位参数。官方是 <hello>57854</hello><conn>56487</conn>,
 * 实测用 1/1 服务端也收, 且不校验长度。 */
#define HUNAN_EXCHECK_ARGS "<hello>1</hello><conn>1</conn>"

/* term.cgi 的 reason, 官方样本为 1 */
#define HUNAN_TERM_REASON "1"

#define HUNAN_DEFAULT_PORTAL "175.12.104.1"
#define HUNAN_DEFAULT_PORT   10001

#endif
