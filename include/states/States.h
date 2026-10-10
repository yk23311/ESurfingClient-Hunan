#ifndef ESURFINGCLIENT_STATES_H
#define ESURFINGCLIENT_STATES_H

#include "cipher/CipherInterface.h"

#include "utils/sim/SimThread.h"

#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>

#define SCHOOL_NETWORK_SYMBOL 8

#define TICKET_URL_LEN 512
#define USER_AGENT_LEN 32
#define CLIENT_ID_LEN 40
#define HOST_NAME_LEN 32
#define KEEP_URL_LEN 256
#define TERM_URL_LEN 256
#define AUTH_URL_LEN 256
#define MAC_ADDR_LEN 20
#define TICKET_LEN 40
#define OSTAG_LEN 32

#define USR_LEN 16
#define PWD_LEN 128

#define WEEK_MINUTES 10080
#define MAX_TIME_WINDOWS 16
#define TIME_WINDOW_STR_LEN 32

#define IP_LEN 16
#define IF_LEN 16

#define LOCATION_LEN 512
#define LAST_LOCATION_LEN 1024

/**
 * 门户地址提示 (BAS 注入的 302 Location) 的缓冲长度。
 * 实测那条 URL 约 110 字节, 128 够用; 超长会在快照处被截断并记一条 WARN。
 */
#define PORTAL_HINT_LEN 128

#define CONTROL_TOKEN_LEN 33

#define CONTROL_TOKEN_ENV "ESURFING_CONTROL_TOKEN"

#define DEFAULT_CONN_TIMEOUT 7

#define DEFAULT_OP_TIMEOUT 10

#define DEFAULT_CHANNEL 3

#define DEFAULT_WEB_PORT 8888

#define DEFAULT_WEB_EXTERNAL_ACC false

/* ---- 省份 ---- */
#define PROVINCE_GUANGDONG 0
#define PROVINCE_HUNAN     1
#define DEFAULT_PROVINCE   PROVINCE_GUANGDONG

typedef enum
{
    GET_TICKET = 1,
    LOGIN = 2,
    HEART_BEAT = 3,
    TERM = 4
} XmlChoose;

typedef enum
{
    CONSOLE_FORMAT = 1,
    FILE_FORMAT = 2
} TimeFormat;

typedef struct
{
    uint8_t* data;
    size_t len;
} bytes_t;

typedef enum
{
    ROLE_STANDALONE = 0,
    ROLE_SUPERVISOR = 1,
    ROLE_AUTH = 2,
    ROLE_WEB = 3
} prog_role_t;

typedef struct
{
    char ticket_url[TICKET_URL_LEN];
    char client_id[CLIENT_ID_LEN];
    char host_name[HOST_NAME_LEN];
    char ostag[OSTAG_LEN];
    char keep_url[KEEP_URL_LEN];
    char term_url[TERM_URL_LEN];
    char auth_url[AUTH_URL_LEN];
    char mac_addr[MAC_ADDR_LEN];
    char algo_id[ALGO_ID_LEN];
    char ticket[TICKET_LEN];
    char client_ip[IP_LEN];
    char ac_ip[IP_LEN];
    bool dynamic;
    cipher_interface_t* cipher;
    ios_zsm_blob_t blob;
    uint64_t keep_retry;
    uint64_t auth_time;
    uint64_t tick;
    int8_t type;
} auth_cfg_t;

typedef struct
{
    uint16_t start_week_min;
    uint16_t end_week_min;
} time_window_t;

typedef struct
{
    char usr[USR_LEN];
    char pwd[PWD_LEN];
    uint8_t chn;
    char user_agent[USER_AGENT_LEN];
    uint32_t mark;
    bool use_cus_mark;
    /* ---- 省份适配 ---- */
    uint8_t province;      /* PROVINCE_* */
    char portal[64];       /* 湖南用: 门户 IP (广东靠门户页发现, 用不到) */
    uint16_t portal_port;  /* 湖南用: 门户端口 */
    char mscgip[IP_LEN];   /* 湖南用: 接入设备地址, 拼进查询串 */
    time_window_t time_windows[MAX_TIME_WINDOWS];
    uint8_t time_window_count;
    bool has_time_control;
    uint8_t idx;
} login_cfg_t;

typedef struct
{
    bool is_initialized;
    bool is_running;
    bool is_authed;
    bool is_need_reauth;
    bool is_time_disabled;

    /**
     * 用户主动断开 (Web 端「断开连接」)。
     *
     * 语义是"登出之后不要自动重连", 直到用户点「连接」:
     *   · 置上时同时置 is_need_reauth → 认证线程退出循环 → clean() 里跑 term() 登出
     *   · clean() 会 memset 整个 runtime_status, 所以这个标志必须像 is_time_disabled
     *     一样被显式保存/恢复, 否则线程守护会立刻把它重新拉起来 (等于没断开)
     *   · 线程不再被重启, 因此断开期间**没有任何网络流量**
     */
    bool is_manual_offline;
} runtime_status_t;

typedef struct
{
    auth_cfg_t auth_cfg;
    login_cfg_t login_cfg;
    runtime_status_t runtime_status;
    uint64_t thread_id;
    sim_thread_t* thread;
    char last_location[LAST_LOCATION_LEN * 2];
    bool last_location_lock;

    /**
     * 判定"需要认证"那一刻的 Location 快照 —— 也就是 BAS 注入的那条门户 URL。
     *
     * 为什么不直接读 last_location: get_last_location() 会**跟随 302** 并不断覆盖
     * last_location。今天湖南的门户页在未认证时返回 200, 所以那个循环不会跑,
     * last_location 恰好停在注入地址上 —— 属于"碰巧对"。而实测已认证时同一个
     * index.cgi 会 302 到一个被动态防护挡着的网页门户 (412/403), 一旦哪里先跳到
     * 那里, last_location 就不再是能用的 API 基址了。快照让这件事变成"构造上对"。
     *
     * 放在 prog_status_t 而不是 auth_cfg_t: clean() 会 memset 掉 auth_cfg, 而
     * reset() 恰好在 auth() 之前调用 (DialerClient.c 的 STATUS_NEED_AUTH 分支),
     * 放 auth_cfg 里会被清空。
     */
    char portal_hint[PORTAL_HINT_LEN];
} prog_status_t;

#ifdef _WIN32
extern jmp_buf g_exit_jmp;
#endif

extern uint64_t g_start_run_tm;

extern prog_role_t g_prog_role;

extern uint8_t g_prog_account;

extern uint16_t g_control_port;

extern uint16_t g_web_port;

extern bool g_web_external_acc;

extern char g_control_token[CONTROL_TOKEN_LEN];

extern int g_main_argc;

extern char** g_main_argv;

extern volatile sig_atomic_t g_stop_requested;

extern int8_t g_prog_cnt;

extern _Thread_local int8_t tl_thread_idx;

extern _Thread_local const char* tl_thread_name;

extern prog_status_t* g_prog_status;

extern char g_school_network_symbol[SCHOOL_NETWORK_SYMBOL];

extern bool g_thread_keep_alive;

extern bool g_is_webserver_running;

extern bool g_need_exit;

extern bool g_prog_enabled;

extern bool g_need_restart;

extern bool g_cfg_loaded;

/**
 * 配置是否**就绪到可以认证** —— 即 enabled 为真, 且至少有一个账号的
 * username / password 都非空。
 *
 * 为假时程序**只跑网页界面**, 不起认证线程: 首次运行、账号还没填、
 * 用户在网页上点了"停用"都落在这里。用户不需要手工编辑配置文件 ——
 * 在网页上填完点「保存并应用」, 这个标志就会翻成真, 主循环随即开始认证。
 *
 * 与 g_cfg_loaded 的区别: 那个只是"文件读过了", 这个才是"能拿去认证了"。
 */
extern bool g_cfg_ready;

/**
 * 配置文件存在, 但内容解析不了 (JSON 语法错误 / 被截断)。
 *
 * 这时程序改用内置默认值继续跑 (不再挂起或退出), 网页上会提示
 * "原配置文件无法解析, 保存会覆盖它", 由用户决定是否覆盖。
 */
extern bool g_cfg_corrupt;

extern long g_conn_timeout;

extern long g_op_timeout;

/** @brief 刷新状态函数 */
void refresh_states();

#endif
