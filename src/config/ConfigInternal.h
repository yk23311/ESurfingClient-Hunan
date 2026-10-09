#ifndef ESURFINGCLIENT_CONFIGINTERNAL_H
#define ESURFINGCLIENT_CONFIGINTERNAL_H

#include "states/States.h"

#include <cJSON/cJSON.h>

extern bool s_list_only;

uint8_t parse_channel_json(const cJSON* chn, const uint8_t cfg_no);

void apply_channel_ua(login_cfg_t* cfg, uint8_t cfg_no);

/**
 * 读取省份相关字段 (province / portal / portal_port / mscgip)。
 * 必须在 apply_channel_ua 之后调用 —— 湖南会覆盖掉通道给出的 UA。
 */
void apply_province_json(login_cfg_t* cfg, const cJSON* account, uint8_t cfg_no);

bool apply_time_windows(const cJSON* item, login_cfg_t* cfg);

uint8_t complete_cfg(cJSON* cfg_json);

void cfg_halt();

#endif
