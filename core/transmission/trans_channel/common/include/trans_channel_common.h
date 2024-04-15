/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRANS_CHANNEL_COMMON_H
#define TRANS_CHANNEL_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lnn_lane_interface.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_trans_def.h"
#include "trans_event.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void FillAppInfo(AppInfo *appInfo, const SessionParam *param,
    TransInfo *transInfo, LaneConnInfo *connInfo);

AppInfo *TransCommonGetAppInfo(const SessionParam *param);

void TransOpenChannelSetModule(int32_t channelType, ConnectOption *connOpt);

void ReportTransOpenChannelEndEvent(TransEventExtra extra, TransInfo *transInfo, int64_t timeStart, int32_t ret);

void ReportTransAlarmEvent(AppInfo *appInfo, int32_t ret);

LaneTransType TransGetLaneTransTypeBySession(const SessionParam *param);

int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt,
    int32_t *channelId);

int32_t TransCommonCloseChannel(int32_t channelId, int32_t channelType);

int32_t TransCommonGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
