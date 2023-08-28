/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TRANS_CHANNEL_MANAGER_H
#define TRANS_CHANNEL_MANAGER_H

#include <stdint.h>

#include "softbus_conn_interface.h"
#include "softbus_trans_def.h"
#include "softbus_app_info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t GenerateChannelId(bool isTdcChannel);

int32_t TransChannelInit(void);

void TransChannelDeinit(void);

int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo);

int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt, const char *reqId);

int32_t TransStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data);

int32_t TransRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data);

int32_t TransRequestQos(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality);

int32_t TransNotifyAuthSuccess(int32_t channelId, int32_t channelType);

int32_t TransCloseChannel(int32_t channelId, int32_t channelType);

int32_t TransSendMsg(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType);

void TransChannelDeathCallback(const char *pkgName, int32_t pid);

int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionNameLen);

int32_t TransGetAppInfoByChanId(int32_t channelId, int32_t channelType, AppInfo* appInfo);

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t* connId);

void ReleaseProxyChannelId(int32_t channelId);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
