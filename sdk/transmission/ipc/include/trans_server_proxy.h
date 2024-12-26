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

#ifndef TRANS_SERVER_PROXY_H
#define TRANS_SERVER_PROXY_H

#include "stdint.h"
#include "softbus_common.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransServerProxyInit(void);
void TransServerProxyDeInit(void);
int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName);
int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName);
int32_t ServerIpcOpenSession(const SessionParam *param, TransInfo *info);
int32_t ServerIpcOpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo);
int32_t ServerIpcNotifyAuthSuccess(int32_t channelId, int32_t channelType);
int32_t ServerIpcCloseChannel(const char *sessionName, int32_t channelId, int32_t channelType);
int32_t ServerIpcCloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len);
int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType);
int32_t ServerIpcQosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality);
int32_t ServerIpcGrantPermission(int uid, int pid, const char *sessionName);
int32_t ServerIpcRemovePermission(const char *sessionName);
int32_t ServerIpcReleaseResources(int32_t channelId);
int32_t ServerIpcStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data);
int32_t ServerIpcRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data);
int32_t ServerIpcEvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount);
int32_t ServerIpcProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len);
int32_t ServerIpcPrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId);
#ifdef __cplusplus
}
#endif
#endif
