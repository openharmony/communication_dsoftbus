/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef G_ENHANCE_TRANS_FUNC_PACK_H
#define G_ENHANCE_TRANS_FUNC_PACK_H

#include <stdint.h>

#include "lnn_lane_interface_struct.h"
#include "softbus_proxychannel_message_struct.h"
#include "softbus_trans_def.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t SetDefaultQdiscPacked(void);
int32_t InitQosPacked(void);
void NotifyQosChannelClosedPacked(int32_t channelId, int32_t channelType);
void GetExtQosInfoPacked(const SessionParam *param, QosInfo *qosInfo, uint32_t index, AllocExtendInfo *extendInfo);
int32_t NotifyQosChannelOpenedPacked(const ChannelInfo *chanInfo);
int32_t TransReversePullUpPacked(const uint32_t chatMode, const uint32_t businessFlag, const char *pkgName);
int32_t TransGetPkgnameByBusinessFlagPacked(const uint32_t businessFlag, char *pkgName, const uint32_t pkgLen);
int32_t InitSoftbusPagingPacked(void);
void DeInitSoftbusPagingPacked(void);
void TransPagingDeathCallbackPacked(const char *pkgName, int32_t pid);
bool TransHasAndUpdatePagingListenPacked(ProxyChannelInfo *info);
int32_t TransPagingGetPidAndDataByFlgPacked(bool isClient, uint32_t businessFlag, int32_t *pid,
    char *data, uint32_t *len);
int32_t TransDelPagingInfoByBusinessFlagPacked(uint32_t businessFlag);

#ifdef __cplusplus
}
#endif

#endif