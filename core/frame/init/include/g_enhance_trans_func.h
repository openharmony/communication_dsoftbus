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

#ifndef G_ENHANCE_TRANS_FUNC_H
#define G_ENHANCE_TRANS_FUNC_H

#include "lnn_lane_interface_struct.h"
#include "stdint.h"
#include "softbus_def.h"
#include "softbus_proxychannel_message_struct.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*InitQosFunc)(void);
typedef int32_t (*NotifyQosChannelOpenedFunc)(const ChannelInfo *chanInfo);
typedef void (*NotifyQosChannelClosedFunc)(int32_t channelId, int32_t channelType);
typedef void (*GetExtQosInfoFunc)(const SessionParam *param, QosInfo *qosInfo, uint32_t index, AllocExtendInfo *extendInfo);
typedef int32_t (*SetDefaultQdiscFunc)(void);
typedef int32_t (*TransReversePullUpFunc)(const uint32_t chatMode, const uint32_t businessFlag, const char *pkgName);
typedef int32_t (*TransGetPkgnameByBusinessFlagFunc)(const uint32_t businessFlag, char *pkgName, const uint32_t pkgLen);
typedef int32_t (*InitSoftbusPagingFunc)(void);
typedef void (*DeInitSoftbusPagingFunc)(void);
typedef void (*TransPagingDeathCallbackFunc)(const char *pkgName, int32_t pid);
typedef bool (*TransHasAndUpdatePagingListenFunc)(ProxyChannelInfo *info);
typedef int32_t (*TransPagingGetPidAndDataByFlgFunc)(bool isClient, uint32_t businessFlag, int32_t *pid,
    char *data, uint32_t *len);
typedef int32_t (*TransDelPagingInfoByBusinessFlagFunc)(uint32_t businessFlag);
typedef struct TagTransEnhanceFuncList {
    InitQosFunc initQos;
    NotifyQosChannelOpenedFunc notifyQosChannelOpened;
    NotifyQosChannelClosedFunc notifyQosChannelClosed;
    GetExtQosInfoFunc getExtQosInfo;
    SetDefaultQdiscFunc setDefaultQdisc;
    TransReversePullUpFunc transReversePullUp;
    TransGetPkgnameByBusinessFlagFunc transGetPkgnameByBusinessFlag;
    InitSoftbusPagingFunc initSoftbusPaging;
    DeInitSoftbusPagingFunc deInitSoftbusPaging;
    TransPagingDeathCallbackFunc transPagingDeathCallback;
    TransHasAndUpdatePagingListenFunc transHasAndUpdatePagingListen;
    TransPagingGetPidAndDataByFlgFunc transPagingGetPidAndDataByFlg;
    TransDelPagingInfoByBusinessFlagFunc transDelPagingInfoByBusinessFlag;
} TransEnhanceFuncList;

TransEnhanceFuncList *TransEnhanceFuncListGet(void);
int32_t TransRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif