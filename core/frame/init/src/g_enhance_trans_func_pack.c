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
#include "g_enhance_trans_func_pack.h"

#include "g_enhance_trans_func.h"
#include "softbus_error_code.h"
#include "softbus_init_common.h"

int32_t SetDefaultQdiscPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->setDefaultQdisc) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->setDefaultQdisc();
}

int32_t InitQosPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->initQos) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->initQos();
}

void NotifyQosChannelClosedPacked(int32_t channelId, int32_t channelType)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->notifyQosChannelClosed) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->notifyQosChannelClosed(channelId, channelType);
}

void GetExtQosInfoPacked(const SessionParam *param, QosInfo *qosInfo, uint32_t index, AllocExtendInfo *extendInfo)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->getExtQosInfo) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->getExtQosInfo(param, qosInfo, index, extendInfo);
}

int32_t NotifyQosChannelOpenedPacked(const ChannelInfo *chanInfo)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->notifyQosChannelOpened) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->notifyQosChannelOpened(chanInfo);
}