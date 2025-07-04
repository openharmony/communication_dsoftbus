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

int32_t TransReversePullUpPacked(const uint32_t chatMode, const uint32_t businessFlag, const char *pkgName)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transReversePullUp) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->transReversePullUp(chatMode, businessFlag, pkgName);
}

int32_t TransGetPkgnameByBusinessFlagPacked(const uint32_t businessFlag, char *pkgName, const uint32_t pkgLen)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transGetPkgnameByBusinessFlag) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->transGetPkgnameByBusinessFlag(businessFlag, pkgName, pkgLen);
}

int32_t InitSoftbusPagingPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->initSoftbusPaging) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->initSoftbusPaging();
}

void DeInitSoftbusPagingPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->deInitSoftbusPaging) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->deInitSoftbusPaging();
}

void TransPagingDeathCallbackPacked(const char *pkgName, int32_t pid)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transPagingDeathCallback) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->transPagingDeathCallback(pkgName, pid);
}

bool TransHasAndUpdatePagingListenPacked(ProxyChannelInfo *info)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transHasAndUpdatePagingListen) != SOFTBUS_OK) {
        return true;
    }
    return pfnTransEnhanceFuncList->transHasAndUpdatePagingListen(info);
}

int32_t TransPagingGetPidAndDataByFlgPacked(bool isClient, uint32_t businessFlag, int32_t *pid,
    char *data, uint32_t *len)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transPagingGetPidAndDataByFlg) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->transPagingGetPidAndDataByFlg(isClient, businessFlag, pid, data, len);
}

int32_t TransDelPagingInfoByBusinessFlagPacked(uint32_t businessFlag)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transDelPagingInfoByBusinessFlag) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->transDelPagingInfoByBusinessFlag(businessFlag);
}
