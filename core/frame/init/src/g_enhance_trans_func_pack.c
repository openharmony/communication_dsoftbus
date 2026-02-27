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

int32_t InitSoftbusPagingResPullPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->initSoftbusPagingResPull) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->initSoftbusPagingResPull();
}

void DeInitSoftbusPagingResPullPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->deInitSoftbusPagingResPull) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->deInitSoftbusPagingResPull();
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

bool TransPagingHasListenAndGetInfoPacked(ProxyChannelInfo *info)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transPagingHasListenAndGetInfo) != SOFTBUS_OK) {
        return true;
    }
    return pfnTransEnhanceFuncList->transPagingHasListenAndGetInfo(info);
}

int32_t TransPagingGetPidAndDataByFlgPacked(
    bool isClient, uint32_t businessFlag, int32_t *pid, char *data, uint32_t *len)
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

int32_t ClientOpenHtpChannelPacked(int32_t channelId, int64_t requestId, const char *localMac, const char *remoteMac)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->clientOpenHtpChannel) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->clientOpenHtpChannel(channelId, requestId, localMac, remoteMac);
}

int32_t ServerOpenHtpChannelPacked(const char *remoteIp, int64_t flIdentity)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->serverOpenHtpChannel) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->serverOpenHtpChannel(remoteIp, flIdentity);
}

int32_t CloseHtpChannelPacked(int32_t channelId)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->closeHtpChannel) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->closeHtpChannel(channelId);
}

void ServerUpdateHtpChannelPacked(int64_t flIdentity, int32_t channelId)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->serverUpdateHtpChannel) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->serverUpdateHtpChannel(flIdentity, channelId);
}

bool CheckHtpPermissionPacked(int32_t uid)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->checkHtpPermission) != SOFTBUS_OK) {
        return false;
    }
    return pfnTransEnhanceFuncList->checkHtpPermission(uid);
}

void TransProcessGroupTalkieInfoPacked(const char *pkgName)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transProcessGroupTalkieInfo) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->transProcessGroupTalkieInfo(pkgName);
}

bool IsInWhitelistPacked(const char *app)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return true;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->isInWhitelist) != SOFTBUS_OK) {
        return true;
    }
    return pfnTransEnhanceFuncList->isInWhitelist(app);
}

bool IsMultipathWhitelistPacked(const char *processName, bool *isWhitelist)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return false;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->isMultipathWhitelist) != SOFTBUS_OK) {
        return false;
    }
    return pfnTransEnhanceFuncList->isMultipathWhitelist(processName, isWhitelist);
}

bool CheckAuthChannelSessionNameValidPacked(const char *sessionName)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return false;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->checkAuthChannelSessionNameValid) != SOFTBUS_OK) {
        return false;
    }
    return pfnTransEnhanceFuncList->checkAuthChannelSessionNameValid(sessionName);
}

bool TransCheckNetworkDelegatePacked(const char *sessionName)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return false;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transCheckNetworkDelegate) != SOFTBUS_OK) {
        return false;
    }
    return pfnTransEnhanceFuncList->transCheckNetworkDelegate(sessionName);
}

bool TransCheckP2pOnlyPacked(const char *sessionName)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return false;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transCheckP2pOnly) != SOFTBUS_OK) {
        return false;
    }
    return pfnTransEnhanceFuncList->transCheckP2pOnly(sessionName);
}

bool TransCheckDcTriggerVirtualLinkPacked(const char *sessionName, const char *peerNetworkId)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return false;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transCheckDcTriggerVirtualLink) != SOFTBUS_OK) {
        return false;
    }
    return pfnTransEnhanceFuncList->transCheckDcTriggerVirtualLink(sessionName, peerNetworkId);
}

int32_t LoadTransPermissionJsonPacked(void)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return SOFTBUS_OK;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->loadTransPermissionJson) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnTransEnhanceFuncList->loadTransPermissionJson();
}

void TransD2dQosUnregisterPacked(int32_t channelId, char *sleMac, uint32_t macLen)
{
    TransEnhanceFuncList *pfnTransEnhanceFuncList = TransEnhanceFuncListGet();
    if (pfnTransEnhanceFuncList == NULL) {
        return;
    }
    if (TransCheckFuncPointer((void *)pfnTransEnhanceFuncList->transD2dQosUnregister) != SOFTBUS_OK) {
        return;
    }
    return pfnTransEnhanceFuncList->transD2dQosUnregister(channelId, sleMac, macLen);
}
