/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "trans_udp_negotiation.h"
#include "softbus_error_code.h"

int32_t TransUdpChannelInit(IServerChannelCallBack *callback)
{
    (void)callback;
    return SOFTBUS_OK;
}

void TransUdpChannelDeinit(void)
{
    return;
}

int32_t TransOpenUdpChannel(AppInfo* appInfo, const ConnectOption *connOpt, int32_t *channelId)
{
    (void)appInfo;
    (void)connOpt;
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransCloseUdpChannel(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t NotifyUdpChannelOpenFailed(const AppInfo *info, int32_t errCode)
{
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t NotifyUdpChannelClosed(const AppInfo *info, int32_t messageType)
{
    (void)info;
    (void)messageType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpGetNameByChanId(int32_t channelId, char *pkgName, char *sessionName,
    uint16_t pkgNameLen, uint16_t sessionNameLen)
{
    (void)channelId;
    (void)pkgName;
    (void)sessionName;
    (void)pkgNameLen;
    (void)sessionNameLen;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void TransUdpDeathCallback(const char *pkgName, int32_t pid)
{
    (void)pkgName;
    (void)pid;
    return;
}

int32_t NotifyUdpQosEvent(const AppInfo *info, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    (void)info;
    (void)eventId;
    (void)tvCount;
    (void)tvList;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransDealUdpChannelOpenResult(int32_t channelId, int32_t openResult, int32_t udpPort)
{
    (void)channelId;
    (void)openResult;
    (void)udpPort;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransDealUdpCheckCollabResult(int32_t channelId, int32_t checkResult)
{
    (void)channelId;
    (void)checkResult;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}