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

#include "trans_spec_object.h"

#include "softbus_error_code.h"

namespace OHOS {
int32_t TransSpecObject::SendEvent(EventData *event)
{
    return SOFTBUS_NOT_IMPLEMENT;
}
int32_t TransSpecObject::StopEvent(EventType event)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::RegisterEventListener(EventType event, EventFreq freq,
    bool deduplicate, const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::UnregisterEventListener(const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::CreateSocketServer(const char *pkgName, bool isFirstTimeAdd, const MetaCustomData *customData,
    const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::RemoveSocketServer(const char *pkgName, bool isLastTimeDel, const MetaCustomData *customData,
    const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::OpenSocket(const MetaCustomData *customData)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::CloseSocket(int32_t socketId)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::SendMetaSocketData(int32_t socketId, const void *dataInfo, uint32_t len)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::GetMacInfo(int32_t channelId, int32_t channelType, MacInfo *info)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::OpenAuthSessionWithPara(const char *sessionName, const LinkPara *para)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::SendLinkEvent(const char *networkId, uint16_t seqNum)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::StopLinkEvent(const char *networkId)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::RegisterLinkEventListener(const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::UnregisterLinkEventListener(const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObject::TransProxySendMetaCtrlData(int32_t socketId, const MetaCustomData *customData)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransCheckUidAndPid(pid_t callingUid, pid_t callingPid, const MetaCustomData *customData)
{
    return SOFTBUS_NOT_IMPLEMENT;
}
}