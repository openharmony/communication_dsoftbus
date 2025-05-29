/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbus_error_code.h"
#include "trans_spec_object_proxy.h"

extern "C" {
    void TransBroadCastInit(void)
    {
        return;
    }
}

namespace OHOS {
TransSpecObjectProxy::TransSpecObjectProxy(const sptr<IRemoteObject> &impl)
    :IRemoteProxy<ITransSpecObject>(impl)
{
}

int32_t TransSpecObjectProxy::SendEvent(EventData *event)
{
    return SOFTBUS_NOT_IMPLEMENT;
}
int32_t TransSpecObjectProxy::StopEvent(EventType event)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::RegisterEventListener(EventType event, EventFreq freq,
    bool deduplicate, const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::UnregisterEventListener(const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::CreateSocketServer(const char *pkgName, bool isFirstTimeAdd,
    const MetaCustomData *customData,
    const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::RemoveSocketServer(const char *pkgName, bool isLastTimeDel,
    const MetaCustomData *customData,
    const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::OpenSocket(const MetaCustomData *customData)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::CloseSocket(int32_t socketId)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::SendMetaSocketData(int32_t socketId, const void *dataInfo, uint32_t len)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::GetMacInfo(int32_t channelId, int32_t channelType, MacInfo *info)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::OpenAuthSessionWithPara(const char *sessionName, const LinkPara *para)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::SendLinkEvent(const char *networkId, uint16_t seqNum)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::StopLinkEvent(const char *networkId)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::RegisterLinkEventListener(const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::UnregisterLinkEventListener(const sptr<IRemoteObject>& listener)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t TransSpecObjectProxy::TransProxySendMetaCtrlData(int32_t socketId, const MetaCustomData *customData)
{
    return SOFTBUS_NOT_IMPLEMENT;
}
} // namespace OHOS