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

#ifndef OHOS_ITRANS_SPEC_OBJECT_H
#define OHOS_ITRANS_SPEC_OBJECT_H

#include "iremote_broker.h"
#include "broadcast_struct.h"
#include "meta_socket_struct.h"
#include "trans_type_enhance_struct.h"

namespace OHOS {
class ITransSpecObject : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ITrans.Spec.virtual");

    virtual int32_t SendEvent(EventData *event) = 0;
    virtual int32_t StopEvent(EventType event) = 0;
    virtual int32_t RegisterEventListener(EventType event, EventFreq freq,
        bool deduplicate, const sptr<IRemoteObject>& listener) = 0;
    virtual int32_t UnregisterEventListener(const sptr<IRemoteObject>& listener) = 0;
    virtual int32_t CreateSocketServer(const char *pkgName, bool isFirstTimeAdd, const MetaCustomData *customData,
        const sptr<IRemoteObject>& listener) = 0;
    virtual int32_t RemoveSocketServer(const char *pkgName, bool isLastTimeDel, const MetaCustomData *customData,
        const sptr<IRemoteObject>& listener) = 0;
    virtual int32_t OpenSocket(const MetaCustomData *customData) = 0;
    virtual int32_t CloseSocket(int32_t socketId) = 0;
    virtual int32_t SendMetaSocketData(int32_t socketId, const void *dataInfo, uint32_t len) = 0;
    virtual int32_t GetMacInfo(int32_t channelId, int32_t channelType, MacInfo *info) = 0;
    virtual int32_t OpenAuthSessionWithPara(const char *sessionName, const LinkPara *para) = 0;
    virtual int32_t SendLinkEvent(const char *networkId, uint16_t seqNum) = 0;
    virtual int32_t StopLinkEvent(const char *networkId) = 0;
    virtual int32_t RegisterLinkEventListener(const sptr<IRemoteObject>& listener) = 0;
    virtual int32_t UnregisterLinkEventListener(const sptr<IRemoteObject>& listener) = 0;
    virtual int32_t TransProxySendMetaCtrlData(int32_t socketId, const MetaCustomData *customData) = 0;
};
} // namespace OHOS

#endif // OHOS_ITRANS_SPEC_OBJECT_H