/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_SOFTBUS_CLIENT_H_
#define INTERFACES_INNERKITS_SOFTBUS_CLIENT_H_

#include "data_level_inner.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "session.h"
#include "socket.h"
#include "softbus_common.h"
#include "softbus_def.h"

namespace OHOS {
class ISoftBusClient : public IRemoteBroker {
public:
    ~ISoftBusClient() override = default;

    virtual int32_t OnChannelOpened(const char *sessionName, const ChannelInfo *channel);

    virtual int32_t OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode);

    virtual int32_t OnChannelLinkDown(const char *networkId, int32_t routeType);

    virtual int32_t OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
                                         uint32_t len, int32_t type);

    virtual int32_t OnChannelClosed(int32_t channelId, int32_t channelType, int32_t messageType);

    virtual int32_t OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
                                      const QosTv *tvList);
    virtual int32_t SetChannelInfo(const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType);
    
    virtual int32_t OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode);

    virtual int32_t OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, void *metaInfo, uint32_t infoLen,
                                         int retCode);

    virtual int32_t OnLeaveLNNResult(const char *networkId, int retCode);

    virtual int32_t OnLeaveMetaNodeResult(const char *networkId, int retCode);

    virtual int32_t OnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info, uint32_t infoTypeLen);

    virtual int32_t OnNodeBasicInfoChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type);

    virtual int32_t OnNodeStatusChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type);

    virtual int32_t OnLocalNetworkIdChanged(const char *pkgName);

    virtual int32_t OnNodeDeviceTrustedChange(const char *pkgName, int32_t type, const char *msg, uint32_t msgLen);

    virtual int32_t OnHichainProofException(
        const char *pkgName, const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode);

    virtual int32_t OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode);

    virtual void OnPublishLNNResult(int32_t publishId, int32_t reason);

    virtual void OnRefreshLNNResult(int32_t refreshId, int32_t reason);

    virtual void OnRefreshDeviceFound(const void *device, uint32_t deviceLen);

    virtual void OnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo);

    virtual int32_t OnClientTransLimitChange(int32_t channelId, uint8_t tos);

    virtual int32_t OnChannelBind(int32_t channelId, int32_t channelType);

    virtual int32_t OnClientChannelOnQos(
        int32_t channelId, int32_t channelType, QoSEvent event, const QosTV *qos, uint32_t count);

    virtual int32_t OnCheckCollabRelation(
        const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, int32_t channelId, int32_t channelType);

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ISoftBusClient");
};
}
#endif
