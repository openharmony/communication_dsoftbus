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

#ifndef INTERFACES_INNERKITS_SOFTBUS_CLIENT_H_
#define INTERFACES_INNERKITS_SOFTBUS_CLIENT_H_

#include "discovery_service.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_def.h"

namespace OHOS {
class ISoftBusClient : public IRemoteBroker {
public:
    virtual ~ISoftBusClient() = default;

    virtual void OnDeviceFound(const DeviceInfo *device) = 0;
    virtual void OnDiscoverFailed(int subscribeId, int failReason) = 0;
    virtual void OnDiscoverySuccess(int subscribeId) = 0;
    virtual void OnPublishSuccess(int publishId) = 0;
    virtual void OnPublishFail(int publishId, int reason) = 0;
    virtual int32_t OnChannelOpened(const char *sessionName, const ChannelInfo *channel) = 0;
    virtual int32_t OnChannelOpenFailed(int32_t channelId, int32_t channelType) = 0;
    virtual int32_t OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
        uint32_t len, int32_t type) = 0;
    virtual int32_t OnChannelClosed(int32_t channelId, int32_t channelType) = 0;
    virtual int32_t OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode) = 0;
    virtual int32_t OnLeaveLNNResult(const char *networkId, int retCode) = 0;
    virtual int32_t OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen) = 0;
    virtual int32_t OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type) = 0;
    virtual int32_t OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ISoftBusClient");
};
} // namespace OHOS

#endif // !defined(INTERFACES_INNERKITS_SOFTBUS_CLIENT_H_ )
