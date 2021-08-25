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

#ifndef INTERFACES_INNERKITS_TRANS_CLIENT_PROXY_STANDARD_H_
#define INTERFACES_INNERKITS_TRANS_CLIENT_PROXY_STANDARD_H_

#include "if_softbus_client.h"

namespace OHOS {
class TransClientProxy : public IRemoteProxy<ISoftBusClient> {
public:
    explicit TransClientProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<ISoftBusClient>(impl) {}
    virtual ~TransClientProxy() = default;

    void OnDeviceFound(const DeviceInfo *device) override;
    void OnDiscoverFailed(int subscribeId, int failReason) override;
    void OnDiscoverySuccess(int subscribeId) override;
    void OnPublishSuccess(int publishId) override;
    void OnPublishFail(int publishId, int reason) override;
    int32_t OnChannelOpened(const char *sessionName, const ChannelInfo *channel) override;
    int32_t OnChannelOpenFailed(int32_t channelId, int32_t channelType) override;
    int32_t OnChannelClosed(int32_t channelId, int32_t channelType) override;
    int32_t OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
        uint32_t len, int32_t type) override;

    int32_t OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode) override;
    int32_t OnLeaveLNNResult(const char *networkId, int retCode) override;
    int32_t OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen) override;
    int32_t OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type) override;
    int32_t OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode) override;

private:
    static inline BrokerDelegator<TransClientProxy> delegator_;
};
} // namespace OHOS

#endif // !defined(INTERFACES_INNERKITS_TRANS_CLIENT_PROXY_STANDARD_H_)