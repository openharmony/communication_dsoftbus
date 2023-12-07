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

#ifndef SOFTBUS_CLIENT_STUB_H_
#define SOFTBUS_CLIENT_STUB_H_

#include <map>
#include "if_softbus_client.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
class SoftBusClientStub : public IRemoteStub<ISoftBusClient> {
public:
    SoftBusClientStub();
    virtual ~SoftBusClientStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnDeviceFound(const DeviceInfo *device) override;
    void OnDiscoverFailed(int subscribeId, int failReason) override;
    void OnDiscoverySuccess(int subscribeId) override;
    void OnPublishSuccess(int publishId) override;
    void OnPublishFail(int publishId, int reason) override;
    int32_t OnChannelOpened(const char *sessionName, const ChannelInfo *info) override;
    int32_t OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode) override;
    int32_t OnChannelLinkDown(const char *networkId, int32_t routeType) override;
    int32_t OnChannelClosed(int32_t channelId, int32_t channelType) override;
    int32_t OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
        uint32_t len, int32_t type) override;
    int32_t OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
        const QosTv *tvList) override;
    int32_t OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode) override;
    int32_t OnLeaveLNNResult(const char *networkId, int retCode) override;
    int32_t OnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info, uint32_t infoTypeLen) override;
    int32_t OnNodeBasicInfoChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type) override;
    int32_t OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode) override;
    void OnPublishLNNResult(int32_t publishId, int32_t reason) override;
    void OnRefreshLNNResult(int32_t refreshId, int32_t reason) override;
    void OnRefreshDeviceFound(const void *device, uint32_t deviceLen) override;

private:
    int32_t OnDeviceFoundInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDiscoverFailedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnDiscoverySuccessInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnPublishSuccessInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnPublishFailInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnChannelOpenedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnChannelOpenFailedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnChannelLinkDownInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnChannelClosedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnChannelMsgReceivedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnChannelQosEventInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnJoinLNNResultInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnLeaveLNNResultInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnNodeOnlineStateChangedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnNodeBasicInfoChangedInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnTimeSyncResultInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnPublishLNNResultInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnRefreshLNNResultInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnRefreshDeviceFoundInner(MessageParcel &data, MessageParcel &reply);
    int32_t OnClientPermissonChangeInner(MessageParcel &data, MessageParcel &reply);

    using SoftBusClientStubFunc =
        int32_t (SoftBusClientStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, SoftBusClientStubFunc> memberFuncMap_;
};
} // namespace OHOS

#endif // SOFTBUS_CLIENT_STUB_H_