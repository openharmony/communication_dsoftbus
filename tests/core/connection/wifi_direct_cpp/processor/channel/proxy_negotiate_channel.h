/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef COC_PROXY_NEGOTIATE_CHANNEL_H
#define COC_PROXY_NEGOTIATE_CHANNEL_H

#include <gmock/gmock.h>

#include "conn_log.h"

#include "channel/negotiate_channel.h"
#include "command/negotiate_command.h"
#include "protocol/json_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "wifi_direct_scheduler_factory.h"

#include "wifi_direct_mock.h"

namespace OHOS::SoftBus {

class CoCProxyNegotiateChannel : public NegotiateChannel {
public:
    static void InjectReceiveData(int32_t channelId, std::string mockData)
    {
        ProtocolType type { ProtocolType::JSON };
        auto channel = std::make_shared<CoCProxyNegotiateChannel>(channelId);
        auto remoteDeviceId = channel->GetRemoteDeviceId();

        auto protocol = WifiDirectProtocolFactory::CreateProtocol(type);
        std::vector<uint8_t> input;
        auto data = mockData.c_str();
        input.insert(input.end(), data, data + mockData.size());
        NegotiateMessage msg;
        msg.Unmarshalling(*protocol, input);
        msg.SetRemoteDeviceId(remoteDeviceId);

        NegotiateCommand command(msg, channel);
        CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s", msg.MessageTypeToString().c_str());
        WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessNegotiateData(remoteDeviceId, command);
    };

    explicit CoCProxyNegotiateChannel(int32_t channelId)
    {
        channelId_ = channelId;
    };

    ~CoCProxyNegotiateChannel() override = default;

    CoCProxyNegotiateChannel(const CoCProxyNegotiateChannel &channel) = default;

    CoCProxyNegotiateChannel &operator=(const CoCProxyNegotiateChannel &channel) = default;

    bool operator==(const CoCProxyNegotiateChannel &other) const
    {
        return channelId_ == other.channelId_;
    }

    int32_t SendMessage(const NegotiateMessage &msg) const override
    {
        return WifiDirectInterfaceMock::GetMock()->ProxyNegotiateChannelSendMessage(channelId_, msg);
    };

    std::string GetRemoteDeviceId() const override
    {
        return WifiDirectInterfaceMock::GetMock()->ProxyNegotiateChannelGetRemoteDeviceId(channelId_);
    };

private:
    int32_t channelId_;
};

} // namespace OHOS::SoftBus
#endif
