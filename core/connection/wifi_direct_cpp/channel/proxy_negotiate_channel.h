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

#include "channel/negotiate_channel.h"
#include "wifi_direct_initiator.h"

namespace OHOS::SoftBus {

class CoCProxyNegotiateChannel : public NegotiateChannel {
public:
    static int Init();

    explicit CoCProxyNegotiateChannel(int32_t channelId);
    CoCProxyNegotiateChannel(const CoCProxyNegotiateChannel &channel) = default;
    ~CoCProxyNegotiateChannel() override;

    CoCProxyNegotiateChannel& operator=(const CoCProxyNegotiateChannel &channel) = default;
    bool operator==(const CoCProxyNegotiateChannel &other) const;

    int SendMessage(const NegotiateMessage &msg) const override;
    std::string GetRemoteDeviceId() const override;

private:
    class Initiator {
    public:
        Initiator()
        {
            WifiDirectInitiator::GetInstance().Add(CoCProxyNegotiateChannel::Init);
        }
    };
    static inline Initiator initiator_;

    int32_t channelId_;
};

} // namespace OHOS::SoftBus
#endif
