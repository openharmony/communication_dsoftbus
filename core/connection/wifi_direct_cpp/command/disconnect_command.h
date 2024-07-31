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
#ifndef WIFI_DIRECT_DISCONNECT_COMMAND_H
#define WIFI_DIRECT_DISCONNECT_COMMAND_H

#include "channel/auth_negotiate_channel.h"
#include "wifi_direct_types.h"
#include "command/wifi_direct_command.h"
#include "channel/negotiate_channel.h"

namespace OHOS::SoftBus {
struct DisconnectInfo {
    WifiDirectDisconnectInfo info_;
    std::shared_ptr<NegotiateChannel> channel_;
};

class DisconnectCommand : public WifiDirectCommand {
public:
    DisconnectCommand(const WifiDirectDisconnectInfo &info, const WifiDirectDisconnectCallback &callback);

    std::string GetRemoteDeviceId() const override;
    std::shared_ptr<WifiDirectProcessor> GetProcessor() override;
    CommandType GetType() const override
    {
        return CommandType::DISCONNECT_COMMAND;
    }

    DisconnectInfo GetDisconnectInfo() const;
    std::shared_ptr<NegotiateChannel> GetNegotiateChannel() const;

    void OnSuccess() const;
    void OnFailure(int32_t reason) const;

protected:
    DisconnectInfo info_;
    WifiDirectDisconnectCallback callback_;
    mutable std::string remoteDeviceId_;
};
}
#endif
