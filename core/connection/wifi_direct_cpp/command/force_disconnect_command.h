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

#ifndef FORCE_DISCONNECT_COMMAND_H
#define FORCE_DISCONNECT_COMMAND_H

#include "wifi_direct_types.h"
#include "command/wifi_direct_command.h"
#include "channel/negotiate_channel.h"

namespace OHOS::SoftBus {
struct ForceDisconnectInfo {
    WifiDirectForceDisconnectInfo info_;
    std::shared_ptr<NegotiateChannel> channel_;
};

class ForceDisconnectCommand : public WifiDirectCommand {
public:
    ForceDisconnectCommand(const WifiDirectForceDisconnectInfo &info, const WifiDirectDisconnectCallback &callback);

    std::string GetRemoteDeviceId() const override;
    std::shared_ptr<WifiDirectProcessor> GetProcessor() override;
    CommandType GetType() const override
    {
        return CommandType::FORCE_DISCONNECT_COMMAND;
    }

    ForceDisconnectInfo GetDisconnectInfo() const;
    std::shared_ptr<NegotiateChannel> GetNegotiateChannel() const;

    void OnSuccess() const;
    void OnFailure(int32_t reason) const;

protected:
    ForceDisconnectInfo info_;
    WifiDirectDisconnectCallback callback_;
    mutable std::string remoteDeviceId_;
};
}  // namespace OHOS::SoftBus
#endif