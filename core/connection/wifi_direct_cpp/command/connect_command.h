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
#ifndef WIFI_DIRECT_CONNECT_COMMAND_H
#define WIFI_DIRECT_CONNECT_COMMAND_H

#include "wifi_direct_command.h"
#include <functional>
#include "wifi_direct_types.h"
#include "channel/negotiate_channel.h"
#include "data/wifi_config_info.h"
#include "conn_event.h"

namespace OHOS::SoftBus {
enum class ConnectCommandRetryReason {
    RETRY_FOR_NOTHING = 0,
    RETRY_FOR_PASSIVE_SWITCH_CHANNEL,
};

struct ConnectInfo {
    WifiDirectConnectInfo info_;
    std::shared_ptr<NegotiateChannel> channel_;
    std::shared_ptr<WifiConfigInfo> wifiConfigInfo_;
};

class ConnectCommand : public WifiDirectCommand {
public:
    using SuccessCallback = std::function<void(const WifiDirectLink &link)>;
    using FailureCallback = std::function<void(int32_t reason)>;

    ConnectCommand(const WifiDirectConnectInfo &info, const WifiDirectConnectCallback &callback);

    std::string GetRemoteDeviceId() const override;
    std::shared_ptr<WifiDirectProcessor> GetProcessor() override;
    CommandType GetType() const override
    {
        return CommandType::CONNECT_COMMAND;
    }

    ConnectInfo& GetConnectInfo();
    WifiDirectConnectCallback GetConnectCallback() const;
    void SetSuccessCallback(const SuccessCallback &callback);
    void SetFailureCallback(const FailureCallback &callback);
    virtual void PreferNegotiateChannel();
    void SetRetried(bool retried) { hasRetried_ = retried; }
    bool HasRetried() const { return hasRetried_; }
    void SetRetryReason(ConnectCommandRetryReason reason) { retryReason_ = reason; }
    ConnectCommandRetryReason GetRetryReason() const { return retryReason_; }

    virtual void OnSuccess(const WifiDirectLink &link) const;
    virtual void OnFailure(int32_t reason) const;
    bool IsSameCommand(const WifiDirectConnectInfo &info) const;
    void ResetConnectType(WifiDirectConnectType connectType);

protected:
    mutable ConnectInfo info_;
    WifiDirectConnectCallback callback_;
    SuccessCallback successCallback_;
    FailureCallback failureCallback_;
    mutable std::string remoteDeviceId_;
    bool hasRetried_ = false;
    ConnectCommandRetryReason retryReason_ = ConnectCommandRetryReason::RETRY_FOR_NOTHING;
};
}
#endif
