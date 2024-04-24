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
#include "wifi_direct_types.h"
#include "channel/negotiate_channel.h"
#include "data/wifi_config_info.h"
#include "conn_event.h"

namespace OHOS::SoftBus {
struct ConnectInfo {
    WifiDirectConnectInfo info_;
    std::shared_ptr<NegotiateChannel> channel_;
    std::shared_ptr<WifiConfigInfo> wifiConfigInfo_;
};

class ConnectCommand : public WifiDirectCommand {
public:
    ConnectCommand(const WifiDirectConnectInfo &info, const WifiDirectConnectCallback &callback);

    std::string GetRemoteDeviceId() const override;
    std::shared_ptr<WifiDirectProcessor> GetProcessor() override;
    CommandType GetType() const override
    {
        return CommandType::CONNECT_COMMAND;
    }

    ConnectInfo& GetConnectInfo();
    WifiDirectConnectCallback GetConnectCallback() const;
    virtual void PreferNegotiateChannel();
    void SetRetried(bool retried) { hasRetried_ = retried; }
    bool HasRetried() const { return hasRetried_; }

    void OnSuccess(const WifiDirectLink &link) const;
    void OnFailure(WifiDirectErrorCode reason) const;

protected:
    ConnectInfo info_;
    WifiDirectConnectCallback callback_;
    mutable std::string remoteDeviceId_;
    bool hasRetried_ = false;

    void DfxRecord(bool isSuccess, WifiDirectErrorCode reason) const;
    void FillConnEventExtra(ConnEventExtra &extra) const;
};
}
#endif
