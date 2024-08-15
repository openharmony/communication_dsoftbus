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
#ifndef WIFI_DIRECT_COMMAND_H
#define WIFI_DIRECT_COMMAND_H

#include <chrono>
#include <memory>
#include <string>

namespace OHOS::SoftBus {
enum class CommandType {
    NOT_COMMAND,
    CONNECT_COMMAND,
    DISCONNECT_COMMAND,
    NEGOTIATE_COMMAND,
    BLE_TRIGGER_COMMAND,
    FORCE_DISCONNECT_COMMAND,
};

class WifiDirectProcessor;
class WifiDirectCommand {
public:
    WifiDirectCommand()
    {
        id_ = commandId_++;
        startTime_ = std::chrono::steady_clock::now();
    }

    virtual std::string GetRemoteDeviceId() const = 0;
    virtual std::shared_ptr<WifiDirectProcessor> GetProcessor() = 0;
    virtual CommandType GetType() const { return CommandType::NOT_COMMAND; }
    virtual ~WifiDirectCommand() = default;

    uint32_t GetId() const
    {
        return id_;
    }

    bool IsValid(int validDuration)
    {
        auto duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime_);
        return duration.count() < validDuration;
    }

private:
    uint32_t id_ = 0;
    static inline std::atomic_uint32_t commandId_;
    std::chrono::time_point<std::chrono::steady_clock> startTime_;
};
}
#endif
