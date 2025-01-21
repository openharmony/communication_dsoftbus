/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "processor_snapshot.h"
#include "utils/wifi_direct_anonymous.h"

namespace OHOS::SoftBus {
ProcessorSnapshot::ProcessorSnapshot(
    const std::string &remoteDeviceId, const std::string &processorType, const std::string &state)
{
    remoteDeviceId_ = WifiDirectAnonymize(remoteDeviceId);
    type_ = processorType;
    state_ = state;
}

void ProcessorSnapshot::Marshalling(nlohmann::json &output)
{
    nlohmann::json json;
    json["dumpType"] = "processor";
    json["remoteDeviceId"] = remoteDeviceId_;
    json["type"] = type_;
    json["state"] = state_;
    output.push_back(json);
}
} // namespace OHOS::SoftBus