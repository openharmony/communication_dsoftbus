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

#ifndef NEGOTIATE_CHANNEL_H
#define NEGOTIATE_CHANNEL_H

#include <string>
#include <vector>

#include "data/negotiate_message.h"

namespace OHOS::SoftBus {
class NegotiateChannel {
public:
    virtual ~NegotiateChannel() = default;

    virtual int SendMessage(const NegotiateMessage &msg) const = 0;
    virtual std::string GetRemoteDeviceId() const = 0;

protected:
    std::string remoteDeviceId_;
};
} // namespace OHOS::SoftBus
#endif
