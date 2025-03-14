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

#ifndef WIFI_DEVICE_MOCK_H
#define WIFI_DEVICE_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "wifi_errcode.h"

namespace OHOS::Wifi {
struct WifiLinkedInfo {
    int chload;
};

class WifiDevice {
public:
    WifiDevice() = default;
    ~WifiDevice() = default;
    static std::shared_ptr<WifiDevice> GetInstance(int systemAbilityId)
    {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<WifiDevice>();
        }
        return instance_;
    }
    MOCK_METHOD(ErrCode, GetLinkedInfo, (WifiLinkedInfo &));

    static inline std::shared_ptr<WifiDevice> instance_;
};
} // namespace OHOS::Wifi
#endif
