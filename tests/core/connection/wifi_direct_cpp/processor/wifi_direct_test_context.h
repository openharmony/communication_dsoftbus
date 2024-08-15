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

#ifndef WIFI_DIRECT_TEST_CONTEXT_H
#define WIFI_DIRECT_TEST_CONTEXT_H

#include <gtest/gtest.h>

#include "data/info_container.h"

enum class TestContextKey {
    LOCAL_NETWORK_ID,
    LOCAL_UUID,
    LOCAL_MAC,
    LOCAL_IPV4,

    REMOTE_NETWORK_ID,
    REMOTE_UUID,
    REMOTE_MAC,
    REMOTE_IPV4,

    CONNECT_REQUEST_ID,
    CONNECT_NEGO_CHANNEL_ID,
    CONNECT_REUSE_ONLY,
    CONNECT_EXPECT_API_ROLE,

    WIFI_P2P_STATE,
    WIFI_5G_CHANNEL_LIST,
    WIFI_GET_SELF_CONFIG,
    WIFI_WIDE_BAND_WIDTH_SUPPORT,
    WIFI_STA_FREQUENCY,
    WIFI_RECOMMEND_FREQUENCY,
    WIFI_REQUEST_GC_IP,

    CHANNEL_SEND_MESSAGE,

    SWITCH_INJECT_REMOTE_INNER_LINK,
    SWITCH_INJECT_LOCAL_INNER_LINK,

    INTERFACE_ROLE,
};

namespace OHOS::SoftBus {

template <typename Key>
class WifiDirectTestContext {
public:
    void Set(Key key, const std::any &value)
    {
        values_[key] = value;
    }

    template <typename T>
    T Get(TestContextKey key, const T &defaultValue) const
    {
        const auto it = values_.find(key);
        if (it != values_.end()) {
            return std::any_cast<T>(it->second);
        }
        ADD_FAILURE() << "key '" << static_cast<int>(key) << "' not found, 'Set' should be called first";
        return defaultValue;
    };

    void Reset()
    {
        values_.clear();
    };

private:
    std::map<Key, std::any> values_;
};
} // namespace OHOS::SoftBus

#endif // WIFI_DIRECT_TEST_CONTEXT_H
