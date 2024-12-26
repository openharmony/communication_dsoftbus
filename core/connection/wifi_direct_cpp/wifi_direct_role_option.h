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
#ifndef WIFI_DIRECT_ROLE_OPTION_H
#define WIFI_DIRECT_ROLE_OPTION_H

#include "wifi_direct_types.h"
#include <string>

namespace OHOS::SoftBus {
class WifiDirectRoleOption {
public:
    static WifiDirectRoleOption &GetInstance()
    {
        static WifiDirectRoleOption instance;
        return instance;
    }

    int GetExpectedRole(
        const std::string &networkId, enum WifiDirectConnectType type, uint32_t &expectedRole, bool &isStrict);

private:
    WifiDirectRole GetExpectedP2pRole(const std::string &netWorkId);
    bool IsPowerAlwaysOn(int32_t devTypeId);
    bool IsGoPreferred(int32_t devTypeId);
    bool IsGcPreferred(int32_t devTypeId);
};
}  // namespace OHOS::SoftBus
#endif
