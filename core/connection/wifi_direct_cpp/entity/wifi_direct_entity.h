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
#ifndef WIFI_DIRECT_ENTITY_H
#define WIFI_DIRECT_ENTITY_H

#include "conn_log.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
class WifiDirectEntity {
public:
    virtual void DisconnectLink(const std::string &remoteMac) = 0;
    virtual void DestroyGroupIfNeeded() = 0;
    virtual HmlCapabilityCode GetHmlCapabilityCode()
    {
        CONN_LOGW(CONN_WIFI_DIRECT, "not support");
        return CONN_HML_NOT_SUPPORT;
    }
};
}
#endif
