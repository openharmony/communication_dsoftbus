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
#include "wifi_direct_role_option.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "bus_center_manager.h"
#include "lnn_device_info.h"

namespace OHOS::SoftBus {
int WifiDirectRoleOption::GetExpectedRole(
    const std::string &networkId, enum WifiDirectConnectType type, uint32_t &expectedRole, bool &isStrict)
{
    if (type == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P) {
        enum WifiDirectRole role = GetExpectedP2pRole(networkId);
        if (role == WIFI_DIRECT_ROLE_GC) {
            expectedRole = WIFI_DIRECT_API_ROLE_GC;
        } else if (role == WIFI_DIRECT_ROLE_GO) {
            expectedRole = WIFI_DIRECT_API_ROLE_GO;
        } else {
            expectedRole = WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO;
        }
        isStrict = false;
    } else if (type == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML) {
        enum WifiDirectRole role = GetExpectedP2pRole(networkId);
        if (role == WIFI_DIRECT_ROLE_GC) {
            expectedRole = WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML;
        } else if (role == WIFI_DIRECT_ROLE_GO) {
            expectedRole = WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML;
        } else {
            expectedRole = WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML;
        }
        isStrict = false;
    } else if (type == WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML ||
        type == WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML || type == WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML) {
        expectedRole = WIFI_DIRECT_API_ROLE_HML;
        isStrict = true;
    } else {
        CONN_LOGW(CONN_WIFI_DIRECT, "type invalid. type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "expectRole=0x%{public}x, isStrict=%{public}d", expectedRole, isStrict);
    return SOFTBUS_OK;
}

WifiDirectRole WifiDirectRoleOption::GetExpectedP2pRole(const std::string &netWorkId)
{
    int32_t localDevTypeId = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, CONN_WIFI_DIRECT, "get local dev type id failed");
    CONN_LOGD(CONN_WIFI_DIRECT, "localDevTypeId=0x%{public}03X", localDevTypeId);

    if (IsPowerAlwaysOn(localDevTypeId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "local device's power is always-on");
        return WIFI_DIRECT_ROLE_GO;
    }

    int32_t remoteDevTypeId = 0;
    ret = LnnGetRemoteNumInfo(netWorkId.data(), NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, CONN_WIFI_DIRECT, "get remote dev type id failed");
    CONN_LOGD(CONN_WIFI_DIRECT, "remoteDevTypeId=0x%{public}03X", remoteDevTypeId);

    if (IsPowerAlwaysOn(remoteDevTypeId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remote device's power is always-on");
        return WIFI_DIRECT_ROLE_GC;
    }

    if (IsGoPreferred(localDevTypeId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "local device prefers Go");
        return WIFI_DIRECT_ROLE_GO;
    }

    if (IsGoPreferred(remoteDevTypeId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remote device prefers Go");
        return WIFI_DIRECT_ROLE_GC;
    }

    if (IsGcPreferred(remoteDevTypeId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remote device prefers Gc");
        return WIFI_DIRECT_ROLE_GO;
    }

    if (IsGcPreferred(localDevTypeId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "local device prefers Gc");
        return WIFI_DIRECT_ROLE_GC;
    }
    return WIFI_DIRECT_ROLE_AUTO;
}

bool WifiDirectRoleOption::IsPowerAlwaysOn(int32_t devTypeId)
{
    return devTypeId == TYPE_TV_ID || devTypeId == TYPE_CAR_ID || devTypeId == TYPE_SMART_DISPLAY_ID;
}

bool WifiDirectRoleOption::IsGoPreferred(int32_t devTypeId)
{
    return devTypeId == TYPE_PAD_ID || devTypeId == TYPE_PC_ID || devTypeId == TYPE_2IN1_ID;
}

bool WifiDirectRoleOption::IsGcPreferred(int32_t devTypeId)
{
    return devTypeId == TYPE_WATCH_ID;
}
}  // namespace OHOS::SoftBus