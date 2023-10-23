/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "bus_center_manager.h"
#include "lnn_device_info.h"

#define LOG_LABEL "[WD] RO: "

static bool IsPowerAlwaysOn(int32_t devTypeId)
{
    return devTypeId == TYPE_TV_ID || devTypeId == TYPE_CAR_ID || devTypeId == TYPE_SMART_DISPLAY_ID ||
           devTypeId == TYPE_PC_ID || devTypeId == TYPE_2IN1_ID;
}

static bool IsGoPreferred(int32_t devTypeId)
{
    return devTypeId == TYPE_PAD_ID;
}

static enum WifiDirectRole GetExpectedP2pRole(const char *networkId)
{
    int32_t localDevTypeId = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, LOG_LABEL "get local dev type id failed");
    CLOGD(LOG_LABEL "localDevTypeId=0x%03X", localDevTypeId);

    if (IsPowerAlwaysOn(localDevTypeId)) {
        CLOGI(LOG_LABEL "local device's power is always-on");
        return WIFI_DIRECT_ROLE_GO;
    }

    int32_t remoteDevTypeId = 0;
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, LOG_LABEL "get remote dev type id failed");
    CLOGD(LOG_LABEL "remoteDevTypeId=0x%03X", remoteDevTypeId);

    if (IsPowerAlwaysOn(remoteDevTypeId)) {
        CLOGI(LOG_LABEL "remote device's power is always-on");
        return WIFI_DIRECT_ROLE_GC;
    }

    if (IsGoPreferred(localDevTypeId)) {
        CLOGI(LOG_LABEL "local device prefers Go");
        return WIFI_DIRECT_ROLE_GO;
    }

    if (IsGoPreferred(remoteDevTypeId)) {
        CLOGI(LOG_LABEL "remote device prefers Go");
        return WIFI_DIRECT_ROLE_GC;
    }

    return WIFI_DIRECT_ROLE_AUTO;
}

static int32_t GetExpectedRole(const char *networkId, enum WifiDirectConnectType type, uint32_t *expectedRole,
                               bool *isStrict)
{
    if (type == WIFI_DIRECT_CONNECT_TYPE_HML) {
        *expectedRole = WIFI_DIRECT_API_ROLE_HML;
        *isStrict = true;
    } else if (type == WIFI_DIRECT_CONNECT_TYPE_P2P) {
        enum WifiDirectRole role = GetExpectedP2pRole(networkId);
        if (role == WIFI_DIRECT_ROLE_GC) {
            *expectedRole = WIFI_DIRECT_API_ROLE_GC;
        } else if (role == WIFI_DIRECT_ROLE_GO) {
            *expectedRole = WIFI_DIRECT_API_ROLE_GO;
        } else {
            *expectedRole = WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO;
        }
        *isStrict = true;
    } else if (type == WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT) {
        enum WifiDirectRole role = GetExpectedP2pRole(networkId);
        if (role == WIFI_DIRECT_ROLE_GC) {
            *expectedRole = WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML;
        } else if (role == WIFI_DIRECT_ROLE_GO) {
            *expectedRole = WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML;
        } else {
            *expectedRole = WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML;
        }
        *isStrict = false;
    } else {
        CLOGE(LOG_LABEL "type=%d invalid", type);
        return SOFTBUS_INVALID_PARAM;
    }

    CLOGI(LOG_LABEL "expectRole=0x%x isStrict=%d", *expectedRole, *isStrict);
    return SOFTBUS_OK;
}

static struct WifiDirectRoleOption g_roleOption = {
    .getExpectedRole = GetExpectedRole,
};

struct WifiDirectRoleOption* GetWifiDirectRoleOption(void)
{
    return &g_roleOption;
}