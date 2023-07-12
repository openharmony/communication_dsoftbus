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
    return devTypeId == TYPE_TV_ID || devTypeId == TYPE_CAR_ID || devTypeId == TYPE_SMART_DISPLAY_ID;
}

static bool IsGoPreferred(int32_t devTypeId)
{
    return devTypeId == TYPE_PAD_ID;
}

static enum WifiDirectRole GetExpectedP2pRole(const char *networkId)
{
    int32_t localDevTypeId = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, "get local dev type id failed");
    CLOGD("localDevTypeId=0x%03X", localDevTypeId);

    if (IsPowerAlwaysOn(localDevTypeId)) {
        CLOGI("local device's power is always-on");
        return WIFI_DIRECT_ROLE_GO;
    }

    int32_t remoteDevTypeId = 0;
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, "get remote dev type id failed");
    CLOGD("remoteDevTypeId=0x%03X", remoteDevTypeId);

    if (IsPowerAlwaysOn(remoteDevTypeId)) {
        CLOGI("remote device's power is always-on");
        return WIFI_DIRECT_ROLE_GC;
    }

    if (IsGoPreferred(localDevTypeId)) {
        CLOGI("local device prefers Go");
        return WIFI_DIRECT_ROLE_GO;
    }

    if (IsGoPreferred(remoteDevTypeId)) {
        CLOGI("remote device prefers Go");
        return WIFI_DIRECT_ROLE_GC;
    }

    return WIFI_DIRECT_ROLE_AUTO;
}

static enum WifiDirectRole GetRemoteExpectedP2pRole(const char *networkId)
{
    int32_t remoteDevTypeId = 0;
    int32_t ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, "get remote dev type id failed");
    CLOGD("remoteDevTypeId=0x%03X", remoteDevTypeId);

    if (IsPowerAlwaysOn(remoteDevTypeId)) {
        CLOGI("remote device's power is always-on");
        return WIFI_DIRECT_ROLE_GO;
    }

    int32_t localDevTypeId = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, WIFI_DIRECT_ROLE_AUTO, "get local dev type id failed");
    CLOGD("localDevTypeId=0x%03X", localDevTypeId);

    if (IsPowerAlwaysOn(localDevTypeId)) {
        CLOGI("local device's power is always-on");
        return WIFI_DIRECT_ROLE_GC;
    }

    if (IsGoPreferred(remoteDevTypeId)) {
        CLOGI("remote device prefers Go");
        return WIFI_DIRECT_ROLE_GO;
    }

    if (IsGoPreferred(localDevTypeId)) {
        CLOGI("local device prefers Go");
        return WIFI_DIRECT_ROLE_GC;
    }

    return WIFI_DIRECT_ROLE_AUTO;
}

static struct WifiDirectRoleOption g_roleOption = {
    .getExpectedP2pRole = GetExpectedP2pRole,
    .getRemoteExpectedP2pRole = GetRemoteExpectedP2pRole,
};

struct WifiDirectRoleOption *GetWifiDirectRoleOption(void)
{
    return &g_roleOption;
}