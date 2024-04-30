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
#include "wifi_direct_manager.h"
#include "softbus_error_code.h"

static uint32_t GetRequestId()
{
    return 0;
}

static int32_t AllocateListenerModuleId(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static void FreeListenerModuleId(int32_t moduleId)
{
    (void)moduleId;
}

static int32_t ConnectDevice(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t DisconnectDevice(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void RegisterStatusListener(struct WifiDirectStatusListener *listener)
{
    (void)listener;
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    (void)remoteNetworkId;
    (void)connectType;
    return SOFTBUS_NOT_IMPLEMENT;
}

static bool IsDeviceOnline(const char *remoteMac)
{
    (void)remoteMac;
    return false;
}

static int32_t GetLocalIpByUuid(const char *uuid, char *localIp, int32_t localIpSize)
{
    (void)uuid;
    (void)localIp;
    (void)localIpSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    (void)remoteIp;
    (void)localIp;
    (void)localIpSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t GetRemoteUuidByIp(const char *remoteIp, char *uuid, int32_t uuidSize)
{
    (void)remoteIp;
    (void)uuid;
    (void)uuidSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void NotifyOnline(const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource)
{
    (void)remoteMac;
    (void)remoteIp;
    (void)remoteUuid;
    (void)isSource;
}

static void NotifyOffline(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp)
{
    (void)remoteMac;
    (void)remoteIp;
    (void)remoteUuid;
    (void)localIp;
}

static void NotifyRoleChange(enum WifiDirectRole oldRole, enum WifiDirectRole newRole)
{
    (void)oldRole;
    (void)newRole;
}

static bool IsNegotiateChannelNeeded(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    (void)remoteNetworkId;
    (void)linkType;
    return false;
}

static bool SupportHmlTwo(void)
{
    return false;
}

static bool IsWifiP2pEnabled(void)
{
    return false;
}

static int GetStationFrequency(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t Init()
{
    return SOFTBUS_OK;
}

static struct WifiDirectManager g_manager = {
    .getRequestId = GetRequestId,
    .allocateListenerModuleId = AllocateListenerModuleId,
    .freeListenerModuleId = FreeListenerModuleId,
    .connectDevice = ConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .registerStatusListener = RegisterStatusListener,
    .prejudgeAvailability = PrejudgeAvailability,

    .isNegotiateChannelNeeded = IsNegotiateChannelNeeded,
    .isDeviceOnline = IsDeviceOnline,
    .getLocalIpByUuid = GetLocalIpByUuid,
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    .getRemoteUuidByIp = GetRemoteUuidByIp,

    .supportHmlTwo = SupportHmlTwo,
    .isWifiP2pEnabled = IsWifiP2pEnabled,
    .getStationFrequency = GetStationFrequency,

    .init = Init,
    .notifyOnline = NotifyOnline,
    .notifyOffline = NotifyOffline,
    .notifyRoleChange = NotifyRoleChange,
};

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return &g_manager;
}
