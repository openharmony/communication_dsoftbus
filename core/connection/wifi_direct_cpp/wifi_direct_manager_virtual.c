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
#include "wifi_direct_manager.h"
#include "softbus_error_code.h"

static uint32_t GetRequestId(void)
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

static bool IsNoneLinkByType(enum WifiDirectLinkType linkType)
{
    (void)linkType;
    return false;
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

static void RefreshRelationShip(const char *remoteUuid, const char *remoteMac)
{
    (void)remoteUuid;
    (void)remoteMac;
}

static bool LinkHasPtk(const char *remoteDeviceId)
{
    (void)remoteDeviceId;
    return true;
}

static int32_t SavePtk(const char *remoteDeviceId, const char *ptk)
{
    (void)remoteDeviceId;
    (void)ptk;
    return SOFTBUS_OK;
}

static int32_t SyncPtk(const char *remoteDeviceId)
{
    (void)remoteDeviceId;
    return SOFTBUS_OK;
}

static void AddSyncPtkListener(SyncPtkListener listener)
{
    (void)listener;
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

static bool IsHmlConnected(void)
{
    return false;
}

static void RegisterEnhanceManager(struct WifiDirectEnhanceManager *manager)
{
    (void)manager;
}

static void NotifyPtkSyncResult(const char *remoteDeviceId, int result)
{
    (void)remoteDeviceId;
    (void)result;
}

static int32_t Init(void)
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
    .isNoneLinkByType = IsNoneLinkByType,

    .isNegotiateChannelNeeded = IsNegotiateChannelNeeded,
    .refreshRelationShip = RefreshRelationShip,
    .linkHasPtk = LinkHasPtk,
    .savePTK = SavePtk,
    .syncPTK = SyncPtk,
    .addSyncPtkListener = AddSyncPtkListener,

    .isDeviceOnline = IsDeviceOnline,
    .getLocalIpByUuid = GetLocalIpByUuid,
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    .getRemoteUuidByIp = GetRemoteUuidByIp,

    .supportHmlTwo = SupportHmlTwo,
    .isWifiP2pEnabled = IsWifiP2pEnabled,
    .getStationFrequency = GetStationFrequency,
    .isHmlConnected = IsHmlConnected,

    .init = Init,
    .notifyOnline = NotifyOnline,
    .notifyOffline = NotifyOffline,
    .notifyRoleChange = NotifyRoleChange,
    .registerEnhanceManager = RegisterEnhanceManager,
    .notifyPtkSyncResult = NotifyPtkSyncResult,
};

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return &g_manager;
}
