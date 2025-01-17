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
#ifndef WIFI_DIRECT_MANAGER_H
#define WIFI_DIRECT_MANAGER_H

#include "common_list.h"
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectStatusListener {
    void (*onLocalRoleChange)(enum WifiDirectRole oldRole, enum WifiDirectRole newRole);
    void (*onDeviceOnLine)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource);
    void (*onDeviceOffLine)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp);
    void (*onConnectedForSink)(const struct WifiDirectSinkLink *link);
    void (*onDisconnectedForSink)(const struct WifiDirectSinkLink *link);
};

typedef void (*SyncPtkListener)(const char *remoteDeviceId, int result);
typedef void (*PtkMismatchListener)(const char *remoteNetworkId, uint32_t len, int32_t reason);
struct WifiDirectEnhanceManager {
    int32_t (*savePTK)(const char *remoteDeviceId, const char *ptk);
    int32_t (*syncPTK)(const char *remoteDeviceId);
};

struct WifiDirectManager {
    uint32_t (*getRequestId)(void);
    int32_t (*allocateListenerModuleId)(void);
    void (*freeListenerModuleId)(int32_t moduleId);

    int32_t (*connectDevice)(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback);
    int32_t (*cancelConnectDevice)(const struct WifiDirectConnectInfo *info);
    int32_t (*disconnectDevice)(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback);
    int32_t (*forceDisconnectDevice)(
        struct WifiDirectForceDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback);
    int32_t (*forceDisconnectDeviceSync)(enum WifiDirectLinkType wifiDirectLinkType);
    void (*registerStatusListener)(struct WifiDirectStatusListener *listener);
    int32_t (*prejudgeAvailability)(const char *remoteNetworkId, enum WifiDirectLinkType linkType);
    bool (*isNoneLinkByType)(enum WifiDirectLinkType linkType);

    bool (*isNegotiateChannelNeeded)(const char *remoteNetworkId, enum WifiDirectLinkType linkType);
    void (*refreshRelationShip)(const char *remoteUuid, const char *remoteMac);
    bool (*linkHasPtk)(const char *remoteDeviceId);
    int32_t (*savePTK)(const char *remoteDeviceId, const char *ptk);
    int32_t (*syncPTK)(const char *remoteDeviceId);
    void (*addSyncPtkListener)(SyncPtkListener listener);
    void (*addPtkMismatchListener)(PtkMismatchListener listener);

    bool (*isDeviceOnline)(const char *remoteMac);
    int32_t (*getLocalIpByUuid)(const char *uuid, char *localIp, int32_t localIpSize);
    int32_t (*getLocalIpByRemoteIp)(const char *remoteIp, char *localIp, int32_t localIpSize);
    int32_t (*getRemoteUuidByIp)(const char *remoteIp, char *uuid, int32_t uuidSize);
    int32_t (*getLocalAndRemoteMacByLocalIp)(const char *localIp, char *localMac, size_t localMacSize, char *remoteMac,
        size_t remoteMacSize);

    bool (*supportHmlTwo)(void);
    bool (*isWifiP2pEnabled)(void);
    int (*getStationFrequency)(void);
    bool (*isHmlConnected)(void);
    HmlCapabilityCode (*getHmlCapabilityCode)(void);

    int32_t (*init)(void);

    /* for private inner usage */
    void (*notifyOnline)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource);
    void (*notifyOffline)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp);
    void (*notifyRoleChange)(enum WifiDirectRole oldRole, enum WifiDirectRole newRole);
    void (*notifyConnectedForSink)(const struct WifiDirectSinkLink *link);
    void (*notifyDisconnectedForSink)(const struct WifiDirectSinkLink *link);
    void (*registerEnhanceManager)(struct WifiDirectEnhanceManager *manager);
    void (*notifyPtkSyncResult)(const char *remoteDeviceId, int result);
    void (*notifyPtkMismatch)(const char *remoteNetworkId, uint32_t len, int32_t reason);
};

/* singleton */
struct WifiDirectManager* GetWifiDirectManager(void);

#ifdef __cplusplus
}
#endif
#endif
