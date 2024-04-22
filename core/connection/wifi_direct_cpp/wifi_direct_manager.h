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
#include "softbus_base_listener.h"
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectStatusListener {
    void (*onLocalRoleChange)(enum WifiDirectRole oldRole, enum WifiDirectRole newRole);
    void (*onDeviceOnLine)(const char *remoteMac, const char *remoteIp, const char *remoteUuid);
    void (*onDeviceOffLine)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp);
};

struct WifiDirectManager {
    uint32_t (*getRequestId)(void);
    ListenerModule (*allocateListenerModuleId)(void);
    void (*freeListenerModuleId)(ListenerModule moduleId);

    int32_t (*connectDevice)(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback);
    int32_t (*disconnectDevice)(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback);
    void (*registerStatusListener)(struct WifiDirectStatusListener *listener);
    int32_t (*prejudgeAvailability)(const char *remoteNetworkId, enum WifiDirectLinkType linkType);

    bool (*isDeviceOnline)(const char *remoteMac);
    int32_t (*getLocalIpByUuid)(const char *uuid, char *localIp, int32_t localIpSize);
    int32_t (*getLocalIpByRemoteIp)(const char *remoteIp, char *localIp, int32_t localIpSize);
    int32_t (*getRemoteUuidByIp)(const char *remoteIp, char *uuid, int32_t uuidSize);

    bool (*supportHmlTwo)(void);
    bool (*isWifiP2pEnabled)(void);
    int (*getStationFrequency)(void);

    int32_t (*init)(void);

    /* for private inner usage */
    void (*notifyOnline)(const char *remoteMac, const char *remoteIp, const char *remoteUuid);
    void (*notifyOffline)(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp);
    void (*notifyRoleChange)(enum WifiDirectRole oldRole, enum WifiDirectRole newRole);
};

/* singleton */
struct WifiDirectManager* GetWifiDirectManager(void);

#ifdef __cplusplus
}
#endif
#endif