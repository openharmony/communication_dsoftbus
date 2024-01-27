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
#ifndef WIFI_DIRECT_RESOURCE_MANAGER_H
#define WIFI_DIRECT_RESOURCE_MANAGER_H

#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "wifi_direct_types.h"
#include "data/interface_info.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ResourceManagerListener {
    void (*onInterfaceInfoChange)(struct InterfaceInfo *info);
};

struct ResourceManager {
    int32_t (*initWifiDirectInfo)(void);
    struct InterfaceInfo* (*getInterfaceInfo)(const char *interface);
    void (*notifyInterfaceInfoChange)(struct InterfaceInfo *info);
    bool (*isInterfaceAvailable)(const char *interface, bool forShare);
    bool (*isStationAndHmlDBAC)(void);
    void (*registerListener)(struct ResourceManagerListener *listener);
    int32_t (*getAllInterfacesSimpleInfo)(struct InterfaceInfo **infoArray, int32_t *infoArraySize);
    int32_t (*getAllInterfacesInfo)(struct InterfaceInfo **infoArray, int32_t *infoArraySize);
    int32_t (*getAllInterfacesNameAndMac)(struct InterfaceInfo **infoArray, int32_t *infoArraySize);
    void (*dump)(int32_t fd);

    SoftBusMutex mutex;
    struct ListNode interfaces;
    int32_t count;
    struct ResourceManagerListener listener;
    bool isInited;
};

struct ResourceManager* GetResourceManager(void);

int32_t ResourceManagerInit(void);

#ifdef __cplusplus
}
#endif
#endif