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
#ifndef WIFI_DIRECT_ADAPTER_H
#define WIFI_DIRECT_ADAPTER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_CLIENT_SIZE 10
#define P2P_INTERFACE_NAME_LEN 16

struct WifiDirectP2pDeviceInfo {
    uint8_t address[MAC_ADDR_ARRAY_SIZE];
};

struct WifiDirectP2pGroupInfo {
    bool isGroupOwner;
    int32_t frequency;
    char interface[P2P_INTERFACE_NAME_LEN];
    struct WifiDirectP2pDeviceInfo groupOwner;
    int32_t clientDeviceSize;
    struct WifiDirectP2pDeviceInfo clientDevices[P2P_CLIENT_SIZE];
};

enum WifiDirectP2pState {
    P2P_ENABLED = 0,
    P2P_DISABLED = 1,
};

enum WifiDirectP2pConnectState {
    WIFI_DIRECT_P2P_CONNECTING,
    WIFI_DIRECT_P2P_CONNECTED,
    WIFI_DIRECT_P2P_CONNECTION_FAIL,
};

enum WifiDirectP2pAdapterEvent {
    WIFI_P2P_ADAPTER_EVENT_START = 0,
    WIFI_P2P_ADAPTER_EVENT_STATE_CHANGED = WIFI_P2P_ADAPTER_EVENT_START + 1,
    WIFI_P2P_ADAPTER_EVENT_CONNECTION_CHANGED = WIFI_P2P_ADAPTER_EVENT_START + 2,
    WIFI_P2P_ADAPTER_EVENT_CONNECT_STATE_CHANGED = WIFI_P2P_ADAPTER_EVENT_START + 3,
    WIFI_P2P_ADAPTER_EVENT_RPT_STATE_CHANGED = WIFI_P2P_ADAPTER_EVENT_START + 4,
    WIFI_P2P_ADAPTER_EVENT_END,

    WIFI_HML_ADAPTER_EVENT_START = 10,
    WIFI_HML_ADAPTER_EVENT_STATE_CHANGED = WIFI_HML_ADAPTER_EVENT_START + 1,
    WIFI_HML_ADAPTER_CONNECTION_CHANGED = WIFI_HML_ADAPTER_EVENT_START + 2,
    WIFI_HML_ADAPTER_NOTIFY_RESULT = WIFI_HML_ADAPTER_EVENT_START + 3,
    WIFI_HML_ADAPTER_EVENT_END,
};

struct WifiDirectP2pAdapter {
    bool (*isWifiP2pEnabled)(void);
    bool (*isWifiConnected)(void);
    bool (*isWifiApEnabled)(void);
    bool (*isWideBandSupported)(void);

    int32_t (*getChannel5GListIntArray)(int32_t *array, size_t *size);
    int32_t (*getStationFrequency)(void);
    int32_t (*getStationFrequencyWithFilter)(void);
    int32_t (*getRecommendChannel)(void);
    int32_t (*getSelfWifiConfigInfo)(uint8_t *config, size_t *configSize);
    int32_t (*setPeerWifiConfigInfo)(const char *config);
    int32_t (*getGroupConfig)(char *groupConfigString, size_t *groupConfigStringSize);
    int32_t (*getGroupInfo)(struct WifiDirectP2pGroupInfo **groupInfo);
    int32_t (*getIpAddress)(char *ipString, int32_t ipStringSize);
    int32_t (*getMacAddress)(char *macString, size_t macStringSize);
    int32_t (*getDynamicMacAddress)(char *macString, size_t macStringSize);
    int32_t (*requestGcIp)(const char *macString, char *ipString, size_t ipStringSize);
    int32_t (*configGcIp)(const char *interface, const char *ip);

    int32_t (*createGroup)(int32_t frequency, bool wideBandSupported);
    int32_t (*connectGroup)(char *groupConfigString, bool isLegacyGo);
    int32_t (*shareLinkReuse)(void);
    int32_t (*shareLinkRemoveGroupAsync)(const char *interface);
    int32_t (*shareLinkRemoveGroupSync)(const char *interface);
    int32_t (*removeGroup)(const char *interface);
    void (*setWifiLinkAttr)(const char *interface, const char *attr);

    int32_t (*getInterfaceCoexistCap)(char **cap);
    int32_t (*getSelfWifiConfigInfoV2)(uint8_t *cfg, size_t *size);
    int32_t (*setPeerWifiConfigInfoV2)(const uint8_t *cfg, size_t size);
    int32_t (*getRecommendChannelV2)(const char *jsonString, char *result, size_t resultSize);
    int (*setConnectNotify)(const char *notify);

    int32_t (*getBaseMac)(const char *interface, uint32_t cap, char baseMac[], size_t baseMacLen);
    bool (*isThreeVapConflict)(void);
};

struct WifiDirectP2pAdapter* GetWifiDirectP2pAdapter(void);

#ifdef __cplusplus
}
#endif
#endif