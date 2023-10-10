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
#ifndef WIFI_CONFIG_INFO_H
#define WIFI_CONFIG_INFO_H

#include "info_container.h"

#ifdef __cplusplus
extern "C" {
#endif

enum WifiConfigInfoKey {
    WC_KEY_INVALID = 0,
    WC_KEY_VERSION = 1,
    WC_KEY_IS_P2P_CHANNEL_OPTIMIZE_ENABLE = 2,
    WC_KEY_IS_DBDC_SUPPORTED = 3,
    WC_KEY_IS_CSA_SUPPORTED = 4,
    WC_KEY_IS_RADAR_DETECTION_SUPPORTED = 5,
    WC_KEY_IS_DFS_P2P_SUPPORTED = 6,
    WC_KEY_IS_INDOOR_P2P_SUPPORTED = 7,
    WC_KEY_STA_CHANNEL = 8,
    WC_KEY_STA_PORTAL_STATE = 9,
    WC_KEY_STA_SSID = 10,
    WC_KEY_STA_BSSID = 11,
    WC_KEY_STA_INTERNET_STATE = 12,
    WC_KEY_P2P_CHANNEL_LIST = 13,
    WC_KEY_STA_PWD = 14,
    WC_KEY_STA_ENCRYPT_MODE = 15,
    WC_KEY_IS_CONNECTED_TO_HUAWEI_ROUTER = 16,
    WC_KEY_DEVICE_TYPE = 17,
    WC_KEY_IGNORE = 18,
    WC_KEY_DEVICE_ID = 19,
    WC_KEY_INTERFACE_INFO_ARRAY = 20,

    WC_KEY_MAX,
};

struct NegotiateMessage;
struct WifiConfigInfo {
    INFO_CONTAINER_BASE(WifiConfigInfo, WC_KEY_MAX);
};

int32_t WifiConfigInfoConstruct(struct WifiConfigInfo *self, uint8_t *cfg, size_t size);
void WifiConfigInfoDestruct(struct WifiConfigInfo *self);

#ifdef __cplusplus
}
#endif
#endif