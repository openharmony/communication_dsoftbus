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

#ifndef LNN_FEATURE_CAPABILITY_H
#define LNN_FEATURE_CAPABILITY_H

#include <stdint.h>
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BIT_WIFI_P2P_REUSE = 1,
    BIT_BR_DUP,
    BIT_WIFI_DIRECT_TLV_NEGOTIATION,
    BIT_META_NODE_CAPABILITY,
    BIT_INFO_COMPRESS,
    BIT_SUPPOURT_EX_CAPABILITY,
    BIT_WIFI_DIRECT_NO_DISCONNECT_RESP,
    BIT_SUPPORT_UNIFORM_NAME_CAPABILITY,
    BIT_BLE_ONLINE_REUSE_CAPABILITY,
    BIT_COC_CONNECT_CAPABILITY,
    BIT_BLE_SUPPORT_LP_HEARTBEAT, // support burst and lowpower
    BIT_BLE_DIRECT_ONLINE,
    BIT_BLE_DIRECT_CONNECT_CAPABILITY,
    BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY,
    BIT_BLE_TRIGGER_CONNECTION,
    BIT_SUPPORT_THREE_STATE,
    BIT_CLOUD_SYNC_DEVICE_INFO,
    BIT_FEATURE_COUNT,
} FeatureCapability;

uint64_t LnnGetFeatureCapabilty(void);
bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit);
int32_t LnnSetFeatureCapability(uint64_t *feature, FeatureCapability capaBit);
int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit);

#ifdef __cplusplus
}
#endif

#endif // LNN_FEATURE_CAPABILITY_H