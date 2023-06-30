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
#ifndef WIFI_DIRECT_INTENT_H
#define WIFI_DIRECT_INTENT_H

#include "wifi_direct_types.h"
#include "info_container.h"

#ifdef __cplusplus
extern "C" {
#endif

enum WifiDirectIntentKey {
    INTENT_KEY_ACTION = 0,
    INTENT_KEY_P2P_STATE = 1,
    INTENT_KEY_P2P_CONNECT_STATE = 2,
    INTENT_KEY_P2P_GROUP_INFO = 3,
    INTENT_KEY_HML_STATE = 4,
    INTENT_KEY_HML_GROUP_INFO = 5,
    INTENT_KEY_NETWORK_INFO = 6,
    INTENT_KEY_EXTRA_INFO = 7,
    INTENT_KEY_WIFI_RPT_STATE = 8,
    INTENT_KEY_INTERFACE_NAME = 9,
    INTENT_KEY_HML_NOTIFY_RESULT = 10,
    INTENT_KEY_MAX
};

struct WifiDirectIntent {
    INFO_CONTAINER_BASE(WifiDirectIntent, INTENT_KEY_MAX);
};

void WifiDirectIntentConstructor(struct WifiDirectIntent* self);
void WifiDirectIntentDestructor(struct WifiDirectIntent* self);
struct WifiDirectIntent* WifiDirectIntentNew(void);
void WifiDirectIntentDelete(struct WifiDirectIntent* self);

#ifdef __cplusplus
}
#endif
#endif