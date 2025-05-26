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
#ifndef LNN_BLE_LPDEVICE_STRUCT_H
#define LNN_BLE_LPDEVICE_STRUCT_H

#include "softbus_common.h"
#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SOFTBUS_SUPPORT_HEARTBEAT_TYPE = 0,
    SOFTBUS_SUPPORT_BURST_TYPE,
    SOFTBUS_SUPPORT_ALL_TYPE,
} LpFeatureType;

typedef struct {
    bool isOnline;
    char udid[UDID_BUF_LEN];
} LpDeviceStateInfo;

#ifdef __cplusplus
}
#endif

#endif