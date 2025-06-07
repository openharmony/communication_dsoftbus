/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DISC_INTERFACE_STRUCT_H
#define DISC_INTERFACE_STRUCT_H

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup softbus_disc_manager
 * Inner Module.
 *
 */
typedef enum {
    MODULE_MIN = 1,
    MODULE_LNN = MODULE_MIN,
    MODULE_CONN = 2,
    MODULE_MAX = MODULE_CONN
} DiscModule;

typedef enum {
    LINK_STATUS_UP = 0,
    LINK_STATUS_DOWN,
} LinkStatus;

typedef enum {
    TYPE_LOCAL_DEVICE_NAME,
    TYPE_ACCOUNT,
} InfoTypeChanged;

/**
 * @ingroup softbus_disc_manager
 * Inner Callback.
 *
 */
typedef struct {
    void (*OnDeviceFound)(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions);
} DiscInnerCallback;

typedef struct {
    char bleMac[BT_MAC_LEN];
    char accountHash[MAX_ACCOUNT_HASH_LEN];
    char deviceIdHash[DISC_MAX_DEVICE_ID_LEN];
    uint8_t heartbeatValue[HB_HEARTBEAT_VALUE_LEN];
    uint32_t deviceTypeId;
    int32_t heartbeatVersion;
    int32_t heartbeatType;
    uint64_t nowTimes;
} RaiseHandDeviceInfo;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DISC_INTERFACE_STRUCT_H */