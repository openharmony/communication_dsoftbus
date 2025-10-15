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

#ifndef DISC_MANAGER_STRUCT_H
#define DISC_MANAGER_STRUCT_H

#include <stdint.h>

#include "disc_interface_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define CAPABILITY_NUM                  1
#define CAPABILITY_MAX_BITNUM           17

typedef struct {
    int32_t freq;
    uint32_t capabilityBitmap[CAPABILITY_NUM];
    uint8_t *capabilityData;
    uint32_t dataLen;
    bool ranging;
} PublishOption;

typedef struct {
    bool isSameAccount;
    bool isWakeRemote;
    int32_t freq;
    uint32_t capabilityBitmap[CAPABILITY_NUM];
    uint32_t dataLen;
    uint8_t *capabilityData;
} SubscribeOption;

typedef enum {
    PUBLISH_FUNC = 0,
    UNPUBLISH_FUNC = 1,
    STARTDISCOVERTY_FUNC = 2,
    STOPDISCOVERY_FUNC = 3
} InterfaceFuncType;

typedef struct {
    int32_t (*Publish)(const PublishOption *option);
    int32_t (*StartScan)(const PublishOption *option);
    int32_t (*Unpublish)(const PublishOption *option);
    int32_t (*StopScan)(const PublishOption *option);
    int32_t (*StartAdvertise)(const SubscribeOption *option);
    int32_t (*Subscribe)(const SubscribeOption *option);
    int32_t (*Unsubscribe)(const SubscribeOption *option);
    int32_t (*StopAdvertise)(const SubscribeOption *option);
    void (*LinkStatusChanged)(LinkStatus status, int32_t ifnameIdx);
    void (*UpdateLocalDeviceInfo)(InfoTypeChanged type);
} DiscoveryFuncInterface;

typedef struct {
    int32_t (*OnServerDeviceFound)(const char *packageName, const DeviceInfo *device,
                                   const InnerDeviceInfoAddtions *additions, int32_t subscribeId);
} IServerDiscInnerCallback;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISC_MANAGER_STRUCT_H */