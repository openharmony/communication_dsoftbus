/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISC_MANAGER_H
#define DISC_MANAGER_H

#include "disc_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define CAPABILITY_NUM 1
#define CAPABILITY_MAX_BITNUM 8

typedef struct {
    int32_t freq;
    uint32_t capabilityBitmap[CAPABILITY_NUM];
    unsigned char *capabilityData;
    uint32_t dataLen;
} PublishOption;

typedef struct {
    int32_t freq;
    bool isSameAccount;
    bool isWakeRemote;
    uint32_t capabilityBitmap[CAPABILITY_NUM];
    unsigned char *capabilityData;
    uint32_t dataLen;
} SubscribeOption;

typedef struct {
    int32_t (*Publish)(const PublishOption *option);
    int32_t (*StartScan)(const PublishOption *option);
    int32_t (*Unpublish)(const PublishOption *option);
    int32_t (*StopScan)(const PublishOption *option);
    int32_t (*StartAdvertise)(const SubscribeOption *option);
    int32_t (*Subscribe)(const SubscribeOption *option);
    int32_t (*Unsubscribe)(const SubscribeOption *option);
    int32_t (*StopAdvertise)(const SubscribeOption *option);
    void (*LinkStatusChanged)(LinkStatus status);
} DiscoveryFuncInterface;

typedef struct {
    int32_t (*OnServerDeviceFound)(const char *packageName, const DeviceInfo *device);
} IServerDiscInnerCallback;

int32_t DiscPublishService(const char *packageName, const PublishInfo *info);
int32_t DiscUnPublishService(const char *packageName, int32_t publishId);
int32_t DiscStartDiscovery(const char *packageName, const SubscribeInfo *info, const IServerDiscInnerCallback *cb);
int32_t DiscStopDiscovery(const char *packageName, int32_t subscribeId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISC_MANAGER_H */