/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef DISC_NSTACKX_ADAPTER_H
#define DISC_NSTACKX_ADAPTER_H

#include <stdint.h>
#include "disc_manager.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    INVALID_MODE = -1,
    ACTIVE_PUBLISH = 0,
    ACTIVE_DISCOVERY,
} DiscCoapMode;

typedef struct {
    bool isPublish;
    union {
        PublishOption publishOption;
        SubscribeOption subscribeOption;
    } option;
} DiscOption;

typedef struct {
    int32_t freq;
    DiscCoapMode mode;
    uint32_t capability;
    uint32_t allCap;
} DiscCoapOption;

int32_t DiscNstackxInit(void);
void DiscNstackxDeinit(void);

int32_t DiscCoapRegisterCb(const DiscInnerCallback *discCoapCb);
int32_t DiscCoapRegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t DiscCoapSetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t DiscCoapRegisterServiceData(const unsigned char *capabilityData, uint32_t dataLen, uint32_t capability);
int32_t DiscCoapRegisterCapabilityData(const unsigned char *capabilityData, uint32_t dataLen, uint32_t capability);
int32_t DiscCoapStartDiscovery(DiscCoapOption *option);
int32_t DiscCoapStopDiscovery(void);
void DiscCoapUpdateLocalIp(LinkStatus status);
void DiscCoapUpdateDevName(void);
void DiscCoapUpdateAccount(void);
int32_t DiscCoapSendRsp(const DeviceInfo *deviceInfo, uint8_t bType);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !DISC_NSTACKX_ADAPTER_H
