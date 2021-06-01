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

int32_t DiscNstackxInit(void);
void DiscNstackxDeinit(void);

int32_t DiscCoapRegisterCb(const DiscInnerCallback *discCoapCb);
int32_t DiscCoapRegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t DiscCoapSetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t DiscCoapRegisterServiceData(const unsigned char *serviceData, uint32_t dataLen);
int32_t DiscCoapStartDiscovery(DiscCoapMode);
int32_t DiscCoapStopDiscovery(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !DISC_NSTACKX_ADAPTER_H
