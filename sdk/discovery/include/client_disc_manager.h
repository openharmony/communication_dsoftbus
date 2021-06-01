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

#ifndef SOFTBUS_CLIENT_SERVICE_MANAGER_H
#define SOFTBUS_CLIENT_SERVICE_MANAGER_H

#include "discovery_service.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t DiscClientInit(void);
int32_t DiscClientDeInit(void);

void DiscClientOnDeviceFound(const DeviceInfo *device);
void DiscClientOnDiscoverySuccess(int32_t subscribeId);
void DiscClientOnDiscoverFailed(int32_t subscribeId, DiscoveryFailReason failReason);
void DiscClientOnPublishSuccess(int32_t publishId);
void DiscClientOnPublishFail(int32_t publishId, PublishFailReason reason);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CLIENT_SERVICE_MANAGER_H
