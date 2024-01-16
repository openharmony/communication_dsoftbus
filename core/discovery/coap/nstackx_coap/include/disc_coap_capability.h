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

#ifndef DISC_COAP_CAPABILITY_H
#define DISC_COAP_CAPABILITY_H

#include "nstackx.h"
#include "disc_interface.h"
#include "softbus_common.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t DiscCoapAssembleCapData(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData,
    uint32_t outLen);
void DiscFillBtype(uint32_t capability, uint32_t allCap, NSTACKX_DiscoverySettings *discSet);
int32_t DiscCoapProcessDeviceInfo(const NSTACKX_DeviceInfo *nstackxInfo, DeviceInfo *devInfo,
    const DiscInnerCallback *discCb);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // DISC_COAP_CAPABILITY_H