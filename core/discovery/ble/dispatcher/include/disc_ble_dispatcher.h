/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DISC_BLE_DISPATCHER_H
#define DISC_BLE_DISPATCHER_H

#include "disc_manager.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    bool (*IsConcern)(uint32_t capability);
    DiscoveryFuncInterface *mediumInterface;
} DiscoveryBleDispatcherInterface;

DiscoveryFuncInterface *DiscBleInit(DiscInnerCallback *discInnerCb);
// for test
DiscoveryFuncInterface *DiscBleInitForTest(DiscoveryBleDispatcherInterface *interfaceA,
    DiscoveryBleDispatcherInterface *interfaceB);
void DiscBleDeinit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* DISC_BLE_DISPATCHER_H */