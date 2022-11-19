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

#ifndef DISC_BLE_H
#define DISC_BLE_H

#include "disc_ble_dispatcher.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

DiscoveryBleDispatcherInterface *DiscSoftBusBleInit(DiscInnerCallback *callback);
void DiscSoftBusBleDeinit(void);

// TEST FUNCTION
void PrintBleInfo(int32_t index);
void PrintDeviceInfo(const DeviceInfo *info);
int BleTest(int argc, const char **argv);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* DISC_BLE_H */