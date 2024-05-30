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

#ifndef DISC_VIRTUAL_LINK_BLE_H
#define DISC_VIRTUAL_LINK_BLE_H

#include "disc_ble_dispatcher.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

DiscoveryBleDispatcherInterface *DiscVLinkBleInit(DiscInnerCallback *discInnerCb);
void DiscVLinkBleDeinit(void);
int32_t DiscVLinkBleEventInit(void);
void DiscVLinkBleEventDeinit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DISC_VIRTUAL_LINK_BLE_H */