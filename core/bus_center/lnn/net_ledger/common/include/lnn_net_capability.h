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

#ifndef LNN_NET_CAPABILITY_H
#define LNN_NET_CAPABILITY_H

#include <stdint.h>
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

bool LnnHasCapability(uint32_t capability, NetCapability type);
uint32_t LnnGetNetCapabilty(void);
int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type);
int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type);

#ifdef __cplusplus
}
#endif

#endif // LNN_NET_CAPABILITY_H