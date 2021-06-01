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

#ifndef CLIENT_BUS_CENTER_H
#define CLIENT_BUS_CENTER_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode);
int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode);
int32_t LnnOnNodeOnlineStateChanged(bool isOnline, void *info);
int32_t LnnOnNodeBasicInfoChanged(void *info, int32_t type);

#ifdef __cplusplus
}
#endif
#endif
