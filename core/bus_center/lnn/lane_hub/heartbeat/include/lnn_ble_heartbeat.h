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

#ifndef LNN_BLE_HEARTBEAT_H
#define LNN_BLE_HEARTBEAT_H

#include <stdint.h>
#include "lnn_heartbeat_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnRegistBleHeartbeatMediumMgr(void);
int32_t HbUpdateBleScanFilter(int32_t listenerId, LnnHeartbeatType type);
int32_t HbGenerateBitPosition(int32_t min, int32_t max, int64_t seed, int32_t *randPos, int32_t num);
#ifdef __cplusplus
}
#endif
#endif /* LNN_BLE_HEARTBEAT_H */
