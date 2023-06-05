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

#ifndef SOFTBUS_ADAPTER_BLE_CONFLICT_H
#define SOFTBUS_ADAPTER_BLE_CONFLICT_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t (*reuseConnection)(const char *address, const char *udid, uint32_t requestId);
    bool (*postBytes)(int32_t underlayerHandle, uint8_t *data, uint32_t dataLen);
    void (*disconnect)(int32_t underlayerHandle, bool isForce);
    void (*occupy)(const char *udid, int32_t timeout);
    void (*cancelOccupy)(const char *udid);
    int32_t (*getConnection)(const char *udid);
} SoftBusBleConflictListener;

void SoftbusBleConflictRegisterListener(SoftBusBleConflictListener *listener);
void SoftbusBleConflictNotifyConnectResult(int32_t requestId, int32_t underlayerHandle, bool status);
void SoftbusBleConflictNotifyDateReceive(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen);
void SoftbusBleConflictNotifyDisconnect(const char *addr, const char *udid);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_BLE_CONFLICT_H */