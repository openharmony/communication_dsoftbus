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
#ifndef LEGACY_BLE_CHANNEL_H
#define LEGACY_BLE_CHANNEL_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_conn_ble_connection.h"
#include "softbus_conn_interface.h"


#ifdef __cplusplus
extern "C" {
#endif

ConnBleConnection *LegacyBleCreateConnection(const char *addr, ConnSideType side,
    int32_t underlayerHandle, bool fastestConnectEnable);
ConnBleConnection *LegacyBleGetConnectionByHandle(int32_t underlayerHandle, ConnSideType side);
ConnBleConnection *LegacyBleGetConnectionById(uint32_t connectinId);
int32_t LegacyBleSaveConnection(ConnBleConnection *connection);
void LegacyBleReturnConnection(ConnBleConnection **connection);
void LegacyBleRemoveConnection(ConnBleConnection *connection);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_BLE_CONFLICT_H */