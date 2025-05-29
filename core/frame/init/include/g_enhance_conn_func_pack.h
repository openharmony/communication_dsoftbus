/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef G_ENHANCE_CONN_FUNC_PACK_H
#define G_ENHANCE_CONN_FUNC_PACK_H

#include <stdint.h>
#include <stdbool.h>

#include "softbus_adapter_ble_conflict_struct.h"
#include "softbus_common.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_conn_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ConnCoapStartServerListenPacked(void);
void ConnCoapStopServerListenPacked(void);
void SoftbusBleConflictNotifyDisconnectPacked(const char *addr, const char *udid);
void SoftbusBleConflictNotifyDateReceivePacked(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen);
void SoftbusBleConflictNotifyConnectResultPacked(uint32_t requestId, int32_t underlayerHandle, bool status);
void SoftbusBleConflictRegisterListenerPacked(SoftBusBleConflictListener *listener);
int32_t ConnBleDirectInitPacked(void);
bool ConnBleDirectIsEnablePacked(BleProtocolType protocol);
int32_t ConnBleDirectConnectDevicePacked(const ConnectOption *option, uint32_t reqId, const ConnectResult* result);
ConnectFuncInterface *ConnSleInitPacked(const ConnectCallback *callback);
int32_t ConnDirectConnectDevicePacked(const ConnectOption *option, uint32_t reqId, const ConnectResult* result);

#ifdef __cplusplus
}
#endif

#endif