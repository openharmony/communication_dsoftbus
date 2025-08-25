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

#ifndef SOFTBUS_CONN_BLE_MANAGER_H
#define SOFTBUS_CONN_BLE_MANAGER_H

#include "softbus_conn_ble_connection.h"
#include "legacy/softbus_hisysevt_connreporter.h"
#include "softbus_conn_ble_manager_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ConnBleSaveConnection(ConnBleConnection *connection);
void ConnBleRemoveConnection(ConnBleConnection *connection);
ConnBleConnection *ConnBleGetConnectionByAddr(const char *addr, ConnSideType side, BleProtocolType protocol);
ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId);
ConnBleConnection *ConnBleGetConnectionByHandle(int32_t underlayerHandle, ConnSideType side, BleProtocolType protocol);
// get connection with different address and same udid
ConnBleConnection *ConnBleGetConnectionByUdid(const char *addr, const char *udid, BleProtocolType protocol);
// get connection with same udid and client side
ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol);
void ConnBleReturnConnection(ConnBleConnection **connection);
void NotifyReusedConnected(uint32_t connectionId, uint16_t challengeCode);
int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time);
int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId);
int32_t ConnBleDumper(ListNode *connectionSnapshots);

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_MANAGER_H */
