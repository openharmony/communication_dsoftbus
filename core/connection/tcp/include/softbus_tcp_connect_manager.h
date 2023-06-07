/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SOFTBUS_TCP_CONNECT_MANAGER_H
#define SOFTBUS_TCP_CONNECT_MANAGER_H

#include <sys/select.h>

#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_base_listener.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

uint32_t CalTcpConnectionId(int32_t fd);

uint32_t TcpGetConnNum(void);

int32_t TcpConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

int32_t TcpDisconnectDevice(uint32_t connectionId);

int32_t TcpDisconnectDeviceNow(const ConnectOption *option);

int32_t TcpPostBytes(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq);

int32_t TcpGetConnectionInfo(uint32_t connectionId, ConnectionInfo *Info);

int32_t TcpStartListening(const LocalListenerInfo *info);

int32_t TcpStopListening(const LocalListenerInfo *info);

ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback);

int32_t ConnGetSocketError(int32_t fd);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif