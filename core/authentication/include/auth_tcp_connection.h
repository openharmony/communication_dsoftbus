/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AUTH_TCP_CONNECTION_H
#define AUTH_TCP_CONNECTION_H

#include "auth_connection.h"
#include "auth_tcp_connection_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SetSocketCallback(const SocketCallback *cb);
void UnsetSocketCallback(void);

// connect succ, return fd; otherwise, return -1.
int32_t SocketConnectDeviceWithAllIp(const char *localIp, const char *remoteIp, int32_t port, bool isBlockMode);
int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode, int32_t ifnameIdx);
int32_t SocketSetDevice(int32_t fd, bool isBlockMode);
void StopSessionKeyListening(int32_t fd);
int32_t NipSocketConnectDevice(ListenerModule module, const char *addr, int32_t port, bool isBlockMode);

void SocketDisconnectDevice(ListenerModule module, int32_t fd);

int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data);
int32_t SocketGetConnInfo(int32_t fd, AuthConnInfo *connInfo, bool *isServer, int32_t ifnameIdx);

int32_t StartSocketListening(ListenerModule module, const LocalListenerInfo *info);
void StopSocketListening(ListenerModule moduleId);

int32_t AuthSetTcpKeepaliveOption(int32_t fd, ModeCycle cycle);
bool IsExistAuthTcpConnFdItemByConnId(int32_t fd);
void DeleteAuthTcpConnFdItemByConnId(int32_t fd);
int32_t TryDeleteAuthTcpConnFdItemByConnId(int32_t fd);
int32_t AuthTcpConnFdLockInit(void);
void AuthTcpConnFdLockDeinit(void);
bool RequireAuthTcpConnFdListLock(void);
void ReleaseAuthTcpConnFdListLock(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_TCP_CONNECTION_H */
