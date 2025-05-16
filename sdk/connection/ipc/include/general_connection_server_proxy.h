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

#ifndef CONNECTION_SERVER_PROXY_H
#define CONNECTION_SERVER_PROXY_H

#include <stdint.h>

#include "softbus_connection.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t ConnectionServerProxyInit(void);
void ConnectionServerProxyDeInit(void);
int32_t ServerIpcCreateServer(const char *pkgName, const char *name);
int32_t ServerIpcRemoveServer(const char *pkgName, const char *name);
int32_t ServerIpcConnect(const char *pkgName, const char *name, const Address *address);
int32_t ServerIpcDisconnect(uint32_t handle);
int32_t ServerIpcSend(uint32_t handle, const uint8_t *data, uint32_t len);
int32_t ServerIpcGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // CONNECTION_SERVER_PROXY_H
