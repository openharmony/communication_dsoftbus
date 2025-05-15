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

#ifndef CONNECTION_CLIENT_PROXY_H
#define CONNECTION_CLIENT_PROXY_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONNECT_STATE_SUCCESSED = 0,
    CONNECT_STATE_FAILED,
    CONNECT_STATE_DISCONNECTED,
} ConnectState;

int32_t ClientIpcOnConnectionStateChange(
    const char *pkgName, int32_t pid, uint32_t handle, int32_t state, int32_t reason);
int32_t ClientIpcOnAcceptConnect(const char *pkgName, int32_t pid, const char *name, uint32_t handle);
int32_t ClientIpcOnDataReceived(const char *pkgName, int32_t pid, uint32_t handle, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif