/*
* Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_TCP_CONNECTION_STRUCT_H
#define AUTH_TCP_CONNECTION_STRUCT_H

#include <stdint.h>
#include <stdbool.h>
#include "auth_common_struct.h"
#include "softbus_conn_interface_struct.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AUTH_INVALID_FD                    (-1)
#define TCP_KEEPALIVE_INTERVAL             2
#define TCP_KEEPALIVE_HIGH_COUNT           3
#define TCP_KEEPALIVE_MID_COUNT            3
#define TCP_KEEPALIVE_LOW_COUNT            5
#define TCP_KEEPALIVE_DEFAULT_COUNT        5
#define TCP_KEEPALIVE_HIGH_USER_TIMEOUT    (10 * 1000)
#define TCP_KEEPALIVE_MID_USER_TIMEOUT     (10 * 1000)
#define TCP_KEEPALIVE_LOW_USER_TIMEOUT     (15 * 1000)
#define TCP_KEEPALIVE_DEFAULT_USER_TIMEOUT (15 * 1000)

typedef struct {
   void (*onConnected)(ListenerModule module, int32_t fd, bool isClient);
   void (*onDisconnected)(ListenerModule module, int32_t fd);
   void (*onDataReceived)(ListenerModule module, int32_t fd, const AuthDataHead *head, const uint8_t *data);
} SocketCallback;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_TCP_CONNECTION_STRUCT_H */