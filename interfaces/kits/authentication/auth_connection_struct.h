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

#ifndef AUTH_CONNECTION_STRUCT_H
#define AUTH_CONNECTION_STRUCT_H

#include <stdbool.h>
#include <stdint.h>

#include "auth_common_struct.h"
#include "auth_interface_struct.h"
#include "softbus_conn_interface_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
   uint64_t connId;
   AuthConnInfo connInfo;
   bool fromServer;
   AuthDataHead head;
   uint32_t len;
   uint8_t data[0];
} RepeatDeviceIdData;

typedef struct {
   void (*onConnectResult)(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo);
   void (*onDisconnected)(uint64_t connId, const AuthConnInfo *connInfo);
   void (*onDataReceived)(
       uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data);
} AuthConnListener;

typedef struct {
   int32_t fd;
   int32_t ret;
} AuthConnectResult;

#define CONN_INFO         "conn=%{public}s:%{public}u"
#define CONN_DATA(connId) GetConnTypeStr(connId), GetConnId(connId)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_CONNECTION_STRUCT_H */