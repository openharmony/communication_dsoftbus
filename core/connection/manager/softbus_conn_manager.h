/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CONN_MANAGER_H
#define SOFTBUS_CONN_MANAGER_H

#include "softbus_conn_interface.h"

#define CONNECT_TYPE_SHIFT 16

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int32_t (*ConnectDevice)(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);
    int32_t (*PostBytes)(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag);
    int32_t (*DisconnectDevice)(uint32_t connectionId);
    int32_t (*DisconnectDeviceNow)(const ConnectOption *option);
    int32_t (*GetConnectionInfo)(uint32_t connectionId, ConnectionInfo *info);
    int32_t (*StartLocalListening)(const LocalListenerInfo *info);
    int32_t (*StopLocalListening)(const LocalListenerInfo *info);
} ConnectFuncInterface;

#define MAGIC_NUMBER  0xBABEFACE
typedef struct {
    int32_t magic;
    int32_t module;
    int64_t seq;
    int32_t flag;
    int32_t len;
} ConnPktHead;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
