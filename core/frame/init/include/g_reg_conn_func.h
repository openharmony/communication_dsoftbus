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

#ifndef G_REG_CONN_FUNC_H
#define G_REG_CONN_FUNC_H

#include "g_enhance_conn_func.h"
#include "softbus_common.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_conn_ble_connection_struct.h"
#include "softbus_base_listener_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ConnBleConnection *(*ConnBleGetConnectionByHandleFunc)(
    int32_t underlayerHandle, ConnSideType side, BleProtocolType protocol);
typedef bool (*CheckActiveConnectionFunc)(const ConnectOption *info, bool needOccupy);
typedef uint32_t (*ConnGetNewRequestIdFunc)(ConnModule moduleId);
typedef int32_t (*DelTriggerFunc)(ListenerModule module, int32_t fd, TriggerType trigger);
typedef uint32_t (*CreateListenerModuleFunc)(void);
typedef int32_t (*StartBaseClientFunc)(ListenerModule module, const SoftbusBaseListener *listener);
typedef int32_t (*AddTriggerFunc)(ListenerModule module, int32_t fd, TriggerType trigger);
typedef struct TagConnOpenFuncList {
    // ble
    ConnBleGetConnectionByHandleFunc connBleGetConnectionByHandle;

    // manager
    CheckActiveConnectionFunc checkActiveConnection;
    ConnGetNewRequestIdFunc connGetNewRequestId;

    // common
    DelTriggerFunc delTrigger;
    CreateListenerModuleFunc createListenerModule;
    StartBaseClientFunc startBaseClient;
    AddTriggerFunc addTrigger;
} ConnOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif