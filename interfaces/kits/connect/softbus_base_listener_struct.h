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

#ifndef SOFTBUS_BASE_LISTENER_STRUCT_H
#define SOFTBUS_BASE_LISTENER_STRUCT_H

#include "stdint.h"
#include "softbus_conn_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

// NOTICE: all element MUST be bitmap mode
typedef enum {
    READ_TRIGGER = 1,
    WRITE_TRIGGER = 2,
    EXCEPT_TRIGGER = 4,
    RW_TRIGGER = READ_TRIGGER | WRITE_TRIGGER,
} TriggerType;

typedef enum {
    UNSET_MODE,
    CLIENT_MODE,
    SERVER_MODE,
} ModeType;

typedef struct {
    int32_t (*onConnectEvent)(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr);
    int32_t (*onDataEvent)(ListenerModule module, int32_t events, int32_t fd);
} SoftbusBaseListener;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_BASE_LISTENER_STRUCT_H */