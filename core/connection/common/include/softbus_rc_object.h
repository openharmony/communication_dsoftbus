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
#ifndef SOFTBUS_RC_OBJECT_H
#define SOFTBUS_RC_OBJECT_H

#include <stdint.h>

#include "common_list.h"
#include "softbus_adapter_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SoftBusRcObject;
typedef struct SoftBusRcObject SoftBusRcObject;
typedef void (*SoftBusRcFreeHook)(SoftBusRcObject *object);

// name method pointer fields as upper camel case on purpose,
// as it will notice user that it is method, avoiding confusion and more readable
#define SOFT_BUS_RC_OBJECT_BASE                      \
    /* public */                                     \
    int32_t (*Lock)(SoftBusRcObject * self);         \
    void (*Unlock)(SoftBusRcObject * self);          \
    void (*Dereference)(SoftBusRcObject * *self);    \
    int32_t (*Reference)(SoftBusRcObject * selfPtr); \
                                                     \
    /* private */                                    \
    ListNode node;                                   \
    uint32_t id;                                     \
    SoftBusMutex mutex;                              \
    int32_t objectRc;                                \
    SoftBusRcFreeHook freehook;                      \
                                                     \
    /* concrete object identifier */                 \
    const char *name;

struct SoftBusRcObject {
    SOFT_BUS_RC_OBJECT_BASE
};

int32_t SoftBusRcObjectConstruct(const char *name, SoftBusRcObject *object, SoftBusRcFreeHook hook);
void SoftBusRcObjectDestruct(SoftBusRcObject *object);

#ifdef __cplusplus
}
#endif

#endif