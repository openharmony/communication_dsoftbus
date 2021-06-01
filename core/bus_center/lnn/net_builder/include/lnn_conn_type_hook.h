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

#ifndef LNN_CONN_TYPE_HOOK_H
#define LNN_CONN_TYPE_HOOK_H

#include <stdint.h>
#include "lnn_state_machine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NETWORK_TYPE_ACTIVE,
    NETWORK_TYPE_SELF
} NetworkType;

#define JOIN_DISCOVERY_TIMEOUT_LEN (60 * 1000UL)

typedef struct {
    int32_t (*preprocess)(const ConnectionAddr *addr, FsmStateMachine *fsm, NetworkType type);
    void (*shutdown)(const ConnectionAddr *addr);
} ConnTypeHook;

void LnnInitIpHook(void);

#ifdef __cplusplus
}
#endif

#endif
