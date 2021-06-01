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

#ifndef SOFTBUS_BASE_LISTENER_H
#define SOFTBUS_BASE_LISTENER_H

#include <pthread.h>

#include "common_list.h"
#include "softbus_def.h"
#include "softbus_utils.h"
#include "sys/select.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    READ_TRIGGER,
    WRITE_TRIGGER,
    EXCEPT_TRIGGER,
    RW_TRIGGER,
} TriggerType;

typedef enum {
    UNSET_MODE,
    CLIENT_MODE,
    SERVER_MODE,
} ModeType;

typedef enum {
    PROXY = 0,
    AUTH,
    DIRECT_CHANNEL_CLIENT,
    DIRECT_CHANNEL_SERVER,
    UNUSE_BUTT,
} ListenerModule;

typedef struct {
    int32_t (*onConnectEvent)(int32_t events, int32_t cfd, const char *ip);
    int32_t (*onDataEvent)(int32_t events, int32_t fd);
} SoftbusBaseListener;

int32_t GetSoftbusBaseListener(ListenerModule module, SoftbusBaseListener *listener);
int32_t SetSoftbusBaseListener(ListenerModule module, const SoftbusBaseListener *listener);
int32_t StartBaseClient(ListenerModule module);
int32_t StartBaseListener(ListenerModule module, const char *ip, int32_t port, ModeType modeType);
int32_t StopBaseListener(ListenerModule module);
void ResetBaseListener(ListenerModule module);
void ResetBaseListenerSet(ListenerModule module);
void DestroyBaseListener(ListenerModule module);

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType triggerType);
int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType triggerType);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_BASE_LISTENER_H */