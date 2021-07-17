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

#ifndef SOFTBUS_CLIENT_EVENT_MANAGER_H
#define SOFTBUS_CLIENT_EVENT_MANAGER_H

#include "softbus.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int EventClientInit(void);
void EventClientDeinit(void);
int RegisterEventCallback(enum SoftBusEvent event, EventCallback cb, void *userData);
void CLIENT_NotifyObserver(enum SoftBusEvent event, void *arg, unsigned int argLen);

#ifdef __cplusplus
}
#endif

#endif
