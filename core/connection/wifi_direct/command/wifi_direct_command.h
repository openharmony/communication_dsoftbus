/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECT_COMMAND_H
#define WIFI_DIRECT_COMMAND_H

#include "common_list.h"
#include "wifi_direct_types.h"
#include "processor/wifi_direct_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_EXECUTE_TIMES 5

enum WifiDirectCommandType {
    COMMAND_TYPE_CONNECT = 0,
    COMMAND_TYPE_DISCONNECT = 1,
    COMMAND_TYPE_NEGO_MESSAGE = 2,
    COMMAND_TYPE_DEFAULT_TRIGGER_MESSAGE = 3,
    COMMAND_TYPE_BLE_TRIGGER_MESSAGE = 4,
};

#define WIFI_DIRECT_COMMAND_BASE                                                                  \
    void (*execute)(struct WifiDirectCommand *base);                                              \
    void (*onSuccess)(struct WifiDirectCommand *base, struct NegotiateMessage *msg);              \
    void (*onFailure)(struct WifiDirectCommand *base, int32_t reason);                            \
    void (*onTimeout)(struct WifiDirectCommand *base);                                            \
    struct WifiDirectCommand* (*duplicate)(struct WifiDirectCommand *base);                       \
    int32_t timerId;                                                                              \
    uint32_t commandId;                                                                            \
    void (*destructor)(struct WifiDirectCommand *base);                                           \
    enum WifiDirectCommandType type;                                                              \
    struct WifiDirectProcessor *processor; \
    struct NegotiateMessage *msg

struct WifiDirectCommand {
    WIFI_DIRECT_COMMAND_BASE;
};

#ifdef __cplusplus
}
#endif
#endif