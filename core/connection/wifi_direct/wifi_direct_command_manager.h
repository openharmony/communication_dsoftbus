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
#ifndef WIFI_DIRECT_COMMAND_MANAGER_H
#define WIFI_DIRECT_COMMAND_MANAGER_H

#include "common_list.h"
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TIMEOUT_COMMAND_WAIT_MS 15000

enum WifiDirectCommandType {
    COMMAND_TYPE_CONNECT = 0,
    COMMAND_TYPE_DISCONNECT = 1,
};

struct WifiDirectCommand {
    int32_t (*execute)(struct WifiDirectCommand *self);
    bool (*isNeedRetry)(struct WifiDirectCommand *self);

    ListNode node;
    enum WifiDirectCommandType type;
    int32_t timerId;
    struct WifiDirectConnectInfo connectInfo;
    int32_t times;
};

struct WifiDirectCommandManager {
    void (*enqueueCommand)(struct WifiDirectCommand *command);
    struct WifiDirectCommand* (*dequeueCommand)(void);
    void (*removeCommand)(struct WifiDirectCommand *command);

    struct ListNode commands;
};

struct WifiDirectCommandManager* GetWifiDirectCommandManager(void);
struct WifiDirectCommand* GenerateWifiDirectConnectCommand(struct WifiDirectConnectInfo *connectInfo);
struct WifiDirectCommand* GenerateWifiDirectDisconnectCommand(struct WifiDirectConnectInfo *connectInfo);
void FreeWifiDirectCommand(struct WifiDirectCommand *command);

int32_t WifiDirectCommandManagerInit(void);

#ifdef __cplusplus
}
#endif
#endif