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

#ifndef WIFI_DIRECT_DISCONNECT_COMMAND_H
#define WIFI_DIRECT_DISCONNECT_COMMAND_H

#include "wifi_direct_command.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectDisconnectCommand {
    WIFI_DIRECT_COMMAND_BASE;

    struct WifiDirectConnectInfo connectInfo;
    struct WifiDirectConnectCallback callback;
    int32_t times;
};

void WifiDirectDisconnectCommandConstructor(struct WifiDirectDisconnectCommand *self,
                                            struct WifiDirectConnectInfo *connectInfo,
                                            struct WifiDirectConnectCallback *callback);
void WifiDirectDisconnectCommandDestructor(struct WifiDirectDisconnectCommand *self);
struct WifiDirectCommand* WifiDirectDisconnectCommandNew(struct WifiDirectConnectInfo *connectInfo,
                                                         struct WifiDirectConnectCallback *callback);
void WifiDirectDisconnectCommandDelete(struct WifiDirectCommand *base);

#ifdef __cplusplus
}
#endif
#endif