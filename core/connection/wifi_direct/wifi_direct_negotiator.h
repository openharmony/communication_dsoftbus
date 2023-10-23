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

#ifndef WIFI_DIRECT_STATE_MACHINE_H
#define WIFI_DIRECT_STATE_MACHINE_H

#include "wifi_direct_types.h"
#include "softbus_adapter_thread.h"
#include "command/wifi_direct_command.h"
#include "command/wifi_direct_connect_command.h"
#include "command/wifi_direct_disconnect_command.h"

#ifdef __cplusplus
extern "C" {
#endif

struct InnerLink;
struct WifiDirectWork;
struct NegotiateMessage;
struct WifiDirectProtocol;
struct WifiDirectProcessor;

struct NegotiatorContext {
    char currentRemoteMac[MAC_ADDR_STR_LEN];
    char currentRemoteDeviceId[UUID_BUF_LEN];
    struct WifiDirectProcessor *currentProcessor;
    struct WifiDirectCommand *currentCommand;
};

struct WifiDirectNegotiator {
    int32_t (*processNextCommand)(void);
    int32_t (*retryCurrentCommand)(void);
    bool (*isBusy)(void);
    void (*resetContext)(void);

    int32_t (*postData)(struct NegotiateMessage *sendMsg);
    int32_t (*handleMessageFromProcessor)(struct NegotiateMessage *msg);

    void (*onNegotiateChannelDataReceived)(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len);
    void (*onNegotiateChannelDisconnected)(struct WifiDirectNegotiateChannel *channel);

    void (*handleFailureWithoutChangeState)(int32_t reason);
    void (*handleUnhandledRequest)(struct NegotiateMessage *msg);
    void (*onWifiDirectAuthOpened)(uint32_t requestId, int64_t authId);
    void (*syncLnnInfo)(struct InnerLink *innerLink);

    struct NegotiatorContext context;
};

struct WifiDirectNegotiator* GetWifiDirectNegotiator(void);
int32_t WifiDirectNegotiatorInit(void);

#ifdef __cplusplus
}
#endif
#endif