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
#ifndef WIFI_DIRECT_PROCESSOR_H
#define WIFI_DIRECT_PROCESSOR_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum WifiDirectProcessorType {
    WIFI_DIRECT_PROCESSOR_TYPE_INVALID = -1,
    WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1 = 0,
    WIFI_DIRECT_PROCESSOR_TYPE_P2P_V2 = 1,
    WIFI_DIRECT_PROCESSOR_TYPE_HML = 2,
    WIFI_DIRECT_PROCESSOR_TYPE_TRIGGER_P2P = 3,
    WIFI_DIRECT_PROCESSOR_TYPE_TRIGGER_HML = 4,
    WIFI_DIRECT_PROCESSOR_TYPE_MAX
};

struct NegotiateMessage;
struct InnerLink;
struct WifiDirectCommand;
struct WifiDirectNegotiateChannel;
struct WifiDirectTriggerChannel;

#define WIFI_DIRECT_PROCESSOR_BASE                                                                                \
    int32_t (*createLink)(struct WifiDirectConnectInfo *connectInfo);                                             \
    int32_t (*reuseLink)(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink);                 \
    int32_t (*disconnectLink)(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink);            \
    void (*processNegotiateMessage)(enum WifiDirectNegotiateCmdType cmd, struct WifiDirectCommand *command);      \
    void (*processHandShake)(struct NegotiateMessage *msg);                                                       \
    void (*onTriggerChannelDataReceived)(struct WifiDirectTriggerChannel *channel);                               \
    void (*onDefaultTriggerChannelDataReceived)(struct WifiDirectNegotiateChannel *channel,                       \
                                                const uint8_t *data, size_t len);                                 \
    void (*onOperationEvent)(int32_t result, void *data);                                                         \
                                                                                                                  \
    bool (*isMessageNeedPending)(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg);              \
    void (*onReversal)(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg);                        \
    void (*resetContext)(void);                                                                                   \
    int32_t (*prejudgeAvailability)(const char *remoteNetworkId);                                                 \
                                                                                                                  \
    char *name;                                                                                                   \
    int32_t timerId;                                                                                              \
    int32_t currentState;                                                                                         \
    struct WifiDirectCommand *activeCommand;                                                                      \
    struct WifiDirectCommand *passiveCommand

struct WifiDirectProcessor {
    WIFI_DIRECT_PROCESSOR_BASE;
};

#ifdef __cplusplus
}
#endif
#endif