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
    WIFI_DIRECT_PROCESSOR_TYPE_MAX
};

enum WifiDirectProcessorState {
    PROCESSOR_STATE_AVAILABLE = 0,
    PROCESSOR_STATE_WAITING_CONNECT_GROUP = 1,
    PROCESSOR_STATE_WAITING_CREATE_GROUP = 2,
    PROCESSOR_STATE_WAITING_REMOVE_GROUP = 3,
    PROCESSOR_STATE_WAITING_HML_NOTIFY = 4,
    PROCESSOR_STATE_WAITING_DISCONNECTED_NO_DESTROY = 5,
    PROCESSOR_STATE_WAITING_SERVER_DISTROYED = 6,
};

struct NegotiateMessage;
struct NegotiateState;
struct InnerLink;

#define PROCESSOR_BASE                                                                                            \
    int32_t (*createLink)(struct WifiDirectConnectInfo *connectInfo);                                             \
    int32_t (*reuseLink)(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink);                 \
    int32_t (*disconnectLink)(struct WifiDirectConnectInfo *connectInfo, struct InnerLink *innerLink);            \
    int32_t (*processNegotiateMessage)(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg);        \
    int32_t (*onOperationEvent)(int32_t requestId, int32_t result);                                               \
                                                                                                                  \
    void (*processUnhandledRequest)(struct NegotiateMessage *msg, int32_t errorCode);                             \
    void (*onReversal)(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg);                        \
                                                                                                                  \
    enum WifiDirectProcessorState currentState;                                                                   \
    struct NegotiateMessage *currentMsg;                                                                          \
    char *name

struct WifiDirectProcessor {
    PROCESSOR_BASE;
};

#ifdef __cplusplus
}
#endif
#endif