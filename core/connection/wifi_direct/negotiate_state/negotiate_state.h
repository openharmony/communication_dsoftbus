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

#ifndef WIFI_DIRECT_NEGOTIATE_STATE_H
#define WIFI_DIRECT_NEGOTIATE_STATE_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct InterfaceInfo;
struct NegotiateMessage;
struct WifiDirectNegotiator;
struct WifiDirectProcessor;

#define NEGO_TIMEOUT_PROCESSING 15000
#define NEGO_TIMEOUT_WAIT_REMOTE 10000
#define NEGO_TIMEOUT_FAST_CONNECTING 10000

enum NegotiateTimeoutEvent {
    NEGO_TIMEOUT_EVENT_INVALID = -1,
    NEGO_TIMEOUT_EVENT_WAITING_CONNECT_RESPONSE = 0,
    NEGO_TIMEOUT_EVENT_WAITING_GROUP_BE_CREATED = 1,
    NEGO_TIMEOUT_EVENT_WAITING_CONNECT_TO_GROUP = 2,
    NEGO_TIMEOUT_EVENT_WAITING_CONNECT_REQUEST = 3,
    NEGO_TIMEOUT_EVENT_WAITING_PROCESSING = 4,
    NEGO_TIMEOUT_EVENT_WAITING_FAST_CONNECTING = 5,
};

enum NegotiateStateType {
    NEGO_STATE_UNAVAILABLE = 0,
    NEGO_STATE_AVAILABLE = 1,
    NEGO_STATE_PROCESSING = 2,
    NEGO_STATE_WAITING_CONNECT_RESPONSE = 3,
    NEGO_STATE_WAITING_CONNECT_REQUEST = 4,
    NEGO_STATE_FAST_CONNECTING = 5,
    NEGO_STATE_MAX
};

#define NEGOTIATE_STATE_BASE(childType) \
    void (*enter)(void);                                                                                             \
    void (*exit)(void);                                                                                              \
                                                                                                                     \
    int32_t (*handleNegotiateMessageFromRemote)(struct WifiDirectProcessor *processor,                               \
                                                enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg);  \
    void (*onTimeout)(enum NegotiateTimeoutEvent event);                                                             \
                                                                                                                     \
    struct WifiDirectNegotiator *negotiator;                                                                         \
    enum NegotiateStateType type;                                                                                    \
    const char *name;                                                                                                \
    bool isInited

struct NegotiateState {
    NEGOTIATE_STATE_BASE(NegotiateState);
};

void NegotiateStateConstructor(struct NegotiateState *self, struct WifiDirectNegotiator *sm, const char *name,
                               enum NegotiateStateType type);

#ifdef __cplusplus
}
#endif
#endif