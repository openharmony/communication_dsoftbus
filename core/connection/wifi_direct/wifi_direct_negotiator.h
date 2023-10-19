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
#include "wifi_direct_command_manager.h"
#include "negotiate_state/negotiate_state.h"

#ifdef __cplusplus
extern "C" {
#endif

struct InnerLink;
struct WifiDirectWork;
struct NegotiateState;
struct NegotiateMessage;
struct WifiDirectProtocol;
struct WifiDirectProcessor;

enum NegotiatorTaskType {
    TASK_TYPE_INVALID = -1,
    TASK_TYPE_CONNECT = 0,
    TASK_TYPE_DISCONNECT = 1,
};

struct NegotiatorContext {
    int32_t currentPid;
    int32_t currentRequestId;
    int32_t currentTimerId;
    int32_t currentLinkId;
    char currentRemoteMac[MAC_ADDR_STR_LEN];
    char currentRemoteDeviceId[UUID_BUF_LEN];

    enum NegotiatorTaskType currentTaskType;
    struct NegotiateState *currentState;
    struct WifiDirectProcessor *currentProcessor;
    struct WifiDirectCommand *currentCommand;
};

struct WifiDirectNegotiator {
    int32_t (*openLink)(struct WifiDirectConnectInfo *connectInfo);
    int32_t (*closeLink)(struct WifiDirectConnectInfo *connectInfo);

    void (*changeState)(enum NegotiateStateType newState);
    int32_t (*processNewCommand)(void);
    int32_t (*retryCurrentCommand)(void);

    int32_t (*startTimer)(int64_t timeoutMs, enum NegotiateTimeoutEvent type);
    void (*stopTimer)(void);

    int32_t (*postData)(struct NegotiateMessage *sendMsg);
    int32_t (*handleMessageFromProcessor)(struct NegotiateMessage *msg, enum NegotiateStateType nextState);

    void (*onNegotiateChannelDataReceived)(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len);

    void (*handleSuccess)(struct NegotiateMessage *msg);
    void (*handleFailure)(int32_t reason);
    void (*handleFailureWithoutChangeState)(int32_t reason);
    void (*handleUnhandledRequest)(struct NegotiateMessage *msg);
    void (*onWifiDirectAuthOpened)(uint32_t requestId, int64_t authId);
    void (*syncLnnInfo)(struct InnerLink *innerLink);

    struct NegotiatorContext context;
    struct NegotiateState *states[NEGO_STATE_MAX];
};

struct WifiDirectNegotiator* GetWifiDirectNegotiator(void);
int32_t WifiDirectNegotiatorInit(void);

#ifdef __cplusplus
}
#endif
#endif