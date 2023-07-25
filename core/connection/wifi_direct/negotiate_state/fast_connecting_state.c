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

#include "fast_connecting_state.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "wifi_direct_negotiator.h"
#include "data/negotiate_message.h"
#include "wifi_direct_fast_connect.h"

#define LOG_LABEL "[WifiDirect] FastConnectingState: "

static void Enter(void)
{
    CLOGI(LOG_LABEL "enter");
    GetWifiDirectNegotiator()->stopTimer();
    GetWifiDirectNegotiator()->startTimer(NEGO_TIMEOUT_FAST_CONNECTING, NEGO_TIMEOUT_EVENT_WAITING_FAST_CONNECTING);
}

static void Exit(void)
{
    CLOGI(LOG_LABEL "exit");
}

static int32_t HandleNegotiateMessageFromRemote(struct WifiDirectProcessor *processor,
                                                enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    return FastConnectProcessNegotiateMessage(cmd, msg);
}

static void OnTimeout(enum NegotiateTimeoutEvent event)
{
    if (event != NEGO_TIMEOUT_EVENT_WAITING_FAST_CONNECTING) {
        CLOGE(LOG_LABEL "mismatch timeout event=%d", event);
        return;
    }
    CLOGE(LOG_LABEL "timeout");
    GetWifiDirectNegotiator()->handleFailure(SOFTBUS_ERR);
}

/* constructor */
static struct FastConnectingState g_state = {
    .isInited = false,
};

static void Constructor(struct FastConnectingState *self, struct WifiDirectNegotiator *negotiator)
{
    self->enter = Enter;
    self->exit = Exit;
    self->handleNegotiateMessageFromRemote = HandleNegotiateMessageFromRemote;
    self->onTimeout = OnTimeout;
    self->negotiator = negotiator;
    self->type = NEGO_STATE_FAST_CONNECTING;
    self->name = "FastConnectingState";
    self->isInited = true;
}

struct FastConnectingState* GetFastConnectingState(struct WifiDirectNegotiator *negotiator)
{
    if (!g_state.isInited) {
        Constructor(&g_state, negotiator);
    }
    return &g_state;
}