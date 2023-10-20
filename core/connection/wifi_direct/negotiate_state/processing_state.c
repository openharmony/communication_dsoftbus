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

#include "processing_state.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "wifi_direct_negotiator.h"
#include "data/negotiate_message.h"
#include "processor/wifi_direct_processor_factory.h"

#define LOG_LABEL "[WifiDirect] NegoProcessingState: "

/* private method forward declare */

/* public interface */
static void Enter(void)
{
    CLOGI(LOG_LABEL "enter");
    GetWifiDirectNegotiator()->stopTimer();
    GetWifiDirectNegotiator()->startTimer(NEGO_TIMEOUT_PROCESSING, NEGO_TIMEOUT_EVENT_WAITING_PROCESSING);
}

static void Exit(void)
{
    CLOGI(LOG_LABEL "exit");
}

static int32_t HandleNegotiateMessageFromRemote(struct WifiDirectProcessor *processor,
                                                enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    if (cmd == CMD_PC_GET_INTERFACE_INFO_REQ) {
        CLOGI(LOG_LABEL "pc get interface info request");
        return processor->processNegotiateMessage(cmd, msg);
    }
    if (cmd == CMD_CTRL_CHL_HANDSHAKE) {
        return processor->processNegotiateMessage(cmd, msg);
    }

    CLOGE(LOG_LABEL "unhandled cmd=%d", cmd);
    GetWifiDirectNegotiator()->handleUnhandledRequest(msg);
    return SOFTBUS_OK;
}

static void OnTimeout(enum NegotiateTimeoutEvent event)
{
    if (event != NEGO_TIMEOUT_EVENT_WAITING_PROCESSING) {
        CLOGE(LOG_LABEL "mismatch timeout event=%d", event);
        return;
    }
    CLOGE(LOG_LABEL "timeout");
    GetWifiDirectNegotiator()->handleFailure(SOFTBUS_ERR);
}

/* constructor */
static struct ProcessingState g_state = {
    .isInited = false,
};

static void Constructor(struct ProcessingState *self, struct WifiDirectNegotiator *negotiator)
{
    self->enter = Enter;
    self->exit = Exit;
    self->handleNegotiateMessageFromRemote = HandleNegotiateMessageFromRemote;
    self->onTimeout = OnTimeout;
    self->negotiator = negotiator;
    self->type = NEGO_STATE_PROCESSING;
    self->name = "NegoProcessingState";
    self->isInited = true;
}

struct ProcessingState* GetProcessingState(struct WifiDirectNegotiator *negotiator)
{
    if (!g_state.isInited) {
        Constructor(&g_state, negotiator);
    }
    return &g_state;
}