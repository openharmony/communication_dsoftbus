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

#include "available_state.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "wifi_direct_negotiator.h"
#include "data/negotiate_message.h"
#include "processor/wifi_direct_processor_factory.h"
#include "protocol/wifi_direct_protocol_factory.h"

#define LOG_LABEL "[WifiDirect] NegoAvailableState: "

/* private method forward declare */

/* public interface */
static void Enter(void)
{
    CLOGI(LOG_LABEL "enter");
    GetWifiDirectNegotiator()->stopTimer();
}

static void Exit(void)
{
    CLOGI(LOG_LABEL "exit");
}

static int32_t HandleNegotiateMessageFromRemote(struct WifiDirectProcessor *processor,
                                                enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    CONN_CHECK_AND_RETURN_RET_LOG(processor, SOFTBUS_INVALID_PARAM, LOG_LABEL "processor is null");
    switch (cmd) {
        case CMD_CONN_V1_REQ:
        case CMD_REUSE_REQ:
        case CMD_CONN_V2_REQ_1:
        case CMD_CONN_V2_REQ_3:
        case CMD_DISCONNECT_V1_REQ:
        case CMD_DISCONNECT_V2_REQ:
        case CMD_CTRL_CHL_HANDSHAKE:
        case CMD_PC_GET_INTERFACE_INFO_REQ:
        case CMD_CLIENT_JOIN_FAIL_NOTIFY:
            GetWifiDirectNegotiator()->context.currentProcessor = processor;
            return processor->processNegotiateMessage(cmd, msg);
        default:
            CLOGE(LOG_LABEL "unhandled cmd=%d", cmd);
            GetWifiDirectNegotiator()->handleUnhandledRequest(msg);
            return SOFTBUS_OK;
    }
}

static void OnTimeout(enum NegotiateTimeoutEvent event)
{
    CLOGE(LOG_LABEL "event=%d", event);
}

/* constructor */
static struct AvailableState g_state = {
    .isInited = false,
};

static void Constructor(struct AvailableState *self, struct WifiDirectNegotiator *negotiator)
{
    self->enter = Enter;
    self->exit = Exit;
    self->handleNegotiateMessageFromRemote = HandleNegotiateMessageFromRemote;
    self->onTimeout = OnTimeout;
    self->negotiator = negotiator;
    self->type = NEGO_STATE_AVAILABLE;
    self->name = "NegoAvailableState";
    self->isInited = true;
}

struct AvailableState* GetAvailableState(struct WifiDirectNegotiator *negotiator)
{
    if (!g_state.isInited) {
        Constructor(&g_state, negotiator);
    }
    return &g_state;
}