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

#include "waiting_connect_request_state.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_negotiate_channel.h"
#include "data/negotiate_message.h"
#include "processor/wifi_direct_processor.h"
#include "utils/wifi_direct_utils.h"

#define LOG_LABEL "[WD] NWCReqS: "

/* private method forward declare */
static int32_t HandleRequest(struct WifiDirectProcessor *processor, enum WifiDirectNegotiateCmdType cmd,
                             struct NegotiateMessage *msg);

/* public interface */
static void Enter(void)
{
    CLOGI(LOG_LABEL "enter");
    GetWifiDirectNegotiator()->stopTimer();
    GetWifiDirectNegotiator()->startTimer(NEGO_TIMEOUT_WAIT_REMOTE, NEGO_TIMEOUT_EVENT_WAITING_CONNECT_REQUEST);
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
        case CMD_CONN_V1_RESP:
        case CMD_CONN_V2_REQ_1:
        case CMD_CONN_V2_REQ_2:
        case CMD_CTRL_CHL_HANDSHAKE:
            GetWifiDirectNegotiator()->context.currentProcessor = processor;
            return processor->processNegotiateMessage(cmd, msg);
        case CMD_PC_GET_INTERFACE_INFO_REQ:
            return HandleRequest(processor, cmd, msg);
        default:
            CLOGE(LOG_LABEL "unhandled cmd=%d", cmd);
            GetWifiDirectNegotiator()->handleUnhandledRequest(msg);
            return SOFTBUS_OK;
    }
}

static void OnTimeout(enum NegotiateTimeoutEvent event)
{
    if (event != NEGO_TIMEOUT_EVENT_WAITING_CONNECT_REQUEST) {
        CLOGE(LOG_LABEL "mismatch timeout event=%d", event);
        return;
    }
    CLOGE(LOG_LABEL "timeout");
    GetWifiDirectNegotiator()->handleFailure(ERROR_WIFI_DIRECT_WAIT_CONNECT_REQUEST_TIMEOUT);
}

/* private method implement */
static int32_t HandleRequest(struct WifiDirectProcessor *processor, enum WifiDirectNegotiateCmdType cmd,
                             struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "get remote device id failed");

    char *currentDeviceId = GetWifiDirectNegotiator()->context.currentRemoteDeviceId;
    if (GetWifiDirectUtils()->strCompareIgnoreCase(remoteDeviceId, currentDeviceId) != 0) {
        CLOGE(LOG_LABEL "msg from other device, current=%s remote=%s",
              AnonymizesUUID(currentDeviceId), AnonymizesUUID(remoteDeviceId));
        return SOFTBUS_ERR;
    }

    CLOGI(LOG_LABEL "msg from target device");
    return processor->processNegotiateMessage(cmd, msg);
}

/* constructor */
static struct WaitingConnectRequestState g_state = {
    .isInited = false,
};

static void Constructor(struct WaitingConnectRequestState *self, struct WifiDirectNegotiator *negotiator)
{
    self->enter = Enter;
    self->exit = Exit;
    self->handleNegotiateMessageFromRemote = HandleNegotiateMessageFromRemote;
    self->onTimeout = OnTimeout;
    self->negotiator = negotiator;
    self->type = NEGO_STATE_WAITING_CONNECT_REQUEST;
    self->name = "NegoWaitingConnectRequestState";
    self->isInited = true;
}

struct WaitingConnectRequestState* GetWaitingConnectRequestState(struct WifiDirectNegotiator *negotiator)
{
    if (!g_state.isInited) {
        Constructor(&g_state, negotiator);
        g_state.isInited = true;
    }
    return &g_state;
}