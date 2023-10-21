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

#include "waiting_connect_response_state.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "bus_center_manager.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_negotiate_channel.h"
#include "wifi_direct_p2p_adapter.h"
#include "data/negotiate_message.h"
#include "processor/wifi_direct_processor.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WifiDirect] NegoWaitingConnectResponseState: "

/* private method forward declare */
static int32_t HandleResponse(struct WifiDirectProcessor *processor, enum WifiDirectNegotiateCmdType cmd,
                              struct NegotiateMessage *msg);
static int32_t HandleRequest(struct WifiDirectProcessor *processor, enum WifiDirectNegotiateCmdType cmd,
                             struct NegotiateMessage *msg);

/* public interface */
static void Enter(void)
{
    CLOGI(LOG_LABEL "enter");
    GetWifiDirectNegotiator()->stopTimer();
    GetWifiDirectNegotiator()->startTimer(NEGO_TIMEOUT_WAIT_REMOTE, NEGO_TIMEOUT_EVENT_WAITING_CONNECT_RESPONSE);
}

static void Exit(void)
{
    CLOGI(LOG_LABEL "exit");
}

static int32_t HandleNegotiateMessageFromRemote(struct WifiDirectProcessor *processor,
                                                enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    switch (cmd) {
        case CMD_CONN_V1_RESP:
        case CMD_REUSE_RESP:
        case CMD_CONN_V2_RESP_1:
        case CMD_CONN_V2_RESP_2:
        case CMD_CONN_V2_RESP_3:
            return HandleResponse(processor, cmd, msg);
        case CMD_CONN_V1_REQ:
        case CMD_CONN_V2_REQ_1:
        case CMD_CONN_V2_REQ_2:
        case CMD_CONN_V2_REQ_3:
            return HandleRequest(processor, cmd, msg);
        case CMD_CLIENT_JOIN_FAIL_NOTIFY:
        case CMD_CTRL_CHL_HANDSHAKE:
        case CMD_PC_GET_INTERFACE_INFO_REQ:
            return processor->processNegotiateMessage(cmd, msg);
        default:
            CLOGE(LOG_LABEL "unhandled cmd=%d", cmd);
            GetWifiDirectNegotiator()->handleUnhandledRequest(msg);
            return SOFTBUS_OK;
    }
}

static void OnTimeout(enum NegotiateTimeoutEvent event)
{
    if (event != NEGO_TIMEOUT_EVENT_WAITING_CONNECT_RESPONSE) {
        CLOGE(LOG_LABEL "mismatch timeout event=%d", event);
        return;
    }
    CLOGE(LOG_LABEL "timeout");
    GetWifiDirectNegotiator()->handleFailure(ERROR_WIFI_DIRECT_WAIT_CONNECT_RESPONSE_TIMEOUT);
}

/* private method implement */
static bool CheckTargetDevice(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, LOG_LABEL "get remote device id failed");

    char *currentDeviceId = GetWifiDirectNegotiator()->context.currentRemoteDeviceId;
    if (GetWifiDirectUtils()->strCompareIgnoreCase(remoteDeviceId, currentDeviceId) != 0) {
        CLOGE(LOG_LABEL "msg from other device, current=%s remote=%s",
              AnonymizesUUID(currentDeviceId), AnonymizesUUID(remoteDeviceId));
        return false;
    }

    CLOGI(LOG_LABEL "msg from target device");
    return true;
}

static int32_t HandleResponse(struct WifiDirectProcessor *processor, enum WifiDirectNegotiateCmdType cmd,
                              struct NegotiateMessage *msg)
{
    if (!CheckTargetDevice(msg)) {
        CLOGE(LOG_LABEL "ignore the response");
        return SOFTBUS_OK;
    }
    GetWifiDirectNegotiator()->context.currentProcessor = processor;
    return processor->processNegotiateMessage(cmd, msg);
}

static bool IsNeedReversal(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    if (!channel->isRemoteTlvSupported(channel)) {
        char localMac[MAC_ADDR_STR_LEN] = {0};
        char remoteMac[MAC_ADDR_STR_LEN] = {0};
        int32_t ret = GetWifiDirectP2pAdapter()->getMacAddress(localMac, sizeof(localMac));
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, "get local mac failed");
        ret = channel->getP2pMac(channel, remoteMac, sizeof(remoteMac));
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, "get remote mac failed");
        CLOGI(LOG_LABEL "localMac=%s remoteMac=%s",
              WifiDirectAnonymizeMac(localMac), WifiDirectAnonymizeMac(remoteMac));
        return GetWifiDirectUtils()->strCompareIgnoreCase(localMac, remoteMac) < 0;
    }

    char remoteUuid[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteUuid, sizeof(remoteUuid));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, "get device id failed");
    char localUuid[UUID_BUF_LEN] = {0};
    ret = LnnGetLocalStrInfo(STRING_KEY_UUID, localUuid, sizeof(localUuid));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, "LnnGetLocalStrInfo failed");
    CLOGI(LOG_LABEL "localUuid=%s remoteUuid=%s", AnonymizesUUID(localUuid), AnonymizesUUID(remoteUuid));
    return GetWifiDirectUtils()->strCompareIgnoreCase(localUuid, remoteUuid) < 0;
}

static int32_t HandleRequest(struct WifiDirectProcessor *processor, enum WifiDirectNegotiateCmdType cmd,
                              struct NegotiateMessage *msg)
{
    if (!CheckTargetDevice(msg)) {
        processor->processUnhandledRequest(msg, ERROR_MANAGER_BUSY);
        return SOFTBUS_OK;
    }

    if (!IsNeedReversal(msg)) {
        CLOGI(LOG_LABEL "no need reversal, ignore remote request");
        GetWifiDirectNegotiator()->handleUnhandledRequest(msg);
        return SOFTBUS_OK;
    }

    CLOGI(LOG_LABEL "need reversal, process remote request and retry local command");
    processor->onReversal(cmd, msg);
    GetWifiDirectNegotiator()->context.currentProcessor = processor;
    return processor->processNegotiateMessage(cmd, msg);
}

/* constructor */
static struct WaitingConnectResponseState g_state = {
    .isInited = false,
};

static void Constructor(struct WaitingConnectResponseState *self, struct WifiDirectNegotiator *negotiator)
{
    self->enter = Enter;
    self->exit = Exit;
    self->handleNegotiateMessageFromRemote = HandleNegotiateMessageFromRemote;
    self->onTimeout = OnTimeout;
    self->negotiator = negotiator;
    self->type = NEGO_STATE_WAITING_CONNECT_RESPONSE;
    self->name = "NegoWaitingConnectResponseState";
    self->isInited = true;
}

struct WaitingConnectResponseState* GetWaitingConnectResponseState(struct WifiDirectNegotiator *negotiator)
{
    if (!g_state.isInited) {
        Constructor(&g_state, negotiator);
    }
    return &g_state;
}