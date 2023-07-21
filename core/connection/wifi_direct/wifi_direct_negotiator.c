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

#include "wifi_direct_negotiator.h"
#include <string.h>
#include "securec.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_timer.h"
#include "bus_center_manager.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_decision_center.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "data/negotiate_message.h"
#include "entity/wifi_direct_entity_factory.h"
#include "negotiate_state/negotiate_state.h"
#include "negotiate_state/available_state.h"
#include "negotiate_state/waiting_connect_response_state.h"
#include "negotiate_state/waiting_connect_request_state.h"
#include "negotiate_state/processing_state.h"
#include "protocol/wifi_direct_protocol.h"
#include "processor/wifi_direct_processor_factory.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_timer_list.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WifiDirect] WifiDirectNegotiator: "
#define RETRY_COMMAND_DELAY_MS 1000
#define WAIT_POST_REQUEST_MS 450

/* private method forward declare */
static void ResetContext(void);
static enum WifiDirectNegotiateCmdType GetNegotiateCmdType(struct NegotiateMessage *msg);

static int32_t ReuseLink(struct WifiDirectConnectInfo *connectInfo);

/* public interface */
static int32_t OpenLink(struct WifiDirectConnectInfo *connectInfo)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CLOGI(LOG_LABEL "requestId=%d currentState=%s", connectInfo->requestId, self->context.currentState->name);

    self->context.currentPid = connectInfo->pid;
    self->context.currentRequestId = connectInfo->requestId;
    self->context.currentTaskType = TASK_TYPE_CONNECT;

    CLOGI(LOG_LABEL "try reuse link");
    if (ReuseLink(connectInfo) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }

    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannel(connectInfo->negoChannel);
    CONN_CHECK_AND_RETURN_RET_LOG(processor, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, LOG_LABEL "no suitable processor");

    self->context.currentProcessor = processor;
    self->changeState(NEGO_STATE_PROCESSING);
    int32_t ret = processor->createLink(connectInfo);
    if (ret != SOFTBUS_OK) {
        self->changeState(NEGO_STATE_AVAILABLE);
    }
    return ret;
}

static int32_t PreferNegoChannelForConnectInfo(struct InnerLink *link, struct WifiDirectConnectInfo *connectInfo)
{
    struct WifiDirectNegotiateChannel *channel = link->getPointer(link, IL_KEY_NEGO_CHANNEL, NULL);
    if (channel) {
        CLOGD(LOG_LABEL "prefer inner link channel");
        if (connectInfo->negoChannel) {
            connectInfo->negoChannel->destructor(connectInfo->negoChannel);
        }
        connectInfo->negoChannel = channel->duplicate(channel);
        CONN_CHECK_AND_RETURN_RET_LOG(connectInfo->negoChannel, SOFTBUS_MALLOC_ERR, LOG_LABEL "new channel failed");
        return SOFTBUS_OK;
    }
    if (connectInfo->negoChannel) {
        CLOGD(LOG_LABEL "prefer input channel");
        return SOFTBUS_OK;
    }

    CLOGE(LOG_LABEL "no channel");
    return ERROR_WRONG_AUTH_CONNECTION_INFO;
}

static int32_t CloseLink(struct WifiDirectConnectInfo *connectInfo)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CLOGI(LOG_LABEL "requestId=%d currentState=%s", connectInfo->requestId, self->context.currentState->name);

    self->context.currentPid = connectInfo->pid;
    self->context.currentRequestId = connectInfo->requestId;
    self->context.currentTaskType = TASK_TYPE_DISCONNECT;
    self->context.currentLinkId = connectInfo->linkId;
    int32_t ret = strcpy_s(self->context.currentRemoteMac, sizeof(self->context.currentRemoteMac),
                           connectInfo->remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy remote mac failed");

    struct InnerLink *link = GetLinkManager()->getLinkById(connectInfo->linkId);
    if (link == NULL) {
        CLOGE(LOG_LABEL "find inner link by linkId failed");
        link = GetLinkManager()->getLinkByDevice(connectInfo->remoteMac);
        if (link == NULL) {
            CLOGI(LOG_LABEL "link is already not exist");
            GetWifiDirectNegotiator()->handleSuccess(NULL);
            return SOFTBUS_OK;
        }
    }

    int32_t reference = link->getReference(link);
    CLOGI(LOG_LABEL "remoteMac=%s reference=%d",
          WifiDirectAnonymizeMac(link->getString(link, IL_KEY_REMOTE_BASE_MAC, "")), reference);
    if (reference > 1) {
        GetWifiDirectNegotiator()->handleSuccess(NULL);
        return SOFTBUS_OK;
    }

    ret = PreferNegoChannelForConnectInfo(link, connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "prefer channel failed");

    enum WifiDirectConnectType connectType = link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_INVALID);
    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannelAndConnectType(connectInfo->negoChannel, connectType);
    CONN_CHECK_AND_RETURN_RET_LOG(processor, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, LOG_LABEL "no suitable processor");
    self->context.currentProcessor = processor;
    self->changeState(NEGO_STATE_PROCESSING);
    ret = processor->disconnectLink(connectInfo, link);
    if (ret != SOFTBUS_OK) {
        self->changeState(NEGO_STATE_AVAILABLE);
    }
    return ret;
}

static int32_t HandleMessageFromProcessor(struct NegotiateMessage *msg, enum NegotiateStateType nextState)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();

    int32_t ret = SOFTBUS_OK;
    if (msg) {
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");
        (void)channel->getDeviceId(channel, self->context.currentRemoteDeviceId,
                                   sizeof(self->context.currentRemoteDeviceId));
        ret = self->postData(msg);
    }
    if (ret == SOFTBUS_OK) {
        self->changeState(nextState);
    }
    return ret;
}

static void SaveP2pChannel(struct WifiDirectNegotiateChannel *channel)
{
    if (!channel->isP2pChannel(channel)) {
        return;
    }

    char remoteMac[MAC_ADDR_STR_LEN] = {0};
    int32_t ret = channel->getP2pMac(channel, remoteMac, sizeof(remoteMac));
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get p2p mac failed");
    struct InnerLink *link = GetLinkManager()->getLinkByDevice(remoteMac);
    CONN_CHECK_AND_RETURN_LOG(link, LOG_LABEL "link is null");
    struct WifiDirectNegotiateChannel *channelOld = link->getPointer(link, IL_KEY_NEGO_CHANNEL, NULL);
    if (channelOld == NULL) {
        struct WifiDirectNegotiateChannel *channelNew = channel->duplicate(channel);
        link->putPointer(link, IL_KEY_NEGO_CHANNEL, (void **)&channelNew);
    }
}

static int32_t UnpackData(const uint8_t *data, size_t size, struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");

    struct WifiDirectDecisionCenter *decisionCenter = GetWifiDirectDecisionCenter();
    struct WifiDirectProtocol *protocol = decisionCenter->getProtocol(channel);
    CONN_CHECK_AND_RETURN_RET_LOG(protocol, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, LOG_LABEL "no suitable protocol");

    if (protocol->getType() == WIFI_DIRECT_PROTOCOL_JSON) {
        CLOGI(LOG_LABEL "WIFI_DIRECT_PROTOCOL_JSON size=%zd", size);
    } else if (protocol->getType() == WIFI_DIRECT_PROTOCOL_TLV) {
        CLOGI(LOG_LABEL "WIFI_DIRECT_PROTOCOL_TLV size=%zd", size);
    }

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    protocol->setFormat(protocol, &format);

    if (!protocol->setDataSource(protocol, data, size)) {
        CLOGE(LOG_LABEL "protocol set data source failed");
        decisionCenter->putProtocol(protocol);
        return ERROR_WIFI_DIRECT_UNPACK_DATA_FAILED;
    }
    if (!protocol->unpack(protocol, (struct InfoContainer *)msg)) {
        CLOGE(LOG_LABEL "unpack data failed");
        decisionCenter->putProtocol(protocol);
        return ERROR_WIFI_DIRECT_UNPACK_DATA_FAILED;
    }

    decisionCenter->putProtocol(protocol);
    return SOFTBUS_OK;
}

static struct NegotiateMessage* GenerateNegotiateMessage(struct WifiDirectNegotiateChannel *channel,
                                                         const uint8_t *data, size_t size)
{
    struct NegotiateMessage *msg = NegotiateMessageNew();
    if (msg == NULL) {
        CLOGE(LOG_LABEL "alloc msg failed");
        return NULL;
    }

    msg->putInt(msg, NM_KEY_SESSION_ID, GetWifiDirectNegotiator()->context.currentRequestId);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    if ((UnpackData(data, size, msg)) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "unpack msg failed");
        NegotiateMessageDelete(msg);
        return NULL;
    }

    return msg;
}

#define CmdStringItemDefine(cmd) { cmd, #cmd }
static void DumpCommandString(enum WifiDirectNegotiateCmdType cmdType, const char *remoteDeviceId)
{
    static struct CmdStringItem {
        enum WifiDirectNegotiateCmdType cmd;
        const char *string;
    } cmdStringMap[] = {
        CmdStringItemDefine(CMD_INVALID),
        CmdStringItemDefine(CMD_DISCONNECT_V1_REQ),
        CmdStringItemDefine(CMD_CONN_V1_REQ),
        CmdStringItemDefine(CMD_CONN_V1_RESP),
        CmdStringItemDefine(CMD_REUSE_REQ),
        CmdStringItemDefine(CMD_CTRL_CHL_HANDSHAKE),
        CmdStringItemDefine(CMD_REUSE_RESP),
        CmdStringItemDefine(CMD_CONN_V2_REQ_1),
        CmdStringItemDefine(CMD_CONN_V2_REQ_2),
        CmdStringItemDefine(CMD_CONN_V2_REQ_3),
        CmdStringItemDefine(CMD_CONN_V2_RESP_1),
        CmdStringItemDefine(CMD_CONN_V2_RESP_2),
        CmdStringItemDefine(CMD_CONN_V2_RESP_3),
        CmdStringItemDefine(CMD_DISCONNECT_V2_REQ),
        CmdStringItemDefine(CMD_DISCONNECT_V2_RESP),
        CmdStringItemDefine(CMD_PC_GET_INTERFACE_INFO_REQ),
        CmdStringItemDefine(CMD_PC_GET_INTERFACE_INFO_RESP),
    };

    for (uint32_t i = 0 ; i < ARRAY_SIZE(cmdStringMap); i++) {
        if (cmdStringMap[i].cmd == cmdType) {
            CLOGI(LOG_LABEL "cmd=%s remoteDeviceId=%s", cmdStringMap[i].string, AnonymizesUUID(remoteDeviceId));
            break;
        }
    }
}

static enum WifiDirectNegotiateCmdType GetNegotiateCmdType(struct NegotiateMessage *msg)
{
    enum WifiDirectNegotiateCmdType cmdType = msg->getInt(msg, NM_KEY_MSG_TYPE, CMD_INVALID);
    if (cmdType == CMD_INVALID) {
        if ((cmdType = msg->getInt(msg, NM_KEY_COMMAND_TYPE, CMD_INVALID)) == CMD_INVALID) {
            CLOGE(LOG_LABEL "cmd type is null");
        }
    }

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    char remoteDeviceId[UUID_BUF_LEN] = {0};
    if (channel != NULL) {
        channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    }
    DumpCommandString(cmdType, remoteDeviceId);
    return cmdType;
}

static int32_t HandleNegotiationMessageWhenProcessorInvalid(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    if (self->context.currentRequestId >= 0) {
        CLOGE(LOG_LABEL "no suitable processor");
        return ERROR_WIFI_DIRECT_NO_SUITABLE_PROCESSOR;
    }

    struct WifiDirectProcessor *processor =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V2);
    if (processor == NULL) {
        CLOGE(LOG_LABEL "create processor failed");
        return ERROR_WIFI_DIRECT_NO_SUITABLE_PROCESSOR;
    }

    CLOGE(LOG_LABEL "ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE");
    processor->processUnhandledRequest(msg, ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE);
    return SOFTBUS_OK;
}

static void OnNegotiateChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CLOGI(LOG_LABEL "currentState=%s len=%zd", self->context.currentState->name, len);
    SaveP2pChannel(channel);

    int32_t ret = SOFTBUS_OK;
    struct NegotiateMessage *msg = GenerateNegotiateMessage(channel, data, len);
    if (msg == NULL) {
        ret = ERROR_WIFI_DIRECT_UNPACK_DATA_FAILED;
        goto OUT;
    }
    enum WifiDirectNegotiateCmdType cmdType = GetNegotiateCmdType(msg);
    if (cmdType == CMD_CTRL_CHL_HANDSHAKE) {
        CLOGI(LOG_LABEL "ignore CMD_CTRL_CHL_HANDSHAKE");
        goto OUT;
    }
    if (cmdType == CMD_INVALID) {
        CLOGE(LOG_LABEL "CMD_INVALID");
        ret = ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG;
        goto OUT;
    }
    ret = msg->getInt(msg, NM_KEY_RESULT_CODE, OK);
    if (ret != OK) {
        goto OUT;
    }

    struct WifiDirectProcessor *processor = GetWifiDirectDecisionCenter()->getProcessorByNegotiateMessage(msg);
    if (processor == NULL) {
        ret = HandleNegotiationMessageWhenProcessorInvalid(msg);
        goto OUT;
    }

    ret = self->context.currentState->handleNegotiateMessageFromRemote(processor, cmdType, msg);
OUT:
    if (msg != NULL) {
        NegotiateMessageDelete(msg);
    }
    if (ret != SOFTBUS_OK) {
        self->handleFailure(ret);
        CLOGE(LOG_LABEL "process remote message failed");
    }
}

static void OnNegotiateChannelDisconnected(struct WifiDirectNegotiateChannel *channel)
{
    if (!channel->isP2pChannel(channel)) {
        return;
    }
    CLOGD(LOG_LABEL "enter");
    GetLinkManager()->clearNegoChannelForLink(channel);
}

static void OnOperationComplete(int32_t requestId, int32_t result)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    self->stopTimer();

    struct WifiDirectProcessor *processor = self->context.currentProcessor;
    CONN_CHECK_AND_RETURN_LOG(processor, LOG_LABEL "processor is null");

    int32_t ret = processor->onOperationEvent(requestId, result);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "handle operation event failed");
        self->handleFailure(ret);
    }
}

static void OnEntityChanged(enum EntityState state)
{
    CLOGI(LOG_LABEL "state=%d", state);
}

static void ChangeState(enum NegotiateStateType newState)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    if (self->context.currentState == NULL) {
        CLOGE(LOG_LABEL "negotiator has not init, currentState is null.");
        return;
    }
    if (newState == self->context.currentState->type) {
        if (newState == NEGO_STATE_AVAILABLE) {
            self->processNewCommand();
        }
        return;
    }

    struct NegotiateState *old = self->context.currentState;
    struct NegotiateState *new = self->states[newState];

    old->exit();
    new->enter();

    CLOGI(LOG_LABEL "%s -> %s", self->context.currentState->name, self->states[newState]->name);
    self->context.currentState = new;
    if (newState == NEGO_STATE_AVAILABLE) {
        self->processNewCommand();
    }
}

static void NegotiateSchedule(void)
{
    struct WifiDirectCommand *command = GetWifiDirectCommandManager()->dequeueCommand();

    if (command == NULL) {
        return;
    }

    GetWifiDirectTimerList()->stopTimer(command->timerId);
    GetWifiDirectNegotiator()->context.currentCommand = command;
    int32_t reason = command->execute(command);
    if (reason == SOFTBUS_OK) {
        return;
    }

    GetWifiDirectNegotiator()->handleFailure(reason);
}

static void ProcessNewCommandAsync(void *data)
{
    if (GetWifiDirectNegotiator()->context.currentState->type != NEGO_STATE_AVAILABLE) {
        return;
    }

    NegotiateSchedule();
}

static int32_t ProcessNewCommand(void)
{
    return CallMethodAsync(ProcessNewCommandAsync, NULL, 0);
}

static void RetryCommandAsync(void *data)
{
    struct WifiDirectCommand *command = data;
    GetWifiDirectCommandManager()->enqueueCommand(command);
    ProcessNewCommand();
}

static int32_t RetryCurrentCommand(void)
{
    struct WifiDirectCommand *command = GetWifiDirectNegotiator()->context.currentCommand;
    if (command == NULL) {
        CLOGE(LOG_LABEL "current command is null");
        return SOFTBUS_ERR;
    }
    GetWifiDirectNegotiator()->context.currentCommand = NULL;
    return CallMethodAsync(RetryCommandAsync, command, RETRY_COMMAND_DELAY_MS);
}

static void NegotiatorTimerOutHandler(void *data)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    enum NegotiateTimeoutEvent type = (intptr_t)data;
    self->context.currentTimerId = TIMER_ID_INVALID;
    self->context.currentState->onTimeout(type);
}

static int32_t StartTimer(int64_t timeoutMs, enum NegotiateTimeoutEvent event)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    self->context.currentTimerId = GetWifiDirectTimerList()->startTimer(NegotiatorTimerOutHandler, timeoutMs,
                                                                        TIMER_FLAG_ONE_SHOOT, (void *)event);
    CONN_CHECK_AND_RETURN_RET_LOG(self->context.currentTimerId >= 0, SOFTBUS_ERR, LOG_LABEL "start timer failed");
    return SOFTBUS_OK;
}

static void StopTimer(void)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    if (self->context.currentTimerId != TIMER_ID_INVALID) {
        GetWifiDirectTimerList()->stopTimer(self->context.currentTimerId);
        self->context.currentTimerId = TIMER_ID_INVALID;
    }
}

static void ResetContext(void)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    self->context.currentRequestId = REQUEST_ID_INVALID;
    self->context.currentTimerId = TIMER_ID_INVALID;
    self->context.currentLinkId = LINK_ID_INVALID;
    self->context.currentTaskType = TASK_TYPE_INVALID;
    if (self->context.currentCommand) {
        FreeWifiDirectCommand(self->context.currentCommand);
        self->context.currentCommand = NULL;
    }
}

static int32_t PostData(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, SOFTBUS_ERR, LOG_LABEL "channel is null");
    struct WifiDirectDecisionCenter *decisionCenter = GetWifiDirectDecisionCenter();
    struct WifiDirectProtocol *protocol = decisionCenter->getProtocol(channel);
    CONN_CHECK_AND_RETURN_RET_LOG(protocol, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, LOG_LABEL "invalid protocol");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    protocol->setFormat(protocol, &format);

    enum WifiDirectNegotiateCmdType cmdType = GetNegotiateCmdType(msg);
    CONN_CHECK_AND_RETURN_RET_LOG(cmdType != CMD_INVALID, SOFTBUS_INVALID_PARAM, "CMD_INVALID");

    size_t size;
    uint8_t *buffer;
    if (!protocol->pack(protocol, (struct InfoContainer *)msg, &buffer, &size)) {
        CLOGE(LOG_LABEL "ERROR_WIFI_DIRECT_PACK_DATA_FAILED");
        decisionCenter->putProtocol(protocol);
        return ERROR_WIFI_DIRECT_PACK_DATA_FAILED;
    }

    if (protocol->getType() == WIFI_DIRECT_PROTOCOL_TLV) {
        CLOGI(LOG_LABEL "WIFI_DIRECT_PROTOCOL_TLV size=%zd", size);
    } else if (protocol->getType() == WIFI_DIRECT_PROTOCOL_JSON) {
        CLOGI(LOG_LABEL "WIFI_DIRECT_PROTOCOL_JSON size=%zd", size);
    }

    int32_t ret = channel->postData(channel, buffer, size);
    decisionCenter->putProtocol(protocol);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ERROR_POST_DATA_FAILED, "ERROR_POST_DATA_FAILED");

    if (channel->isP2pChannel(channel) && msg->getInt(msg, NM_KEY_COMMAND_TYPE, -1) != CMD_CTRL_CHL_HANDSHAKE) {
        CLOGI(LOG_LABEL "wait %dms for p2p auth to send data", WAIT_POST_REQUEST_MS);
        SoftBusSleepMs(WAIT_POST_REQUEST_MS);
    }
    return SOFTBUS_OK;
}

static void SyncLnnInfoForP2p(struct InnerLink *innerLink)
{
    char *localMac = innerLink->getString(innerLink, IL_KEY_LOCAL_BASE_MAC, "");
    char *remoteMac = innerLink->getString(innerLink, IL_KEY_REMOTE_BASE_MAC, "");
    char *interface = innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, "");
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(interface);
    CONN_CHECK_AND_RETURN_LOG(info, LOG_LABEL "interface info is null");

    enum WifiDirectRole myRole =
        (enum WifiDirectRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_ROLE_NONE));
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, myRole);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "set lnn p2p role failed");
    }

    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_MAC, localMac);
    if (ret != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "set lnn p2p my mac failed");
    }

    if (myRole == WIFI_DIRECT_ROLE_GC) {
        ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, remoteMac);
        if (ret != SOFTBUS_OK) {
            CLOGE(LOG_LABEL "set lnn p2p go mac failed");
        }
    } else {
        ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, "");
        if (ret != SOFTBUS_OK) {
            CLOGE(LOG_LABEL "clean lnn p2p go mac failed");
        }
    }

    LnnSyncP2pInfo();
}

static void SyncLnnInfoForHml(struct InnerLink *innerLink)
{
    CLOGI(LOG_LABEL "not implement");
}

static void SyncLnnInfo(struct InnerLink *innerLink)
{
    char *interface = innerLink->getString(innerLink, IL_KEY_LOCAL_INTERFACE, "");
    if (strcmp(interface, IF_NAME_P2P) == 0) {
        SyncLnnInfoForP2p(innerLink);
        return;
    }
    if (strcmp(interface, IF_NAME_HML) == 0) {
        SyncLnnInfoForHml(innerLink);
    }
}

static void HandleSuccess(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CLOGI(LOG_LABEL "currentRequestId=%d", self->context.currentRequestId);
    if (self->context.currentRequestId < 0) {
        CLOGI(LOG_LABEL "no caller");
    } else {
        struct WifiDirectManager *manager = GetWifiDirectManager();
        if (self->context.currentTaskType == TASK_TYPE_CONNECT) {
            if (msg == NULL) {
                CLOGE(LOG_LABEL "msg is null");
                goto OUT;
            }
            struct InnerLink *innerLink = msg->get(msg, NM_KEY_INNER_LINK, NULL, NULL);
            if (innerLink == NULL) {
                CLOGE(LOG_LABEL "inner link is null");
                goto OUT;
            }

            struct WifiDirectLink link;
            (void)memset_s(&link, sizeof(link), 0, sizeof(link));
            innerLink->getLink(innerLink, self->context.currentRequestId, self->context.currentPid, &link);
            CLOGI(LOG_LABEL "notify connect success, requestId=%d linkId=%d", self->context.currentRequestId,
                  link.linkId);
            SyncLnnInfo(innerLink);
            manager->onConnectSuccess(self->context.currentRequestId, &link);
        } else if (self->context.currentTaskType == TASK_TYPE_DISCONNECT) {
            CLOGI(LOG_LABEL "notify disconnect success, requestId=%d linkId=%d remoteMac=%s",
                  self->context.currentRequestId, self->context.currentLinkId,
                  WifiDirectAnonymizeMac(self->context.currentRemoteMac));
            GetLinkManager()->recycleLinkId(self->context.currentLinkId, self->context.currentRemoteMac);
            manager->onDisconnectSuccess(self->context.currentRequestId);
        }
    }

    CLOGI(LOG_LABEL "--dump links--");
    GetResourceManager()->dump();
    GetLinkManager()->dump();
OUT:
    ChangeState(NEGO_STATE_AVAILABLE);
    ResetContext();
}

static bool IsNeedRetry(int32_t reason)
{
    return reason == V1_ERROR_BUSY || reason == ERROR_MANAGER_BUSY || reason == V1_ERROR_REUSE_FAILED ||
        reason == ERROR_ENTITY_BUSY ||
        reason == ERROR_WIFI_DIRECT_LOCAL_DISCONNECTED_REMOTE_CONNECTED ||
        reason == ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE ||
        reason == ERROR_WIFI_DIRECT_BIDIRECTIONAL_SIMULTANEOUS_REQ ||
        reason == ERROR_P2P_SHARE_LINK_REUSE_FAILED;
}

static void HandleFailure(int32_t reason)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CLOGI(LOG_LABEL "currentRequestId=%d reason=%d", self->context.currentRequestId, reason);
    if (self->context.currentRequestId < 0) {
        CLOGI(LOG_LABEL "no caller");
        goto OUT;
    }

    struct WifiDirectCommand *command = self->context.currentCommand;
    if (IsNeedRetry(reason) && command->isNeedRetry(command)) {
        CLOGI(LOG_LABEL "retry current command");
        self->retryCurrentCommand();
        goto OUT;
    }

    struct WifiDirectManager *manager = GetWifiDirectManager();
    if (self->context.currentTaskType == TASK_TYPE_CONNECT) {
        manager->onConnectFailure(self->context.currentRequestId, reason);
    } else if (self->context.currentTaskType == TASK_TYPE_DISCONNECT) {
        manager->onDisconnectFailure(self->context.currentRequestId, reason);
    }

OUT:
    CLOGI(LOG_LABEL "--dump links--");
    GetResourceManager()->dump();
    GetLinkManager()->dump();
    ChangeState(NEGO_STATE_AVAILABLE);
    ResetContext();
}

static void HandleFailureWithoutChangeState(int32_t reason)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CLOGI(LOG_LABEL "currentRequestId=%d reason=%d", self->context.currentRequestId, reason);
    if (self->context.currentRequestId < 0) {
        CLOGI(LOG_LABEL "no caller");
        goto OUT;
    }

    struct WifiDirectCommand *command = self->context.currentCommand;
    if (IsNeedRetry(reason) && command->isNeedRetry(command)) {
        CLOGI(LOG_LABEL "retry current command");
        self->retryCurrentCommand();
        goto OUT;
    }

    struct WifiDirectManager *manager = GetWifiDirectManager();
    if (self->context.currentTaskType == TASK_TYPE_CONNECT) {
        manager->onConnectFailure(self->context.currentRequestId, reason);
    } else if (self->context.currentTaskType == TASK_TYPE_DISCONNECT) {
        manager->onDisconnectFailure(self->context.currentRequestId, reason);
    }

OUT:
    CLOGI(LOG_LABEL "--dump links--");
    GetResourceManager()->dump();
    GetLinkManager()->dump();
    ResetContext();
    self->processNewCommand();
}

static void HandleUnhandledRequest(struct NegotiateMessage *msg)
{
    struct WifiDirectProcessor *processor = GetWifiDirectDecisionCenter()->getProcessorByNegotiateMessage(msg);
    CONN_CHECK_AND_RETURN_LOG(processor, LOG_LABEL "no available processor");

    processor->processUnhandledRequest(msg, ERROR_MANAGER_BUSY);
}

static void OnWifiDirectAuthOpened(uint32_t requestId, int64_t authId)
{
    CLOGI(LOG_LABEL "requestId=%u authId=%zd", requestId, authId);
}

static int32_t ReuseLink(struct WifiDirectConnectInfo *connectInfo)
{
    char remoteUuid[UUID_BUF_LEN] = {0};
    int32_t ret = connectInfo->negoChannel->getDeviceId(connectInfo->negoChannel, remoteUuid, sizeof(remoteUuid));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "get remote uuid failed");

    struct InnerLink *link = GetLinkManager()->getLinkByUuid(remoteUuid);
    CONN_CHECK_AND_RETURN_RET_LOG(link, SOFTBUS_ERR, LOG_LABEL "link is null");
    enum InnerLinkState state = link->getInt(link, IL_KEY_STATE, INNER_LINK_STATE_DISCONNECTED);
    CONN_CHECK_AND_RETURN_RET_LOG(state == INNER_LINK_STATE_CONNECTED, SOFTBUS_ERR, LOG_LABEL "link is not connected");

    struct WifiDirectIpv4Info *ipv4 = link->getRawData(link, IL_KEY_REMOTE_IPV4, NULL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(ipv4, SOFTBUS_ERR, LOG_LABEL "ipv4 is null");

    bool isBeingUsedByLocal = link->getBoolean(link, IL_KEY_IS_BEING_USED_BY_LOCAL, false);
    CLOGI(LOG_LABEL "isBeingUsedByLocal=%d", isBeingUsedByLocal);

    if (isBeingUsedByLocal) {
        CLOGI(LOG_LABEL "reuse success");
        struct NegotiateMessage output;
        NegotiateMessageConstructor(&output);
        output.putContainer(&output, NM_KEY_INNER_LINK, (struct InfoContainer *)link, sizeof(*link));
        GetWifiDirectNegotiator()->handleSuccess(&output);
        NegotiateMessageDestructor(&output);
        return SOFTBUS_OK;
    }

    enum WifiDirectConnectType connectType = link->getInt(link, IL_KEY_CONNECT_TYPE, WIFI_DIRECT_CONNECT_TYPE_HML);
    struct WifiDirectProcessor *processor =
        GetWifiDirectDecisionCenter()->getProcessorByNegoChannelAndConnectType(connectInfo->negoChannel, connectType);
    GetWifiDirectNegotiator()->context.currentProcessor = processor;
    GetWifiDirectNegotiator()->changeState(NEGO_STATE_PROCESSING);
    return processor->reuseLink(connectInfo, link);
}

static struct EntityListener g_entityListener = {
    .onOperationComplete = OnOperationComplete,
    .onEntityChanged = OnEntityChanged,
};

static struct WifiDirectNegotiator g_negotiator = {
    .openLink = OpenLink,
    .closeLink = CloseLink,
    .postData = PostData,
    .changeState = ChangeState,
    .processNewCommand = ProcessNewCommand,
    .retryCurrentCommand = RetryCurrentCommand,
    .startTimer = StartTimer,
    .stopTimer = StopTimer,
    .handleMessageFromProcessor = HandleMessageFromProcessor,
    .onNegotiateChannelDataReceived = OnNegotiateChannelDataReceived,
    .onNegotiateChannelDisconnected = OnNegotiateChannelDisconnected,
    .handleSuccess = HandleSuccess,
    .handleFailure = HandleFailure,
    .handleFailureWithoutChangeState = HandleFailureWithoutChangeState,
    .handleUnhandledRequest = HandleUnhandledRequest,
    .syncLnnInfo = SyncLnnInfo,
    .onWifiDirectAuthOpened = OnWifiDirectAuthOpened,
    .context = {
        .currentRequestId = REQUEST_ID_INVALID,
        .currentTimerId = TIMER_ID_INVALID,
        .currentTaskType = TASK_TYPE_INVALID,
        .currentState = NULL,
        .currentProcessor = NULL,
        .currentCommand = NULL,
    },
};

struct WifiDirectNegotiator* GetWifiDirectNegotiator(void)
{
    return &g_negotiator;
}

int32_t WifiDirectNegotiatorInit(void)
{
    g_negotiator.states[NEGO_STATE_AVAILABLE] =
        (struct NegotiateState *)GetAvailableState(&g_negotiator);
    g_negotiator.states[NEGO_STATE_PROCESSING] =
        (struct NegotiateState *)GetProcessingState(&g_negotiator);
    g_negotiator.states[NEGO_STATE_WAITING_CONNECT_RESPONSE] =
        (struct NegotiateState *)GetWaitingConnectResponseState(&g_negotiator);
    g_negotiator.states[NEGO_STATE_WAITING_CONNECT_REQUEST] =
        (struct NegotiateState *)GetWaitingConnectRequestState(&g_negotiator);

    for (enum WifiDirectEntityType type = 0; type < ENTITY_TYPE_MAX; type++) {
        struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(type);
        if (entity != NULL) {
            entity->registerListener(&g_entityListener);
        }
    }
    CLOGI(LOG_LABEL "set initial state to available state");
    g_negotiator.context.currentState = (struct NegotiateState *) GetAvailableState(&g_negotiator);
    return SOFTBUS_OK;
}