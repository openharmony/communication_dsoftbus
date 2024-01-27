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
#include "conn_log.h"
#include "conn_event.h"
#include "softbus_error_code.h"
#include "softbus_adapter_timer.h"
#include "bus_center_manager.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_decision_center.h"
#include "command/wifi_direct_command_manager.h"
#include "command/wifi_direct_negotiate_command.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "data/negotiate_message.h"
#include "entity/wifi_direct_entity_factory.h"
#include "protocol/wifi_direct_protocol.h"
#include "processor/wifi_direct_processor_factory.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_timer_list.h"

#define RETRY_COMMAND_DELAY_MS 1000
#define WAIT_POST_REQUEST_MS 450
#define WATCH_DOG_TIMEOUT_MS 30000

/* public interface */
static int32_t g_retryErrorCodeTable[] = {
    V1_ERROR_BUSY,
    V1_ERROR_REUSE_FAILED,
    V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE,
    V1_ERROR_IF_NOT_AVAILABLE,
    ERROR_MANAGER_BUSY,
    ERROR_ENTITY_BUSY,
    ERROR_ENTITY_UNAVAILABLE,
    ERROR_SINK_NO_LINK,
    ERROR_SOURCE_NO_LINK,
    ERROR_WIFI_DIRECT_LOCAL_DISCONNECTED_REMOTE_CONNECTED,
    ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE,
    ERROR_WIFI_DIRECT_BIDIRECTIONAL_SIMULTANEOUS_REQ,
    ERROR_P2P_SHARE_LINK_REUSE_FAILED,
};

static bool IsRetryErrorCode(int32_t reason)
{
    for (size_t i = 0; i < ARRAY_SIZE(g_retryErrorCodeTable); i++) {
        if (reason == g_retryErrorCodeTable[i]) {
            return true;
        }
    }
    return false;
}

static int32_t HandleMessageFromProcessor(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();

    int32_t ret = SOFTBUS_OK;
    if (msg != NULL) {
        msg->dump(msg, 0);
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        CONN_CHECK_AND_RETURN_RET_LOGW(channel != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");
        self->updateCurrentRemoteDeviceId(channel);
        ret = self->postData(msg);
    }
    return ret;
}

static void SaveP2pChannel(struct WifiDirectNegotiateChannel *channel, struct NegotiateMessage *msg)
{
    if (!channel->isP2pChannel(channel)) {
        return;
    }

    enum WifiDirectLinkType linkType = WIFI_DIRECT_LINK_TYPE_P2P;
    char *ip = msg->getString(msg, NM_KEY_IP, "");
    CONN_LOGI(CONN_WIFI_DIRECT, "ip=%{public}s", WifiDirectAnonymizeIp(ip));
    if (strstr(ip, HML_IP_NET_PREFIX) != NULL) {
        linkType = WIFI_DIRECT_LINK_TYPE_HML;
    }

    char remoteUuid[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteUuid, sizeof(remoteUuid));
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get remote uuid failed");
    CONN_LOGI(CONN_WIFI_DIRECT,
        "linkType=%{public}d, remoteUuid=%{public}s", linkType, WifiDirectAnonymizeDeviceId(remoteUuid));
    struct InnerLink *link = GetLinkManager()->getLinkByTypeAndUuid(linkType, remoteUuid);
    if (link == NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "no link. remoteUuid=%{public}s", WifiDirectAnonymizeDeviceId(remoteUuid));
        return;
    }

    struct WifiDirectNegotiateChannel *channelOld = link->getPointer(link, IL_KEY_NEGO_CHANNEL, NULL);
    if (channelOld == NULL) {
        struct WifiDirectNegotiateChannel *channelNew = channel->duplicate(channel);
        link->putPointer(link, IL_KEY_NEGO_CHANNEL, (void **)&channelNew);
    }
}

static int32_t UnpackData(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t size,
                          struct NegotiateMessage *msg)
{
    struct WifiDirectDecisionCenter *decisionCenter = GetWifiDirectDecisionCenter();
    struct WifiDirectProtocol *protocol = decisionCenter->getProtocol(channel);
    CONN_CHECK_AND_RETURN_RET_LOGW(protocol, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, CONN_WIFI_DIRECT,
        "no suitable protocol");

    if (protocol->getType() == WIFI_DIRECT_PROTOCOL_JSON) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_DIRECT_PROTOCOL_JSON size=%{public}zd", size);
    } else if (protocol->getType() == WIFI_DIRECT_PROTOCOL_TLV) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_DIRECT_PROTOCOL_TLV size=%{public}zd", size);
    }

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    protocol->setFormat(protocol, &format);

    if (!protocol->setDataSource(protocol, data, size)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "protocol set data source failed");
        decisionCenter->putProtocol(protocol);
        return ERROR_WIFI_DIRECT_UNPACK_DATA_FAILED;
    }
    if (!protocol->unpack(protocol, (struct InfoContainer *)msg)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "unpack data failed");
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
        CONN_LOGE(CONN_WIFI_DIRECT, "alloc msg failed");
        return NULL;
    }

    if ((UnpackData(channel, data, size, msg)) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "unpack msg failed");
        NegotiateMessageDelete(msg);
        return NULL;
    }

    if (msg->isEmpty(msg)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "msg is empty");
        NegotiateMessageDelete(msg);
        return NULL;
    }

    struct WifiDirectNegotiateChannel *channelCopy = channel->duplicate(channel);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channelCopy);
    msg->dump(msg, 0);
    return msg;
}

#define CMD_STRING_ITEM_DEFINE(cmd) { cmd, #cmd }
static void DumpCommandString(enum WifiDirectNegotiateCmdType cmdType, const char *remoteDeviceId)
{
    static struct CmdStringItem {
        enum WifiDirectNegotiateCmdType cmd;
        const char *string;
    } cmdStringMap[] = {
        CMD_STRING_ITEM_DEFINE(CMD_INVALID),
        CMD_STRING_ITEM_DEFINE(CMD_DISCONNECT_V1_REQ),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V1_REQ),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V1_RESP),
        CMD_STRING_ITEM_DEFINE(CMD_REUSE_REQ),
        CMD_STRING_ITEM_DEFINE(CMD_CTRL_CHL_HANDSHAKE),
        CMD_STRING_ITEM_DEFINE(CMD_GC_WIFI_CONFIG_CHANGED),
        CMD_STRING_ITEM_DEFINE(CMD_REUSE_RESP),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V2_REQ_1),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V2_REQ_2),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V2_REQ_3),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V2_RESP_1),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V2_RESP_2),
        CMD_STRING_ITEM_DEFINE(CMD_CONN_V2_RESP_3),
        CMD_STRING_ITEM_DEFINE(CMD_DISCONNECT_V2_REQ),
        CMD_STRING_ITEM_DEFINE(CMD_DISCONNECT_V2_RESP),
        CMD_STRING_ITEM_DEFINE(CMD_CLIENT_JOIN_FAIL_NOTIFY),
        CMD_STRING_ITEM_DEFINE(CMD_PC_GET_INTERFACE_INFO_REQ),
        CMD_STRING_ITEM_DEFINE(CMD_RENEGOTIATE_REQ),
        CMD_STRING_ITEM_DEFINE(CMD_RENEGOTIATE_RESP),
    };

    for (uint32_t i = 0 ; i < ARRAY_SIZE(cmdStringMap); i++) {
        if (cmdStringMap[i].cmd == cmdType) {
            CONN_LOGI(CONN_WIFI_DIRECT, "cmd=%{public}s, remoteDeviceId=%{public}s", cmdStringMap[i].string,
                      WifiDirectAnonymizeDeviceId(remoteDeviceId));
            break;
        }
    }
}

static enum WifiDirectNegotiateCmdType GetNegotiateCmdType(struct NegotiateMessage *msg)
{
    enum WifiDirectNegotiateCmdType cmdType = msg->getInt(msg, NM_KEY_MSG_TYPE, CMD_INVALID);
    if (cmdType == CMD_INVALID) {
        if ((cmdType = msg->getInt(msg, NM_KEY_COMMAND_TYPE, CMD_INVALID)) == CMD_INVALID) {
            CONN_LOGW(CONN_WIFI_DIRECT, "cmd type is null");
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

static bool IsMessageNeedPending(struct WifiDirectNegotiator *self, struct WifiDirectProcessor *processor,
                                 enum WifiDirectNegotiateCmdType cmdType, struct NegotiateMessage *msg)
{
    if (strlen(self->currentRemoteDeviceId) == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "current remote deviceId is empty");
        return false;
    }

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel != NULL, true, CONN_WIFI_DIRECT, "channel is null");

    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, true, CONN_WIFI_DIRECT, "get device id failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "currentRemote=%{public}s, msgRemote=%{public}s",
        WifiDirectAnonymizeDeviceId(self->currentRemoteDeviceId), WifiDirectAnonymizeDeviceId(remoteDeviceId));

    if (GetWifiDirectUtils()->strCompareIgnoreCase(remoteDeviceId, self->currentRemoteDeviceId) != 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "mis deviceId");
        return true;
    }
    if (self->currentProcessor == NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "currentProcessor=NULL");
        return false;
    }
    if (self->currentProcessor != processor) {
        CONN_LOGI(CONN_WIFI_DIRECT, "currentProcessor=%s processor=%s", self->currentProcessor->name, processor->name);
        struct WifiDirectProcessor *hmlProcessor =
            GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_HML);
        struct WifiDirectProcessor *p2pV2Processor =
            GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V2);
        if (self->currentProcessor == hmlProcessor && processor == p2pV2Processor) {
            return hmlProcessor->isMessageNeedPending(cmdType, msg);
        }
        return true;
    }

    return processor->isMessageNeedPending(cmdType, msg);
}

static bool ProcessHandShake(enum WifiDirectNegotiateCmdType cmd, struct WifiDirectNegotiateChannel *channel,
                             struct NegotiateMessage *msg)
{
    if (cmd != CMD_CTRL_CHL_HANDSHAKE) {
        return false;
    }

    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    if (self->currentProcessor != NULL && self->currentProcessor->processHandShake != NULL) {
        self->currentProcessor->processHandShake(msg);
    } else {
        SaveP2pChannel(channel, msg);
        CONN_LOGI(CONN_WIFI_DIRECT, "ignore CMD_CTRL_CHL_HANDSHAKE");
    }
    struct WifiDirectNegotiateChannel *msgChannel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    if (msgChannel != NULL) {
        msgChannel->destructor(msgChannel);
    }
    NegotiateMessageDelete(msg);
    return true;
}

static void ProcessNegotiateMessageWhenProcessorInvalid(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_WIFI_DIRECT, "channel is null");
    struct NegotiateMessage *response = NegotiateMessageNew();
    CONN_CHECK_AND_RETURN_LOGE(response != NULL, CONN_WIFI_DIRECT, "malloc response failed");
    response->putInt(response, NM_KEY_MSG_TYPE, CMD_CONN_V2_RESP_3);
    response->putInt(response, NM_KEY_SESSION_ID, msg->getInt(msg, NM_KEY_SESSION_ID, -1));
    response->putInt(response, NM_KEY_RESULT_CODE, ERROR_WIFI_DIRECT_NO_SUITABLE_PROCESSOR);
    response->putPointer(response, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    response->dump(response, 0);
    if (GetWifiDirectNegotiator()->postData(response) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "send response failed");
    }
    NegotiateMessageDelete(response);
}

static void OnNegotiateChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct NegotiateMessage *msg = GenerateNegotiateMessage(channel, data, len);
    if (msg == NULL) {
        ConnAuditExtra extra = {
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .errcode = ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG,
            .peerUdid = self->currentRemoteDeviceId,
        };
        CONN_AUDIT(STATS_SCENE_CONN_WIFI_RECV_FAILED, extra);
        CONN_LOGW(CONN_WIFI_DIRECT, "unpack msg failed");
        return;
    }
    enum WifiDirectNegotiateCmdType cmdType = GetNegotiateCmdType(msg);
    if (ProcessHandShake(cmdType, channel, msg)) {
        return;
    }

    struct WifiDirectProcessor *processor = GetWifiDirectDecisionCenter()->getProcessorByNegotiateMessage(msg);
    struct WifiDirectCommand *command = WifiDirectNegotiateCommandNew(cmdType, msg);
    if (command == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "malloc negotiate command failed");
        NegotiateMessageDelete(msg);
        return;
    }

    if (processor == NULL) {
        CONN_LOGE(CONN_WIFI_DIRECT, "processor is null");
        if (self->currentProcessor == NULL) {
            CONN_LOGW(CONN_WIFI_DIRECT, "currentProcessor is null");
            if (cmdType == CMD_CONN_V2_REQ_1) {
                ProcessNegotiateMessageWhenProcessorInvalid(msg);
            }
            NegotiateMessageDelete(msg);
            return;
        }
        CONN_LOGI(CONN_WIFI_DIRECT, "use currentProcessor");
        processor = self->currentProcessor;
    }
    command->processor = processor;

    if (IsMessageNeedPending(self, processor, cmdType, msg)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "queue negotiate command");
        GetWifiDirectCommandManager()->enqueueCommand(command);
    } else {
        self->startWatchDog();
        self->updateCurrentRemoteDeviceId(channel);
        self->currentProcessor = processor;
        CONN_LOGI(CONN_WIFI_DIRECT, "currentProcessor=%{public}s", processor->name);
        processor->processNegotiateMessage(cmdType, command);
    }
}

static void OnNegotiateChannelDisconnected(struct WifiDirectNegotiateChannel *channel)
{
    if (!channel->isP2pChannel(channel)) {
        return;
    }
    char uuid[UUID_BUF_LEN] = {0};
    channel->getDeviceId(channel, uuid, sizeof(uuid));
    CONN_LOGD(CONN_WIFI_DIRECT, "uuid=%{public}s", WifiDirectAnonymizeDeviceId(uuid));
    GetLinkManager()->clearNegotiateChannelForLink(channel);
}

static void OnTriggerChannelDataReceived(struct WifiDirectTriggerChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_WIFI_DIRECT, "channel is null");
    struct WifiDirectProcessor *processor = GetWifiDirectDecisionCenter()->getTriggerProcessorByChannel(channel);
    CONN_CHECK_AND_RETURN_LOGW(processor != NULL, CONN_WIFI_DIRECT, "trigger processor is null");
    GetWifiDirectNegotiator()->startWatchDog();
    CONN_LOGI(CONN_WIFI_DIRECT, "processor=%{public}s", processor->name);
    processor->onTriggerChannelDataReceived(channel);
}

static void OnDefaultTriggerChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data,
                                                size_t len)
{
    struct WifiDirectProcessor *processor = GetWifiDirectDecisionCenter()->getTriggerProcessorByData(data, len);
    CONN_CHECK_AND_RETURN_LOGW(processor != NULL, CONN_WIFI_DIRECT, "trigger processor is null");
    CONN_LOGI(CONN_WIFI_DIRECT, "processor=%{public}s", processor->name);
    GetWifiDirectNegotiator()->startWatchDog();
    processor->onDefaultTriggerChannelDataReceived(channel, data, len);
}

static void OnOperationComplete(int32_t event, void *data)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct WifiDirectProcessor *processor = self->currentProcessor;
    CONN_CHECK_AND_RETURN_LOGW(processor, CONN_WIFI_DIRECT, "current processor is null");

    processor->onOperationEvent(event, data);
}

static void OnEntityChanged(enum EntityState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "state=%{public}d", state);
}

static void NegotiateSchedule(void)
{
    struct WifiDirectCommand *nextCommand = GetWifiDirectCommandManager()->dequeueCommand();
    CONN_CHECK_AND_RETURN_LOGW(nextCommand != NULL, CONN_WIFI_DIRECT, "command queue is empty");

    CONN_LOGI(CONN_WIFI_DIRECT, "execute next command");
    struct WifiDirectCommand *prevCommand = GetWifiDirectNegotiator()->currentCommand;
    if (prevCommand != NULL) {
        prevCommand->destructor(prevCommand);
    }
    GetWifiDirectNegotiator()->currentCommand = nextCommand;
    CONN_LOGI(CONN_WIFI_DIRECT, "currentCommand=%{public}d", nextCommand->type);
    nextCommand->execute(nextCommand);
}

static void ProcessNewCommandAsync(void *data)
{
    (void)data;
    if (GetWifiDirectNegotiator()->isBusy()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "negotiator is busy");
    } else {
        NegotiateSchedule();
    }
}

static int32_t ProcessNextCommand(void)
{
    return CallMethodAsync(ProcessNewCommandAsync, NULL, 0);
}

static void RetryCommandAsync(void *data)
{
    struct WifiDirectCommand *command = data;
    GetWifiDirectCommandManager()->enqueueCommand(command);
    ProcessNextCommand();
}

static bool IsActiveCommand(enum WifiDirectCommandType type)
{
    return type == COMMAND_TYPE_CONNECT || type == COMMAND_TYPE_DISCONNECT;
}

static int32_t RetryCurrentCommand(void)
{
    struct WifiDirectCommand *command = GetWifiDirectNegotiator()->currentCommand;
    if (command == NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "current command is null or message, ignore retry");
        return SOFTBUS_ERR;
    }
    if (!IsActiveCommand(command->type)) {
        CONN_LOGW(CONN_WIFI_DIRECT, "current command is not active command, ignore retry");
        return SOFTBUS_ERR;
    }

    GetWifiDirectNegotiator()->currentCommand = NULL;
    CONN_LOGI(CONN_WIFI_DIRECT, "currentCommand=NULL");
    struct WifiDirectCommand *commandCopy = command->duplicate(command);
    return CallMethodAsync(RetryCommandAsync, commandCopy, RETRY_COMMAND_DELAY_MS);
}

static bool IsBusy(void)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    if (self->currentCommand != NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "currentCommand is not null");
        return true;
    }
    if (self->currentProcessor != NULL && self->currentProcessor->passiveCommand != NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "passiveCommand of currentProcessor is not null");
        return true;
    }
    return false;
}

static void ResetContext(void)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    (void)memset_s(self->currentRemoteDeviceId, sizeof(self->currentRemoteDeviceId), 0,
                   sizeof(self->currentRemoteDeviceId));
    self->currentCommand = NULL;
    CONN_LOGI(CONN_WIFI_DIRECT, "currentCommand=NULL");
    if (self->currentProcessor != NULL) {
        self->currentProcessor->resetContext();
        self->currentProcessor = NULL;
        CONN_LOGI(CONN_WIFI_DIRECT, "currentProcessor=NULL");
    }
    self->stopWatchDog();
    self->processNextCommand();
}

static void UpdateCurrentRemoteDeviceId(struct WifiDirectNegotiateChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_WIFI_DIRECT, "channel is null");
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    (void)channel->getDeviceId(channel, self->currentRemoteDeviceId, sizeof(self->currentRemoteDeviceId));
}

static bool IsNeedDelayForPostData(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, false, CONN_WIFI_DIRECT, "channel is null");
    if (!channel->isP2pChannel(channel)) {
        return false;
    }

    static int32_t delayCmdTable[] = {
        CMD_DISCONNECT_V1_REQ,
        CMD_DISCONNECT_V2_REQ,
    };

    int32_t cmd = msg->getInt(msg, NM_KEY_MSG_TYPE, CMD_INVALID);
    for (size_t i = 0; i < ARRAY_SIZE(delayCmdTable); i++) {
        if (cmd == delayCmdTable[i]) {
            return true;
        }
    }
    return false;
}

static int32_t PostData(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(channel, SOFTBUS_ERR, CONN_WIFI_DIRECT, "channel is null");
    struct WifiDirectDecisionCenter *decisionCenter = GetWifiDirectDecisionCenter();
    struct WifiDirectProtocol *protocol = decisionCenter->getProtocol(channel);
    CONN_CHECK_AND_RETURN_RET_LOGW(protocol, ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL, CONN_WIFI_DIRECT,
                                   "invalid protocol");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    protocol->setFormat(protocol, &format);

    enum WifiDirectNegotiateCmdType cmdType = GetNegotiateCmdType(msg);
    CONN_CHECK_AND_RETURN_RET_LOGW(cmdType != CMD_INVALID, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "CMD_INVALID");

    size_t size;
    uint8_t *buffer;
    if (!protocol->pack(protocol, (struct InfoContainer *)msg, &buffer, &size)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "ERROR_WIFI_DIRECT_PACK_DATA_FAILED");
        decisionCenter->putProtocol(protocol);
        return ERROR_WIFI_DIRECT_PACK_DATA_FAILED;
    }

    if (protocol->getType() == WIFI_DIRECT_PROTOCOL_TLV) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_DIRECT_PROTOCOL_TLV size=%{public}zd", size);
    } else if (protocol->getType() == WIFI_DIRECT_PROTOCOL_JSON) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_DIRECT_PROTOCOL_JSON size=%{public}zd", size);
    }

    int32_t ret = channel->postData(channel, buffer, size);
    decisionCenter->putProtocol(protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ERROR_POST_DATA_FAILED, CONN_WIFI_DIRECT,
        "ERROR_POST_DATA_FAILED");

    if (IsNeedDelayForPostData(msg)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "wait for p2p auth to send data. WAIT_POST_REQUEST_MS=%{public}dms",
            WAIT_POST_REQUEST_MS);
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
    CONN_CHECK_AND_RETURN_LOGW(info, CONN_WIFI_DIRECT, "interface info is null");

    enum WifiDirectRole myRole =
        (enum WifiDirectRole)(info->getInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_ROLE_NONE));
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, myRole);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "set lnn p2p role failed");
    }

    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_MAC, localMac);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "set lnn p2p my mac failed");
    }

    if (myRole == WIFI_DIRECT_ROLE_GC) {
        ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, remoteMac);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "set lnn p2p go mac failed");
        }
    } else {
        ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, "");
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "clean lnn p2p go mac failed");
        }
    }

    LnnSyncP2pInfo();
}

static void SyncLnnInfoForHml(struct InnerLink *innerLink)
{
    (void)innerLink;
    CONN_LOGI(CONN_WIFI_DIRECT, "not implement");
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

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    struct WifiDirectProcessor *processor = NULL;
    if (linkType == WIFI_DIRECT_LINK_TYPE_P2P) {
        processor = GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
    } else {
        processor = GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_HML);
    }

    if (processor != NULL) {
        return processor->prejudgeAvailability(remoteNetworkId);
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "processor is null");
    return SOFTBUS_OK;
}

static void WatchDogTimeout(struct WifiDirectNegotiator *self)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "currentRemoteDeviceId=%{public}s",
              WifiDirectAnonymizeDeviceId(self->currentRemoteDeviceId));
    struct WifiDirectProcessor *processor = self->currentProcessor;
    if (self->currentProcessor != NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "name=%{public}s state=%{public}d", processor->name, processor->currentState);
        if (processor->activeCommand != NULL) {
            CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=%{public}d", processor->activeCommand->type);
        } else {
            CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=NULL");
        }
        if (processor->passiveCommand != NULL) {
            CONN_LOGI(CONN_WIFI_DIRECT, "passiveCommand=%{public}d", processor->passiveCommand->type);
        } else {
            CONN_LOGI(CONN_WIFI_DIRECT, "passiveCommand=NULL");
        }
    }
    if (self->currentCommand != NULL) {
        self->currentCommand->onFailure(self->currentCommand, SOFTBUS_TIMOUT);
    } else {
        self->resetContext();
    }
    GetWifiDirectCommandManager()->removePassiveCommand();
}

static void StartWatchDog(void)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    if (self->watchDogTimerId != TIMER_ID_INVALID) {
        GetWifiDirectTimerList()->stopTimer(self->watchDogTimerId);
    }
    self->watchDogTimerId = GetWifiDirectTimerList()->startTimer((TimeoutHandler)WatchDogTimeout, WATCH_DOG_TIMEOUT_MS,
                                                                 TIMER_FLAG_ONE_SHOOT, self);
    CONN_LOGI(CONN_WIFI_DIRECT, "watchDogTimerId=%{public}d", self->watchDogTimerId);
}

static void StopWatchDog(void)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    CONN_LOGI(CONN_WIFI_DIRECT, "watchDogTimerId=%{public}d", self->watchDogTimerId);
    if (self->watchDogTimerId != TIMER_ID_INVALID) {
        GetWifiDirectTimerList()->stopTimer(self->watchDogTimerId);
        self->watchDogTimerId = TIMER_ID_INVALID;
    }
}

static struct EntityListener g_entityListener = {
    .onOperationComplete = OnOperationComplete,
    .onEntityChanged = OnEntityChanged,
};

static struct WifiDirectNegotiator g_negotiator = {
    .postData = PostData,
    .processNextCommand = ProcessNextCommand,
    .retryCurrentCommand = RetryCurrentCommand,
    .isRetryErrorCode = IsRetryErrorCode,
    .isBusy = IsBusy,
    .resetContext = ResetContext,
    .updateCurrentRemoteDeviceId = UpdateCurrentRemoteDeviceId,
    .getNegotiateCmdType = GetNegotiateCmdType,
    .handleMessageFromProcessor = HandleMessageFromProcessor,
    .onNegotiateChannelDataReceived = OnNegotiateChannelDataReceived,
    .onNegotiateChannelDisconnected = OnNegotiateChannelDisconnected,
    .onTriggerChannelDataReceived = OnTriggerChannelDataReceived,
    .onDefaultTriggerChannelDataReceived = OnDefaultTriggerChannelDataReceived,
    .syncLnnInfo = SyncLnnInfo,
    .prejudgeAvailability = PrejudgeAvailability,

    .startWatchDog = StartWatchDog,
    .stopWatchDog = StopWatchDog,
    .watchDogTimeout = WatchDogTimeout,

    .currentCommand = NULL,
    .currentProcessor = NULL,
    .watchDogTimerId = TIMER_ID_INVALID,
};

struct WifiDirectNegotiator* GetWifiDirectNegotiator(void)
{
    return &g_negotiator;
}

int32_t WifiDirectNegotiatorInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    for (enum WifiDirectEntityType type = 0; type < ENTITY_TYPE_MAX; type++) {
        struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(type);
        if (entity != NULL) {
            entity->registerListener(&g_entityListener);
        }
    }
    return SOFTBUS_OK;
}