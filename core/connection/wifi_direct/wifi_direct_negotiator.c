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

#define LOG_LABEL "[WD] Nego: "
#define RETRY_COMMAND_DELAY_MS 1000
#define WAIT_POST_REQUEST_MS 450

/* public interface */
static int32_t HandleMessageFromProcessor(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();

    int32_t ret = SOFTBUS_OK;
    if (msg) {
        struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        CONN_CHECK_AND_RETURN_RET_LOG(channel != NULL, SOFTBUS_ERR, LOG_LABEL "channel is null");
        (void)channel->getDeviceId(channel, self->context.currentRemoteDeviceId,
                                   sizeof(self->context.currentRemoteDeviceId));
        ret = self->postData(msg);
    }
    return ret;
}

static void SaveP2pChannel(struct WifiDirectNegotiateChannel *channel)
{
    if (!channel->isP2pChannel(channel)) {
        return;
    }

    char remoteUuid[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteUuid, sizeof(remoteUuid));
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get remote uuid failed");
    struct InnerLink *link = GetLinkManager()->getLinkByUuid(remoteUuid);
    CONN_CHECK_AND_RETURN_LOG(link, LOG_LABEL "no link for %s", AnonymizesUUID(remoteUuid));
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

    if ((UnpackData(channel, data, size, msg)) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "unpack msg failed");
        NegotiateMessageDelete(msg);
        return NULL;
    }

    if (msg->isEmpty(msg)) {
        CLOGE(LOG_LABEL "msg is empty");
        NegotiateMessageDelete(msg);
        return NULL;
    }

    struct WifiDirectNegotiateChannel *channelCopy = channel->duplicate(channel);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channelCopy);
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
        CmdStringItemDefine(CMD_GC_WIFI_CONFIG_CHANGED),
        CmdStringItemDefine(CMD_REUSE_RESP),
        CmdStringItemDefine(CMD_CONN_V2_REQ_1),
        CmdStringItemDefine(CMD_CONN_V2_REQ_2),
        CmdStringItemDefine(CMD_CONN_V2_REQ_3),
        CmdStringItemDefine(CMD_CONN_V2_RESP_1),
        CmdStringItemDefine(CMD_CONN_V2_RESP_2),
        CmdStringItemDefine(CMD_CONN_V2_RESP_3),
        CmdStringItemDefine(CMD_DISCONNECT_V2_REQ),
        CmdStringItemDefine(CMD_DISCONNECT_V2_RESP),
        CmdStringItemDefine(CMD_CLIENT_JOIN_FAIL_NOTIFY),
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

static bool IsMessageNeedPending(struct WifiDirectNegotiator *self, struct NegotiateMessage *msg)
{
    if (strlen(self->context.currentRemoteDeviceId) == 0) {
        CLOGI(LOG_LABEL "current remote deviceId is empty");
        return false;
    }

    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel != NULL, true, LOG_LABEL "channel is null");

    char remoteDeviceId[UUID_BUF_LEN] = {0};
    int32_t ret = channel->getDeviceId(channel, remoteDeviceId, sizeof(remoteDeviceId));
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, true, LOG_LABEL "get device id failed");

    CLOGI(LOG_LABEL "currentRemote=%s msgRemote=%s", AnonymizesUUID(self->context.currentRemoteDeviceId),
          AnonymizesUUID(remoteDeviceId));
    return GetWifiDirectUtils()->strCompareIgnoreCase(remoteDeviceId, self->context.currentRemoteDeviceId) != 0;
}

static void OnNegotiateChannelDataReceived(struct WifiDirectNegotiateChannel *channel, const uint8_t *data, size_t len)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    SaveP2pChannel(channel);

    struct NegotiateMessage *msg = GenerateNegotiateMessage(channel, data, len);
    CONN_CHECK_AND_RETURN_LOG(msg != NULL, LOG_LABEL "unpack msg failed");

    enum WifiDirectNegotiateCmdType cmdType = GetNegotiateCmdType(msg);
    if (cmdType == CMD_CTRL_CHL_HANDSHAKE) {
        CLOGI(LOG_LABEL "ignore CMD_CTRL_CHL_HANDSHAKE");
        struct WifiDirectNegotiateChannel *msgChannel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
        if (msgChannel != NULL) {
            msgChannel->destructor(msgChannel);
        }
        NegotiateMessageDelete(msg);
        return;
    }

    channel->getDeviceId(channel, self->context.currentRemoteDeviceId, sizeof(self->context.currentRemoteDeviceId));
    struct WifiDirectProcessor *processor = GetWifiDirectDecisionCenter()->getProcessorByNegotiateMessage(msg);
    struct WifiDirectCommand *command = WifiDirectNegotiateCommandNew(cmdType, msg);
    if (command == NULL) {
        CLOGE(LOG_LABEL "malloc negotiate command failed");
        NegotiateMessageDelete(msg);
        return;
    }

    if (processor == NULL) {
        CLOGE(LOG_LABEL "processor is null");
        if (self->context.currentProcessor != NULL) {
            CLOGI(LOG_LABEL "use currentProcessor");
            self->context.currentProcessor->processNegotiateMessage(cmdType, command);
        }
        return;
    }

    command->processor = processor;
    self->context.currentProcessor = processor;
    if (IsMessageNeedPending(self, msg)) {
        CLOGI(LOG_LABEL "queue negotiate command");
        GetWifiDirectCommandManager()->enqueueCommand(command);
    } else {
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
    CLOGD(LOG_LABEL "uuid=%s", AnonymizesUUID(uuid));
    GetLinkManager()->clearNegoChannelForLink(uuid, false);
}

static void OnOperationComplete(int32_t event)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct WifiDirectProcessor *processor = self->context.currentProcessor;
    CONN_CHECK_AND_RETURN_LOG(processor, LOG_LABEL "current processor is null");

    processor->onOperationEvent(event);
}

static void OnEntityChanged(enum EntityState state)
{
    CLOGI(LOG_LABEL "state=%d", state);
}

static void NegotiateSchedule(void)
{
    struct WifiDirectCommand *nextCommand = GetWifiDirectCommandManager()->dequeueCommand();
    CONN_CHECK_AND_RETURN_LOG(nextCommand != NULL, LOG_LABEL "command queue is empty");

    CLOGI(LOG_LABEL "execute next command");
    struct WifiDirectCommand *prevCommand = GetWifiDirectNegotiator()->context.currentCommand;
    if (prevCommand != NULL) {
        prevCommand->delete(prevCommand);
    }
    GetWifiDirectNegotiator()->context.currentCommand = nextCommand;
    nextCommand->execute(nextCommand);
}

static void ProcessNewCommandAsync(void *data)
{
    (void)data;
    if (GetWifiDirectNegotiator()->isBusy()) {
        CLOGI(LOG_LABEL "negotiator is busy");
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

static bool IsBusy(void)
{
    return GetWifiDirectNegotiator()->context.currentCommand != NULL;
}

static void ResetContext(void)
{
    CLOGI(LOG_LABEL);
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    (void)memset_s(self->context.currentRemoteDeviceId, sizeof(self->context.currentRemoteDeviceId), 0,
                   sizeof(self->context.currentRemoteDeviceId));
    self->context.currentCommand = NULL;
    if (self->context.currentProcessor != NULL) {
        self->context.currentProcessor->resetContext();
        self->context.currentProcessor = NULL;
    }
    self->processNextCommand();
}

static bool IsNeedDelayForPostData(struct NegotiateMessage *msg)
{
    struct WifiDirectNegotiateChannel *channel = msg->getPointer(msg, NM_KEY_NEGO_CHANNEL, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(channel, false, LOG_LABEL "channel is null");
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
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ERROR_POST_DATA_FAILED, LOG_LABEL "ERROR_POST_DATA_FAILED");

    if (IsNeedDelayForPostData(msg)) {
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
    (void)innerLink;
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

static struct EntityListener g_entityListener = {
    .onOperationComplete = OnOperationComplete,
    .onEntityChanged = OnEntityChanged,
};

static struct WifiDirectNegotiator g_negotiator = {
    .postData = PostData,
    .processNextCommand = ProcessNextCommand,
    .retryCurrentCommand = RetryCurrentCommand,
    .isBusy = IsBusy,
    .resetContext = ResetContext,
    .handleMessageFromProcessor = HandleMessageFromProcessor,
    .onNegotiateChannelDataReceived = OnNegotiateChannelDataReceived,
    .onNegotiateChannelDisconnected = OnNegotiateChannelDisconnected,
    .handleUnhandledRequest = HandleUnhandledRequest,
    .syncLnnInfo = SyncLnnInfo,
    .onWifiDirectAuthOpened = OnWifiDirectAuthOpened,
    .context = {
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
    for (enum WifiDirectEntityType type = 0; type < ENTITY_TYPE_MAX; type++) {
        struct WifiDirectEntity *entity = GetWifiDirectEntityFactory()->createEntity(type);
        if (entity != NULL) {
            entity->registerListener(&g_entityListener);
        }
    }
    return SOFTBUS_OK;
}